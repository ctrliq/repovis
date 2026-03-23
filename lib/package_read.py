#!/usr/bin/python3
"""DNF repository reader and package metadata extractor.

Configures DNF for a set of repositories, loads all package information
into memory, de-duplicates by source RPM, extracts changelogs and CVE
references, and returns a list of :class:`PackageInfo` records.
"""

from __future__ import annotations

import datetime
import logging
import os
import re
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

import dnf
import dnf.module.module_base
import hawkey
import yaml

from lib.models import ChangelogEntry, PackageInfo

logger = logging.getLogger(__name__)

# Pre-compiled regex for CVE identifiers (e.g. CVE-2024-12345)
_CVE_REGEX = re.compile(r"CVE-\d+-\d+", re.IGNORECASE)


def _profile_comparison_key(profile: Any) -> str:
    """Sort key for DNF module profiles."""
    return profile.getName()


def _parse_version_from_srpm(srpm: str, src_name: str) -> Tuple[str, str]:
    """Extract version and release strings from an SRPM filename.

    Args:
        srpm: Full SRPM filename, e.g. ``"foo-1.2.3-4.el8.src.rpm"``.
        src_name: The source package name, e.g. ``"foo"``.

    Returns:
        A ``(version, release)`` tuple.

    Raises:
        ValueError: If the filename cannot be parsed into version and release.
    """
    # Strip the trailing .src.rpm first, then remove the leading source name
    # using the last occurrence to handle names that contain hyphens.
    stripped = srpm.removesuffix(".src.rpm")
    prefix = src_name + "-"
    if stripped.startswith(prefix):
        stripped = stripped[len(prefix):]

    parts = stripped.split("-", maxsplit=1)
    if len(parts) < 2:
        raise ValueError(
            f"Cannot parse version-release from SRPM '{srpm}' "
            f"(source name='{src_name}')"
        )
    return parts[0], parts[1]


class PackageRead:
    """Read and normalise package metadata from one or more DNF repos.

    Args:
        repo_list: DNF repo IDs to enable (all others are disabled).
        repo_dir: Optional alternate directory containing ``*.repo`` files.
        latest: When ``True``, only the most recent build per
            source-name + module-stream is kept.
        build_time: Epoch timestamp — packages built before this are ignored.
        cve_file: Optional path to a supplemental YAML file of extra CVE data.
    """

    def __init__(
        self,
        repo_list: List[str],
        repo_dir: str,
        latest: bool,
        build_time: int,
        cve_file: str,
    ) -> None:
        self.packages: List[PackageInfo] = []
        self.build_time: int = build_time
        self.cve_extra: Dict[str, Any] = {}

        # Create a private temp directory for the DNF cache
        self._cache_dir: str = tempfile.mkdtemp(prefix="repovis_dnf_cache_")

        self._dnf_base: dnf.Base = dnf.Base()

        if repo_dir:
            self._dnf_base.conf.reposdir = repo_dir

        self._dnf_base.conf.gpgcheck = False
        self._dnf_base.conf.cachedir = self._cache_dir

        try:
            self._dnf_base.read_all_repos()
        except Exception:
            logger.error("Could not read repos")
            sys.exit(1)

        # Enable only the repos specified on the command line
        for repo in self._dnf_base.repos:
            if repo not in repo_list:
                self._dnf_base.repos[repo].disable()
            else:
                self._dnf_base.repos[repo].enable()
                self._dnf_base.repos[repo].load_metadata_other = True
                self._dnf_base.repos[repo].module_hotfixes = True

        self._dnf_base.fill_sack(load_system_repo=False)

        # Gather all available packages from the enabled repos
        tmp_pkg_list = self._dnf_base.sack.query().available().filter()

        # Load supplemental CVE YAML if provided
        if cve_file:
            with open(cve_file) as f:
                self.cve_extra = yaml.safe_load(f) or {}

        self._build_package_list(tmp_pkg_list, latest)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup(self) -> None:
        """Remove the temporary DNF cache directory."""
        if os.path.exists(self._cache_dir):
            shutil.rmtree(self._cache_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Package list construction
    # ------------------------------------------------------------------

    def _build_package_list(self, tmp_pkg_list: Any, latest: bool) -> None:
        """Iterate raw DNF packages and build the de-duplicated list."""
        for pkg in tmp_pkg_list:
            # Skip packages outside our time window
            if pkg.buildtime < self.build_time:
                continue

            # Derive source version/release from the SRPM filename
            try:
                source_version, source_release = _parse_version_from_srpm(
                    pkg.sourcerpm, pkg.source_name
                )
            except ValueError:
                logger.warning(
                    "Skipping package '%s': could not parse SRPM '%s'",
                    pkg.source_name,
                    pkg.sourcerpm,
                )
                continue

            # Skip if we already have this exact source version
            if any(
                p.source_name == pkg.source_name
                and p.source_version == source_version
                and p.source_release == source_release
                for p in self.packages
            ):
                continue

            # Determine module label for modular packages
            module_label = "-"
            if ".module" in source_release:
                module_label = self._get_module_label(pkg)

            # When *latest* is requested, keep only the newest build per
            # source-name + module-stream.
            if latest:
                discard = False
                for existing in self.packages[:]:
                    if (
                        existing.source_name == pkg.source_name
                        and existing.module_label == module_label
                    ):
                        if existing.buildtime > pkg.buildtime:
                            discard = True
                            break
                        if pkg.buildtime > existing.buildtime:
                            self.packages.remove(existing)
                if discard:
                    continue

            # Build filtered changelogs and CVE dict
            filtered_changelogs = self._get_filtered_changelog(pkg.changelogs)
            cve_dict = self._get_cves_from_changelog(
                filtered_changelogs, pkg.source_name
            )

            # Emit a proper PackageInfo dataclass instead of monkey-patching
            self.packages.append(
                PackageInfo(
                    source_name=pkg.source_name,
                    source_version=source_version,
                    source_release=source_release,
                    module_label=module_label,
                    buildtime=pkg.buildtime,
                    filtered_changelogs=filtered_changelogs,
                    cve_dict=cve_dict,
                )
            )

    # ------------------------------------------------------------------
    # Changelog helpers
    # ------------------------------------------------------------------

    def _get_filtered_changelog(
        self, changelog: List[Dict[str, Any]]
    ) -> List[ChangelogEntry]:
        """Return changelog entries within the configured time window.

        The most recent entry is always included regardless of timestamp.
        """
        if not changelog:
            return []

        filtered: List[ChangelogEntry] = [
            ChangelogEntry(
                timestamp=str(changelog[0]["timestamp"]),
                text=str(changelog[0]["text"]),
            )
        ]

        for entry in changelog[1:]:
            entry_epoch = int(
                datetime.datetime.fromordinal(
                    entry["timestamp"].toordinal()
                ).timestamp()
            )
            if entry_epoch > self.build_time:
                filtered.append(
                    ChangelogEntry(
                        timestamp=str(entry["timestamp"]),
                        text=str(entry["text"]),
                    )
                )

        return filtered

    def _get_cves_from_changelog(
        self, changelog: List[ChangelogEntry], package: str
    ) -> Dict[str, List[str]]:
        """Extract CVE identifiers from changelog text and supplemental YAML.

        Returns a dict mapping date-strings to lists of CVE identifiers.
        """
        cve_dict: Dict[str, List[str]] = {}
        seen: set[str] = set()

        # --- CVEs from the RPM changelog ---
        for entry in changelog:
            entry_epoch = int(
                datetime.datetime.strptime(
                    str(entry.timestamp), "%Y-%m-%d"
                ).timestamp()
            )
            if entry_epoch < self.build_time:
                continue

            # Find unique CVEs in this entry, excluding already-seen ones
            raw_cves = list(dict.fromkeys(_CVE_REGEX.findall(entry.text.upper())))
            new_cves = [c for c in raw_cves if c not in seen]

            if new_cves:
                cve_dict[str(entry.timestamp)] = new_cves
                seen.update(new_cves)

        # --- CVEs from supplemental YAML ---
        extra_packages = self.cve_extra.get("packages", {}) or {}
        extra_pkg = extra_packages.get(package, {}) or {}
        extra_fixes = extra_pkg.get("cve_fixes", {}) or {}

        for date, cve_list in extra_fixes.items():
            date_epoch = int(
                datetime.datetime.strptime(str(date), "%Y-%m-%d").timestamp()
            )
            if date_epoch < self.build_time:
                continue

            # Filter: must be a known advisory prefix and not already seen
            new_cves = [
                cve
                for cve in cve_list
                if (
                    cve.startswith("CVE-")
                    or cve.startswith("RLSA-")
                    or cve.startswith("RHSA-")
                )
                and cve not in seen
            ]

            if new_cves:
                date_key = str(date)  # normalise to string for dict key
                if date_key in cve_dict:
                    cve_dict[date_key].extend(new_cves)
                else:
                    cve_dict[date_key] = new_cves
                seen.update(new_cves)

        return cve_dict

    # ------------------------------------------------------------------
    # Module introspection
    # ------------------------------------------------------------------

    def _get_module_label(self, package: Any) -> str:
        """Determine which module stream a package belongs to.

        Logic is derived from ``_what_provides()`` in DNF's own
        ``module_base.py``.
        """
        module_packages = self._dnf_base._moduleContainer.getModulePackages()
        base_query = self._dnf_base.sack.query().filterm(empty=True).apply()
        init_query = self._dnf_base.sack.query(
            flags=hawkey.IGNORE_MODULAR_EXCLUDES
        )

        subj = dnf.subject.Subject(
            f"{package.name}-{package.version}-{package.release}"
        )
        base_query = base_query.union(
            subj.get_best_query(
                self._dnf_base.sack,
                with_nevra=True,
                with_provides=False,
                with_filenames=False,
                query=init_query,
            )
        )
        base_query.apply()

        for mod_pkg in module_packages:
            artifacts = mod_pkg.getArtifacts()
            if not artifacts:
                continue
            query = base_query.filter(nevra_strict=artifacts)
            if query:
                ident = mod_pkg.getFullIdentifier()
                parts = ident.split(":")
                return f"{parts[0]}:{parts[1]}"

        return ""
