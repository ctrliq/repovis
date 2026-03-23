"""Data models for RepoVis package information.

Provides an explicit dataclass-based model to replace the monkey-patched
dnf Package objects that were previously passed between modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class CvssInfo:
    """CVSS v3 scoring information for a single CVE."""

    base_score: float
    base_severity: str


@dataclass
class ChangelogEntry:
    """A single changelog entry with a timestamp and text body."""

    timestamp: str
    text: str


@dataclass
class PackageInfo:
    """Canonical representation of a source package and its metadata.

    This replaces the previously monkey-patched ``dnf.package.Package``
    objects so that consumers (e.g. ``Output``) no longer depend on
    undocumented, runtime-injected attributes.
    """

    source_name: str
    source_version: str
    source_release: str
    module_label: str
    buildtime: int
    filtered_changelogs: List[ChangelogEntry] = field(default_factory=list)
    cve_dict: Dict[str, List[str]] = field(default_factory=dict)
