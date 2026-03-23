"""Read CIQ CSAF advisory JSON files and produce CVE fix data.

Replicates the logic of ``read_lts_advisories.py`` but operates on a
local directory of advisory JSON files instead of cloning a Git repo.
The output is a dictionary matching the supplemental CVE YAML schema
consumed by :class:`PackageRead`.

Each CVE entry in the ``cve_fixes`` lists is a dict containing at
minimum a ``cve_id`` key, plus optional ``base_score`` and
``base_severity`` when CVSS v3 data is present in the advisory:

.. code-block:: python

    {
        "packages": {
            "<srpm-name>": {
                "cve_fixes": {
                    "YYYY-MM-DD": [
                        {
                            "cve_id": "CVE-...",
                            "base_score": 8.1,
                            "base_severity": "HIGH"
                        },
                        ...
                    ],
                    ...
                }
            },
            ...
        }
    }

This format is backward-compatible: :class:`PackageRead` handles both
plain string entries (from legacy YAML files) and dict entries.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def read_advisories_from_directory(
    advisory_dir: str,
    product_codes: List[str],
) -> Dict[str, Any]:
    """Scan *advisory_dir* for CSAF JSON files and extract CVE fix data.

    Args:
        advisory_dir: Path to a local directory containing ``*.json``
            advisory files (searched recursively).
        product_codes: One or more product-code strings used to filter
            which fixed RPMs are relevant (e.g. ``["lts-8.6"]``).

    Returns:
        A dictionary with the same structure as the supplemental CVE
        YAML file expected by :class:`PackageRead`.
    """
    fixes: Dict[str, Any] = {"packages": {}}
    advisory_path = Path(advisory_dir)

    if not advisory_path.is_dir():
        logger.error(
            "Advisory directory does not exist or is not a directory: %s",
            advisory_dir,
        )
        return fixes

    json_files = list(advisory_path.rglob("*.json"))
    if not json_files:
        logger.warning("No JSON advisory files found in: %s", advisory_dir)
        return fixes

    logger.info(
        "Processing %d advisory JSON file(s) from: %s",
        len(json_files),
        advisory_dir,
    )

    for json_file in json_files:
        try:
            with open(json_file) as fh:
                advisory_data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping %s: %s", json_file, exc)
            continue

        _process_advisory(advisory_data, product_codes, fixes)

    return fixes


def _process_advisory(
    advisory_data: Dict[str, Any],
    product_codes: List[str],
    fixes: Dict[str, Any],
) -> None:
    """Extract CVE-fix entries from a single advisory document.

    Mutates *fixes* in place to accumulate results across many files.
    """
    # Safely extract the release date (YYYY-MM-DD)
    try:
        fix_date = str(
            advisory_data["document"]["tracking"]["current_release_date"][:10]
        )
    except (KeyError, TypeError, IndexError):
        logger.warning("Advisory missing tracking/current_release_date — skipping")
        return

    vulnerabilities = advisory_data.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        cve = vuln.get("cve")
        if not cve:
            continue

        # Extract CVSS v3 scoring (first score entry, if available)
        base_score, base_severity = _extract_cvss_v3(vuln)

        product_status = vuln.get("product_status", {})
        fixed_rpms = product_status.get("fixed")
        if not fixed_rpms:
            # "will not fix" or no fixed products listed
            continue

        # Build the CVE entry dict
        cve_entry: Dict[str, Any] = {"cve_id": cve}
        if base_score is not None:
            cve_entry["base_score"] = base_score
        if base_severity is not None:
            cve_entry["base_severity"] = base_severity

        for rpm in fixed_rpms:
            for prod_id in product_codes:
                if f"{prod_id}:" not in rpm or ".src" not in rpm:
                    continue

                # Derive the SRPM (source package) name by stripping the
                # product-code prefix and the final two hyphen-delimited
                # segments (version and release).
                srpm = rpm.split(":", 1)[1]
                srpm = srpm[: srpm.rfind("-")]
                srpm = srpm[: srpm.rfind("-")]

                packages = fixes["packages"]

                if srpm not in packages:
                    packages[srpm] = {"cve_fixes": {}}

                cve_fixes = packages[srpm]["cve_fixes"]

                if fix_date not in cve_fixes:
                    cve_fixes[fix_date] = []

                # Avoid duplicates (check by cve_id)
                if not any(
                    (e.get("cve_id") if isinstance(e, dict) else e) == cve
                    for e in cve_fixes[fix_date]
                ):
                    cve_fixes[fix_date].append(cve_entry)


def _extract_cvss_v3(
    vuln: Dict[str, Any],
) -> tuple:
    """Return ``(base_score, base_severity)`` from the first CVSS v3 score.

    Returns ``(None, None)`` when no scoring data is available.
    """
    scores = vuln.get("scores", [])
    for score_block in scores:
        cvss_v3 = score_block.get("cvss_v3")
        if cvss_v3:
            return cvss_v3.get("baseScore"), cvss_v3.get("baseSeverity")
    return None, None
