#!/usr/bin/python3
"""Output formatters for RepoVis reports.

Produces HTML (DataTables), CSV, or YAML-CVE output from a list of
:class:`PackageInfo` records.
"""

from __future__ import annotations

import csv
import datetime
import html
import io
import logging
import os
import shutil
import sys
import time
from typing import List

import yaml

from lib.models import PackageInfo

logger = logging.getLogger(__name__)


def _format_utc_date(epoch: int) -> str:
    """Convert an epoch timestamp to a UTC ``YYYY-MM-DD`` string."""
    return datetime.datetime.fromtimestamp(
        epoch, tz=datetime.timezone.utc
    ).strftime("%Y-%m-%d")


def _current_timestamp_string() -> str:
    """Return a human-readable 'now' timestamp with timezone indicator."""
    stamp = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    # Use the timezone name appropriate for whether DST is active
    tz_index = time.daylight and time.localtime().tm_isdst
    tz_name = time.tzname[tz_index] if time.tzname[tz_index] else "UTC"
    return f"{stamp} ({tz_name})"


class Output:
    """Render a list of :class:`PackageInfo` records to various formats.

    Args:
        packages: The package records to render.
        out_file: Optional file path to write output to.
            When empty, output is printed to stdout.
    """

    def __init__(self, packages: List[PackageInfo], out_file: str) -> None:
        self._packages = packages
        self._out_file = out_file

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def write_html(self, title: str, description: str, build_time: int) -> None:
        """Write an interactive HTML report using jQuery DataTables.

        Args:
            title: Page / heading title.
            description: Sub-heading (may contain HTML).
            build_time: Epoch start-date shown in the report header.
        """
        start_date = _format_utc_date(build_time)
        table_data = self._build_html_table_rows()

        timestamp = _current_timestamp_string()

        # Read the template from the bundled html/ directory
        template_path = os.path.join(
            os.path.dirname(__file__), "html", "html_template.html"
        )
        with open(template_path, "r") as f:
            html_data = f.read()

        html_data = (
            html_data.replace("@@TITLE@@", title)
            .replace("@@DESCRIPTION@@", description)
            .replace("@@START_DATE@@", start_date)
            .replace("@@TIMESTAMP@@", timestamp)
            .replace("@@TABLE_DATA@@", table_data)
        )

        if self._out_file:
            with open(self._out_file, "w") as f:
                f.write(html_data)

            out_dir = os.path.dirname(os.path.abspath(self._out_file))
            html_assets_dir = os.path.join(os.path.dirname(__file__), "html")
            for asset in (
                "jquery-3.6.0.min.js",
                "datatables.min.js",
                "datatables.min.css",
            ):
                shutil.copyfile(
                    os.path.join(html_assets_dir, asset),
                    os.path.join(out_dir, asset),
                )
            logger.info("JS, CSS, and HTML output written to: %s", out_dir)
        else:
            print(html_data)

    def _build_html_table_rows(self) -> str:
        """Build the ``<tr>`` elements for the HTML DataTable."""
        rows: list[str] = []

        for pkg in self._packages:
            esc = html.escape  # shorthand

            build_date = _format_utc_date(pkg.buildtime)

            # --- CVE cell ---
            cve_items = [
                f"<li>{esc(cve)}</li>"
                for cve_list in pkg.cve_dict.values()
                for cve in cve_list
            ]
            cve_html = (
                f"<ul>{''.join(cve_items)}</ul>" if cve_items else "-"
            )

            # --- Changelog cell ---
            change_lines: list[str] = []
            for entry in pkg.filtered_changelogs:
                change_lines.append(
                    f"{esc(entry.timestamp)}  :  \n{esc(entry.text)}"
                )
            change_text = "\n".join(change_lines).strip()

            split_lines = change_text.split("\n")
            if len(split_lines) >= 4:
                summary = "<br />\n".join(split_lines[:3])
                changelog_cell = (
                    f"{summary}<br />\n"
                    f"<br /><a><u>[Show All]</u></a>"
                    f"<pre>{change_text}</pre>"
                )
            else:
                changelog_cell = change_text.replace("\n", "<br />\n")

            rows.append(
                f"<tr>\n"
                f"<td> <b>{esc(pkg.source_name)}</b> </td>\n"
                f"<td> {esc(pkg.source_version)}-{esc(pkg.source_release)} </td>\n"
                f"<td> {esc(pkg.module_label)} </td>\n"
                f"<td> {build_date} </td>\n"
                f"<td> {cve_html} </td>\n"
                f"<td> {changelog_cell} </td>\n"
                f"</tr>\n"
            )

        return "\n".join(rows)

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    def write_csv(self) -> None:
        """Write a CSV report of packages and their CVE fixes."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Package", "Version", "Module", "Build Date", "CVE Fixes"])

        for pkg in self._packages:
            cve_text = " ".join(
                cve
                for cve_list in pkg.cve_dict.values()
                for cve in cve_list
            )
            writer.writerow([
                pkg.source_name,
                f"{pkg.source_version}-{pkg.source_release}",
                pkg.module_label,
                _format_utc_date(pkg.buildtime),
                cve_text,
            ])

        csv_data = buf.getvalue()

        if self._out_file:
            with open(self._out_file, "w") as f:
                f.write(csv_data)
            logger.info("CSV file written to: %s", self._out_file)
        else:
            print(csv_data)

    # ------------------------------------------------------------------
    # YAML-CVE
    # ------------------------------------------------------------------

    def write_cve_yaml(self, title: str, description: str) -> None:
        """Write a YAML summary of packages and their resolved CVEs.

        Only packages that have at least one CVE fix are included.

        Args:
            title: Report title (emitted as a YAML comment).
            description: Report description (emitted as a YAML comment).
        """
        yaml_text = f"# {title}\n\n# {description}\n\n---\n"

        header = {"version": "v1alpha1"}

        packages_dict: dict[str, dict] = {}
        for pkg in self._packages:
            if not pkg.cve_dict:
                continue

            cve_fixes: dict[str, list[str]] = {}
            for date, cves in pkg.cve_dict.items():
                cve_fixes[date] = [str(c) for c in cves]

            packages_dict[pkg.source_name] = {
                "package_version": f"{pkg.source_version}-{pkg.source_release}",
                "module_stream": str(pkg.module_label),
                "build_date": _format_utc_date(pkg.buildtime),
                "cve_fixes": cve_fixes,
            }

        yaml_text += yaml.dump(header) + yaml.dump({"packages": packages_dict})

        # Cosmetic fixups for readability (matches original behaviour)
        yaml_text = yaml_text.replace("  '", "  ")
        yaml_text = yaml_text.replace("':", ":")
        yaml_text = yaml_text.replace(" - ", "   - ")

        if self._out_file:
            with open(self._out_file, "w") as f:
                f.write(yaml_text)
            logger.info("YAML CVE file written to: %s", self._out_file)
        else:
            print(yaml_text)
