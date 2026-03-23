#!/usr/bin/python3
"""RepoVis — DNF repository history visualiser.

Scans one or more DNF repositories for recent package updates, extracts
changelogs and CVE references, and produces a summary report in HTML,
CSV, or YAML format.
"""

from __future__ import annotations

import argparse
import datetime
import logging
import sys
import time

from lib.output import Output
from lib.package_read import PackageRead

logger = logging.getLogger(__name__)


def _build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Gather and summarise DNF repository history."
    )
    parser.add_argument(
        "-d", "--days",
        type=int,
        default=0,
        help="How many days back should the repository history be searched through.",
    )
    parser.add_argument(
        "-s", "--startdate",
        type=str,
        default="",
        help=(
            "Earliest date to start searching repository history (YYYY-MM-DD). "
            "Conflicts with --days."
        ),
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        default="",
        help=(
            "File to write report to (default is stdout). "
            "HTML output will have .css and .js files copied to the same directory."
        ),
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="html",
        choices=["html", "csv", "yaml-cve"],
        help="Type of output to produce.",
    )
    parser.add_argument(
        "-r", "--repodir",
        type=str,
        default="",
        help=(
            "Alternate DNF repository config directory where *.repo files are located. "
            "Default is /etc/yum.repos.d/."
        ),
    )
    parser.add_argument(
        "-c", "--cveyaml",
        type=str,
        default="",
        help=(
            "Custom YAML file with additional dates + CVEs resolved. "
            "See docs for the specific YAML format."
        ),
    )
    parser.add_argument(
        "-t", "--title",
        type=str,
        default="Repository Recent History Summary",
        help="Title at top of document for HTML and YAML output.",
    )
    parser.add_argument(
        "--description",
        type=str,
        default="",
        help=(
            "Description header (below title) for HTML and YAML output. "
            "May also contain custom HTML."
        ),
    )
    parser.add_argument(
        "repos",
        type=str,
        nargs="+",
        help=(
            'DNF repositories (one or more, space-separated) to consider. '
            'Must be the proper name as shown in "dnf repolist".'
        ),
    )
    return parser


def _calculate_build_time(args: argparse.Namespace) -> int:
    """Derive the epoch 'origin point' from CLI arguments.

    Packages built before this timestamp are excluded from the report.
    """
    build_time: int | None = None

    if args.days > 0:
        build_time = int(time.time()) - (args.days * 86400)

    if args.startdate:
        build_time = int(
            datetime.datetime.strptime(args.startdate, "%Y-%m-%d").timestamp()
        )

    if build_time is None:
        logger.error(
            "Must specify --days or --startdate YYYY-MM-DD on the command line."
        )
        sys.exit(1)

    return build_time


def main() -> None:
    """Entry point for the RepoVis CLI."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    parser = _build_arg_parser()
    args = parser.parse_args()

    build_time = _calculate_build_time(args)

    reader = PackageRead(
        repo_list=args.repos,
        repo_dir=args.repodir,
        latest=True,
        build_time=build_time,
        cve_file=args.cveyaml,
    )

    out = Output(reader.packages, args.file)

    if args.output == "html":
        out.write_html(args.title, args.description, build_time)
    elif args.output == "csv":
        out.write_csv()
    elif args.output == "yaml-cve":
        out.write_cve_yaml(args.title, args.description)

    reader.cleanup()


if __name__ == "__main__":
    main()

