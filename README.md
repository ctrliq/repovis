# RepoVis

RepoVis scans one or more DNF repositories for recent package updates, extracts changelogs and CVE references, and produces a summary report in **HTML**, **CSV**, or **YAML** format.

Key capabilities:

- Filter by a rolling window (`--days`) or a fixed start date (`--startdate`).
- Extract CVE identifiers from changelogs for a quick security overview.
- Enrich reports with **CVSS v3 scores** when CSAF advisory data is available.
- Support both system and custom repository configurations.

## Requirements

- Python 3
- DNF and RPM libraries (`dnf`, `rpm` Python bindings — pre-installed on RHEL/Rocky/CentOS)

## Quick Start

```bash
python3 repovis.py --days 30 --output html --file report.html <repo-name>
```

## CLI Reference

| Option                               | Description                                                                                                                                                                                         |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-d`, `--days N`                     | How many days back to search. Mutually exclusive with `--startdate`.                                                                                                                                |
| `-s`, `--startdate YYYY-MM-DD`       | Earliest date to search from. Mutually exclusive with `--days`.                                                                                                                                     |
| `-o`, `--output {html,csv,yaml-cve}` | Output format (default: `html`).                                                                                                                                                                    |
| `-f`, `--file PATH`                  | Write report to a file instead of stdout. HTML output also copies `.css` and `.js` assets to the same directory.                                                                                    |
| `-r`, `--repodir PATH`               | Alternate directory containing `.repo` files (default: `/etc/yum.repos.d/`).                                                                                                                        |
| `-c`, `--cveyaml PATH`               | Custom YAML file with additional CVE fix data. Mutually exclusive with `--advisory-dir`.                                                                                                            |
| `--advisory-dir PATH`                | Path to a directory containing CSAF advisory JSON files (searched recursively). Generates supplemental CVE + CVSS data on the fly. Requires `--product-codes`. Mutually exclusive with `--cveyaml`. |
| `--product-codes CODE [CODE ...]`    | One or more product codes to filter advisory data (e.g. `lts-9.2`, `rlc-9.2`, `fips-9.2-certified`). Required when `--advisory-dir` is set.                                                         |
| `-t`, `--title TEXT`                 | Report title for HTML and YAML output.                                                                                                                                                              |
| `--description TEXT`                 | Description header (below title) for HTML and YAML output. May contain custom HTML.                                                                                                                 |
| `repos` (positional)                 | One or more DNF repository names to scan, as shown in `dnf repolist`.                                                                                                                               |

> **Note:** You must specify either `--days` or `--startdate`.

## Examples

### HTML report — system repositories (last 21 days)

```bash
python3 repovis.py \
  --days 21 \
  --output html \
  --file ./update_report/Updates.html \
  --title "Rocky Linux 21 Day History" \
  --description "Rocky package updates (BaseOS/AppStream) from the past 21 days." \
  baseos appstream
```

### CSV report — custom repository with manual CVE YAML

Use `--repodir` when scanning repositories that are not in `/etc/yum.repos.d/`:

```bash
python3 repovis.py \
  --startdate 2022-05-11 \
  --cveyaml ./tmp/my_fixes.yaml \
  --output csv \
  --file ./update_since_2022.csv \
  --repodir ./repos.tmp/ \
  --title "Custom Repo Since May 2022" \
  --description "Packages from the custom LTS repository with fixes added." \
  custom-lts-repo-8 custom-lts-repo-8-additional
```

### YAML-CVE report — with CSAF advisory directory

When you have a local clone of an advisories repository, use `--advisory-dir` and `--product-codes` instead of `--cveyaml`. This reads CSAF JSON files directly and also extracts CVSS v3 scoring data:

```bash
python3 repovis.py \
  --advisory-dir ../advisories/csaf/advisories \
  --product-codes lts-9.2 rlc-9.2 \
  --repodir .tmp/ \
  --output yaml-cve \
  --startdate 2024-01-01 \
  --file output.yaml \
  --title "Rocky Linux 9.2 LTS CVE Report" \
  --description "CVE summary for Rocky Linux 9.2 CIQ LTS repositories." \
  rlc-9.2-lts.aarch64 rocky-9.2-baseos.aarch64 rocky-9.2-appstream.aarch64 rocky-9.2-extras.aarch64
```

### HTML report — with CSAF advisory directory

Same as above but with interactive HTML output:

```bash
python3 repovis.py \
  --advisory-dir ../advisories/csaf/advisories \
  --product-codes lts-9.2 rlc-9.2 \
  --repodir .tmp/ \
  --output html \
  --startdate 2024-01-01 \
  --file output.html \
  --title "Rocky Linux 9.2 LTS CVE Report" \
  --description "CVE summary for Rocky Linux 9.2 CIQ LTS repositories." \
  rlc-9.2-lts.aarch64 rocky-9.2-baseos.aarch64 rocky-9.2-appstream.aarch64 rocky-9.2-extras.aarch64
```

## CVE Data Sources

RepoVis supports two ways to supply supplemental CVE fix data (in addition to what is extracted from changelogs):

### 1. CSAF Advisory Directory (`--advisory-dir`)

Point to a directory containing CSAF advisory JSON files. RepoVis recursively scans for `*.json` files and extracts:

- CVE identifiers and fix dates
- CVSS v3 base score and severity

Use `--product-codes` to specify which product entries to match (e.g. `lts-9.2`, `rlc-9.2`, `fips-9.2-certified`). Only advisory entries whose product ID matches one of the given codes are included.

> This replaces the previous two-step workflow of running a separate advisory-parsing script and then passing the result via `--cveyaml`.

### 2. Manual CVE YAML (`--cveyaml`)

Changelogs, CVE codes, and other information can be added to or overridden via a custom YAML file:

```yaml
packages:
  openssl:
    cve_fixes:
      '2025-03-01':
        - CVE-2025-1234
        - CVE-2025-5678
```

> **Note:** `--advisory-dir` and `--cveyaml` are mutually exclusive.

## CVSS Scoring

When advisory data is supplied via `--advisory-dir`, CVSS v3 base scores and severities are automatically included in all output formats:

- **HTML** — Inline coloured labels next to each CVE (Critical / High / Medium / Low).
- **CSV** — A `CVSS Scores` column with `CVE-ID:score:SEVERITY` entries.
- **YAML-CVE** — A separate top-level `cvss` section mapping CVE IDs to scores.

When no CVSS data is available, output is identical to the previous behaviour.

See [docs/cvss-scoring.md](docs/cvss-scoring.md) for full details.

## Further Documentation

- [Advisory Directory Option](docs/advisory-dir-option.md) — detailed architecture and data-model documentation for `--advisory-dir`.
- [CVSS Scoring](docs/cvss-scoring.md) — how CVSS data flows through the pipeline and appears in each output format.
