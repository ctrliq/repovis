# Feature: Local Advisory Directory & CVSS Scoring

## Overview

RepoVis can now read CIQ CSAF advisory JSON files directly from a local
directory, eliminating the need for a separate `read_lts_advisories.py`
script and its git-clone step. When advisory data is available, CVSS v3
scoring information (base score and base severity) is also extracted and
carried through the data model for downstream use.

## New CLI Options

### `--advisory-dir <path>`

Path to a local directory containing CSAF advisory JSON files (searched
recursively for `*.json`). The advisory data is processed on the fly to
generate supplemental CVE data — functionally equivalent to passing a
pre-built YAML file via `--cveyaml`.

- **Mutually exclusive** with `--cveyaml`.
- **Requires** `--product-codes`.

### `--product-codes <code> [<code> ...]`

One or more product-code strings used to filter which fixed RPMs in the
advisory JSONs are relevant (e.g. `lts-8.6`, `fipscompliant-8`,
`cbr-7.9`). Only entries whose product ID matches one of these codes
are included.

### Example

```bash
# Using a local clone of the advisories repo:
./repovis.py \
    --advisory-dir ~/advisories/csaf \
    --product-codes lts-9.2 \
    -s 2025-01-01 \
    -o html \
    -f report.html \
    rlc-9.2-lts.x86_64
```

This replaces the previous two-step workflow:

```bash
# Old workflow (no longer needed):
./read_lts_advisories.py lts-9.2 > cves.yaml
./repovis.py -c cves.yaml -s 2025-01-01 -o html rlc-9.2-lts.x86_64
```

## Backward Compatibility

### Existing `--cveyaml` files

The `--cveyaml` option continues to work exactly as before. YAML files
with plain string CVE lists are fully supported:

```yaml
packages:
  openssl:
    cve_fixes:
      '2025-03-01':
        - CVE-2025-1234
        - CVE-2025-5678
```

### Mixed data sources

The `--advisory-dir` and `--cveyaml` options are mutually exclusive.
However, `PackageRead` internally merges advisory-generated data with
any programmatically supplied CVE data, deduplicating by CVE ID across
both plain string entries and rich dict entries.

## Data Model Changes

### `CvssInfo` (new dataclass in `lib/models.py`)

| Field           | Type    | Description                      |
| --------------- | ------- | -------------------------------- |
| `base_score`    | `float` | CVSS v3 base score (e.g. `8.1`)  |
| `base_severity` | `str`   | CVSS v3 severity (e.g. `"HIGH"`) |

### `PackageInfo.cvss_data` (removed)

CVSS data was initially stored per-package on `PackageInfo.cvss_data`.
This has been replaced by a **global** `cvss_map: Dict[str, CvssInfo]`
on `PackageRead`, because CVSS scores are CVE-global (a given CVE always
has the same score regardless of which package ships the fix).

The global map is passed to the `Output` class and used to enrich all
three output formats (HTML, CSV, YAML-CVE).

The existing `cve_dict: Dict[str, List[str]]` field is **unchanged** —
CVE ID lists remain plain strings in all contexts.

## Internal Architecture

### `lib/advisory_read.py` (new module)

- `read_advisories_from_directory(advisory_dir, product_codes)` —
  recursively scans a directory for `*.json` advisory files and returns
  a data structure matching the supplemental CVE YAML schema.
- `_process_advisory(...)` — processes a single advisory document,
  extracting CVE IDs, CVSS v3 scores, fix dates, and SRPM names.
- `_extract_cvss_v3(vuln)` — extracts `baseScore` and `baseSeverity`
  from the CSAF `scores[].cvss_v3` block.

Each CVE entry produced by the advisory reader is a dict:

```python
{
    "cve_id": "CVE-2025-1234",
    "base_score": 8.1,
    "base_severity": "HIGH"
}
```

### `lib/package_read.py` changes

- **`__init__`** accepts a new optional `cve_data` parameter for
  pre-built CVE data (from the advisory reader).
- **`_merge_cve_data()`** merges advisory data into `cve_extra`,
  handling both plain string and dict CVE entries when deduplicating.
- **`_get_cves_from_changelog()`** normalises dict entries back to
  plain CVE-ID strings for `cve_dict`, preserving backward
  compatibility with all output formatters.
- **`_get_cvss_data()`** (retained) extracts CVSS metadata from the
  supplemental data for a single package. Superseded at the top level
  by `_build_global_cvss_map()`.
- **`_build_global_cvss_map()`** (new) iterates all packages in
  `cve_extra` once and builds a flat `Dict[str, CvssInfo]` stored as
  `self.cvss_map`.

### `repovis.py` changes

- Imports `read_advisories_from_directory`.
- Adds `--advisory-dir` and `--product-codes` argument definitions.
- Validates mutual exclusivity and required combinations.
- Calls the advisory reader before constructing `PackageRead` and
  passes the result via the new `cve_data` parameter.
- Passes `reader.cvss_map` to the `Output` constructor.

## CVSS in Output Formats

When CVSS data is available (via `--advisory-dir` or rich dict entries
in `--cveyaml` source data), scores and severities are included in all
three output formats. When no CVSS data exists, output is identical to
the previous behaviour — graceful degradation throughout.

### HTML

Each CVE in the list gets an inline coloured label:

```html
<li>CVE-2025-1234 <span class="cvss cvss-high">(8.1 HIGH)</span></li>
<li>CVE-2025-9999</li>
<!-- no CVSS data: rendered as before -->
```

Severity CSS classes (`cvss-critical`, `cvss-high`, `cvss-medium`,
`cvss-low`, `cvss-none`) are defined in `html_template.html`.

### CSV

A new `CVSS Scores` column is appended. Entries are positionally
aligned with the CVEs in the `CVE Fixes` column:

```
Package,Version,Module,Build Date,CVE Fixes,CVSS Scores
openssl,3.0.7-28.el9,-, 2025-03-01,CVE-2025-1234 CVE-2025-9999,CVE-2025-1234:8.1:HIGH CVE-2025-9999::
```

CVEs without CVSS data use the placeholder `CVE-ID::` to preserve
positional alignment with the CVE Fixes column.

### YAML-CVE

CVE ID lists in `cve_fixes` remain plain strings (unchanged). A
separate top-level `cvss` section is appended:

```yaml
packages:
  openssl:
    cve_fixes:
      2025-03-01:
        - CVE-2025-1234
        - CVE-2025-9999
cvss:
  CVE-2025-1234:
    base_score: 8.1
    base_severity: HIGH
```

Only CVEs that have CVSS data appear in the `cvss` section. The section
is omitted entirely when no CVSS data is available.
