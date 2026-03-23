# CVSS Scoring in RepoVis

## Overview

When advisory data is available, RepoVis extracts CVSS v3 scoring
information (base score and base severity) and displays it alongside
CVE identifiers in all three output formats. CVSS enrichment is
entirely optional — when no scoring data is present, output is
identical to the previous behaviour.

## Data Sources

CVSS scores are extracted from **CSAF advisory JSON files** supplied
via the `--advisory-dir` CLI option. Each advisory's
`vulnerabilities[].scores[].cvss_v3` block is read to obtain
`baseScore` and `baseSeverity`.

Scores are **not** extracted from plain `--cveyaml` files (those
contain only CVE ID strings). However, when a YAML-CVE report is
_written_ with CVSS data present, the scores are included in a
separate `cvss` section (see [YAML-CVE output](#yaml-cve) below), so
downstream consumers that re-read RepoVis YAML output can access the
scores.

## Architecture

### Global CVSS Map

CVE IDs are globally unique — a given CVE always carries the same
CVSS score regardless of which package ships the fix. RepoVis
therefore builds a single flat lookup once:

```
PackageRead
  ├── self.packages: List[PackageInfo]     (per-package metadata)
  └── self.cvss_map: Dict[str, CvssInfo]   (global CVE → score map)
```

`cvss_map` is built by `_build_global_cvss_map()` after all packages
have been collected. It iterates every package entry in
`self.cve_extra` and collects each dict item that carries both
`base_score` and `base_severity`.

The map is passed to the `Output` class, which uses it to enrich all
three output formats via two small helpers:

| Helper              | Returns                                          |
| ------------------- | ------------------------------------------------ |
| `_cvss_label(cve)`  | `"8.1 HIGH"` or `""` (plain text)                |
| `_cvss_html_span()` | `<span class="cvss cvss-high">(8.1 HIGH)</span>` |

### CvssInfo Dataclass

Defined in `lib/models.py`:

```python
@dataclass
class CvssInfo:
    base_score: float      # e.g. 8.1
    base_severity: str     # e.g. "HIGH"
```

## Output Formats

### HTML

Each CVE in the report list receives an inline coloured label when
CVSS data is available:

```html
<ul>
  <li>CVE-2025-1234 <span class="cvss cvss-high">(8.1 HIGH)</span></li>
  <li>CVE-2025-9999</li>
</ul>
```

CVEs without scoring data are rendered exactly as before (ID only).

#### Severity CSS Classes

Defined in `lib/html/html_template.html`:

| Class            | Colour     | Score Range |
| ---------------- | ---------- | ----------- |
| `.cvss-critical` | Dark red   | 9.0 – 10.0  |
| `.cvss-high`     | Red        | 7.0 – 8.9   |
| `.cvss-medium`   | Orange     | 4.0 – 6.9   |
| `.cvss-low`      | Grey       | 0.1 – 3.9   |
| `.cvss-none`     | Light grey | 0.0         |

### CSV

A `CVSS Scores` column is appended after `CVE Fixes`:

```
Package,Version,Module,Build Date,CVE Fixes,CVSS Scores
openssl,3.0.7-28.el9,-,2025-03-01,CVE-2025-1234 CVE-2025-9999,CVE-2025-1234:8.1:HIGH CVE-2025-9999::
```

Each entry in the CVSS column is `CVE-ID:score:SEVERITY`, separated
by spaces. CVEs without CVSS data use the placeholder `CVE-ID::` to
preserve positional alignment with the `CVE Fixes` column.

When no CVSS data exists at all, the column is empty.

### YAML-CVE

CVE ID lists in `cve_fixes` remain **plain strings** (unchanged).
CVSS data is written as a separate top-level `cvss` section:

```yaml
version: v1alpha1
packages:
  openssl:
    package_version: 3.0.7-28.el9
    module_stream: '-'
    build_date: '2025-03-01'
    cve_fixes:
      2025-03-01:
        - CVE-2025-1234
        - CVE-2025-9999
cvss:
  CVE-2025-1234:
    base_score: 8.1
    base_severity: HIGH
```

Key properties:

- **Backward-compatible** — existing YAML consumers that read only
  `packages` are unaffected; the `cvss` key is simply ignored.
- **No duplication** — each CVE ID appears once in the per-package
  lists and at most once in the global `cvss` block.
- **Optional** — the `cvss` section is omitted entirely when no
  scoring data is available.
- **Forward-compatible** — new fields (e.g. `vector_string`) can be
  added to `cvss` entries without changing the list structure.

## Graceful Degradation

| Scenario                           | Behaviour                              |
| ---------------------------------- | -------------------------------------- |
| `--advisory-dir` with CVSS data    | Scores shown in all output formats     |
| `--advisory-dir` without CVSS data | Output identical to pre-CVSS behaviour |
| `--cveyaml` only                   | No CVSS data; output unchanged         |
| No CVE source at all               | No CVE or CVSS data; output unchanged  |
