# PkgReview

Simple tool to gather information about a collection of source DNF repos, and compare to a collection of target DNF repos.

Figures out which packages has been added or updated, identifies relevant changelog entries, extracts CVE fix info from those logs.

Organizes the information into a friendly format, either pretty HTML (for human consumption) or YAML (machine readable).

For example, you might compare the vaulted Rocky 8.6 repositories (source) against CIQ's LTS-8.6 repository (target).  You would then see what changes, CVE fixes, etc. were added to the LTS-8.6 repository.

## Setup

Configuration is done via simple Python file which defines some variables:  setup_vars.py .  This file should be modified, or perhaps sym-linked to an appropriate file if multiple need to be maintained.


## Manual Override

Changelogs, CVE codes, and other information can be added to or overridden via custom YAML files read from a directory

