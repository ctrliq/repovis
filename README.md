# RepoVis

Simple tool to gather information about one or more DNF repositories.  Scans of versions, build times, and changelogs are performed, and a friendly summary in HTML, CSV, or YAML is presented.

The tool will filter by "days ago" ("--days") or a particular start date ("--startdate"), and only consider that time period.

CVE text from the changelog is extracted for easy summary about what has or has not been fixed.

This program requires python3 and the DNF+RPM libraries to be installed



## Examples:

Get a 21 day update report for Rocky Linux 8's:  default repositories
```
python3 repovis.py --days 21  --file ./update_report/Updates.html --output html   --title "Rocky Linux 21 Day History"  --description "Rocky Package updates (BaseOS/AppStream/PowerTools) from the past 21 days."  baseos appstream powertools
```

<br />

Get a CSV report for a custom repository from a certain date, with known fixes (yaml) added:
(This is not a system repository, but assumes an alternate .repo file exists in ./repos.tmp/ ):
```
python3 ${REPOVIS} --startdate 2022-05-11 --cveyaml ./tmp/my_fixes.yaml  --file ./update_since_2022.csv  --output csv  --repodir ./repos.tmp/  --title "Custom Repo Since May 2022" --description "Packages from the custom LTS repository, with fixes added.  Since May 2022."  custom-lts-repo-8 custom-lts-repo-8-additional
```


## Manual CVE fix additions

Changelogs, CVE codes, and other information can be added to or overridden via custom YAML files read from a file.  

