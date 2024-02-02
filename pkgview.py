#!/usr/bin/python3

"""
options:

--days 60
--startdate 2023-11-05
--latest false (true by default)
--file <file.csv>  (make it take a folder for html(?))
--folder /tmp/html_out/ (for html output - must exist)
--outform html/csv/yaml
--cveyaml  <extra_cve_defs.yaml>  (yaml file with extra CVE listings to add to output)
--repodir /path/to/*.repo  --> override system repos.d folder with own location
--title (html title) (add as comment to yaml output header?)
--description (html description) (add as comment to yaml output header?

N args:
repo1 repo2 repo3
"""

from lib.PackageRead import *
from lib.Output import *
import time,datetime,sys


daysAgo = 0
startDate = ""
buildTime = 0


#daysAgo=60
startDate = "2022-12-15"
latest = True
fileOut = "/tmp/repohistory.html"
folderOut = ""
outForm = "html"
cveYaml = ""
repoDir = "/home/skip/src/pkgview/tmp"
title = "CIQ Rocky LTS 8.6 Packages"
description = "A look at CIQ LTS-8.6 packages, publication times, CVE fixes, and summary."
repoList = ['lts-8.6']

# Calculate the "origin point": any packages built before this time are not checked for changes
if startDate != "":
    buildTime = int(datetime.datetime.strptime(startDate, "%Y-%m-%d").timestamp())

if int(daysAgo) > 0:
    buildTime = int(time.time()) - int(daysAgo * 86400)

if startDate == "" and int(daysAgo) <= 0:
    print("Error, *must* specify --days  or --date YYYY-MM-DD  on the command line!")
    sys.exit(1)

packages = PackageRead(repoList,repoDir, True, buildTime)

#pkgGroup1 = packageRepo1.pkg


out = Output(packages.pkg, fileOut)

out.writeHTML(title, description, str(datetime.datetime.utcfromtimestamp(buildTime).strftime('%Y-%m-%d')))

sys.exit(0)

