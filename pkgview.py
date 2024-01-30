#!/usr/bin/python3


from lib.PackageRead import *
from lib.Output import *
import time,datetime,sys


# Read packages from these repos, only grab latest:
#repos = ["http://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/","http://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/"]
repos = ['https://repo.ciq.com/v1/<KEY>/subscriptions/lts-8.6/hashed-CIQ_LTS_86/x86_64']

daysAgo = 0
buildDate = ""
buildTime = 0

title = "CIQ Rocky LTS 8.6 Packages"
description = "A look at CIQ LTS-8.6 packages, publication times, CVE fixes, and summary."


buildDate = "2022-12-15"
#daysAgo=60

# Calculate the "origin point": any packages built before this time are not checked for changes
if buildDate != "":
    buildTime = int(datetime.datetime.strptime(buildDate, "%Y-%m-%d").timestamp())

if int(daysAgo) > 0:
    buildTime = int(time.time()) - int(daysAgo * 86400)

if buildDate == "" and int(daysAgo) <= 0:
    print("Error, *must* specify --days  or --date YYYY-MM-DD  on the command line!")
    sys.exit(1)

packages = PackageRead(repos, True, buildTime)

#pkgGroup1 = packageRepo1.pkg


out = Output(packages.pkg, "/tmp/repohistory.html")

out.writeHTML(title, description, str(datetime.datetime.utcfromtimestamp(buildTime).strftime('%Y-%m-%d')))

sys.exit(0)

print("len pkg == " + str(len(packageRepo1.pkg)))
print("len pkgGroup1 == " + str(len(pkgGroup1)))

for p in packageRepo1.pkg:
        
    changes = "\"\"\"\n"
    for c in range(0, len(p.filter_changelogs)):
        changes += str(p.filter_changelogs[c]["text"]) + "  (DATE :: " + str(p.filter_changelogs[c]["timestamp"]) + ")\n"
    changes += "\"\"\""
    
    for c in p.cve_dict.keys():
        changes += "\nCVE : " + str(c) + " : " + str(p.cve_dict[c])
        
    print("N V R == " + p.source_name + "-"  + p.source_version + "-" + p.source_release +  "\n\tRemote URL:" + str(p.remote_location())  + "\n\tmodule_label == " + p.module_label + "\n\tBuildTime == " + str(p.buildtime) +  "\n\tChangelog == \n" + str(changes) +  "\n\n")
    
"""
    changeText = ""
    for c in range(0, len(p.filter_changelogs)):
        changeText += str(p.filter_changelogs[c]["timestamp"]) + "  :  \n" + str(p.filter_changelogs[c]["text"]) + "\n"
    
    print(p.source_name + "\n" + changeText)
"""
