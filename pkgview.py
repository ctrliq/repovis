#!/usr/bin/python3


from lib.PackageRead import *
import time,datetime,sys


# Read packages from these repos, only grab latest:
repos = ["http://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/","http://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/"]

daysAgo = 0
buildDate = ""
buildTime = 0

buildDate = "2023-11-30"


# Calculate the "origin point": any packages built before this time are not checked for changes
if buildDate != "":
    buildTime = int(datetime.datetime.strptime(buildDate, "%Y-%m-%d").timestamp())

if int(daysAgo) > 0:
    buildTime = int(time.time()) - int(daysAgo * 86400)

if buildDate == "" and int(daysAgo) <= 0:
    print("Error, *must* specify --days  or --date YYYY-MM-DD  on the command line!")
    sys.exit(1)

packageRepo1 = PackageRead(repos, True, buildTime)

pkgGroup1 = packageRepo1.pkg

#for p in pkg:
#  cves = ""
#  for c in p.cve_list:
#    cves = cves +  str(c) + " , "
  
#  changes=""
#  for c in range(0, 3):
#    changes += str(p.changelogs[c]["text"]) + "\n"


#  + "\n\tCVE Fixed List == " + str(cves.replace("\n", " ")) 

print("len pkg == " + str(len(packageRepo1.pkg)))
print("len pkgGroup1 == " + str(len(pkgGroup1)))

for p in packageRepo1.pkg:
    
    changes = "\"\"\"\n"
    for c in range(0, min(3, len(p.changelogs))):
        changes += str(p.changelogs[c]["text"]) + "  (DATE :: " + str(p.changelogs[c]["timestamp"]) + ")\n"
    changes += "\"\"\""
    
    print("N V R == " + p.rName + "-"  + p.version + "-" + p.release +  "\n\tRemote URL:" + str(p.remote_location())  + "\n\tmodule_label == " + p.module_label + "\n\tBuildTime == " + str(p.buildtime) +  "\n\tChangelog == \n" + str(changes) +  "\n\n")


