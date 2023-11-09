#!/usr/bin/python3


from lib.PackageRead import *

repos = ["http://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/","http://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/"]

packageRepo1 = PackageRead(repos)

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
        changes += str(p.changelogs[c]["text"]) + "\n"
    changes += "\"\"\""
    
    print("N V R == " + p.rName + "   "  + p.version + "  " + p.release +  "\n\tRemote URL:" + str(p.remote_location())  + "\n\tmodule_label == " + p.module_label + "\n\tChangelog == \n" + str(changes) +  "\n\n")


