#!/usr/bin/python3

import dnf

import os,shutil,subprocess,sys


# Configure DNF for a set of repositories, and load all package information into memory (returned as an object)
# We'll compare these objects (multiple sets of repos) in another class to determine changes, CVEs fixed, changelogs, etc.
#
# Need a set of repos given as a simple list of strings: ["https://reposite.com/repo/repo1", "http://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/"]
# We also feed a "latest" boolean.  If latest=true, only the most recent version from the repos are considered
#   (we have to determine this programmatically after finding module stream info, or else we end up discarding all but the latest module stream(!) )
class PackageRead:

    pkg = []
    
    def __init__(self, repoList, latest):
        if os.path.exists('/tmp/temp_dnf_cache'):
            shutil.rmtree('/tmp/temp_dnf_cache')
        dnfBase = dnf.Base()
        dnfConf = dnfBase.conf

        dnfConf.gpgcheck=False
        dnfConf.reposdir="/tmp"
        dnfConf.cachedir="/tmp/temp_dnf_cache"


        # Add all the repos to our dnf configuration.  Each one is designated "repoId_#", with the passed in list of URLs
        repos=[]
        for r in range(0, len(repoList)):
            repos.append(dnfBase.repos.add_new_repo("repoId_" + str(r), dnfConf, baseurl=[str(repoList[r])]))
            repos[r].load_metadata_other = True
            repos[r].module_hotfixes = True    
        
        dnfBase.read_all_repos()
        dnfBase.fill_sack(load_system_repo=False)

        # Gather list of all packages in the repo to a temporary list:
        tmpPkgList = dnfBase.sack.query().available().filter()
        
        # Get a mapping of modular package -> module stream information for lookup
        #moduleMap = 
        
        # Main loop: Go through every package we collected from our repos, find the matching source package, and create the de-duplicated pkg[] list
        # (with the source name as canonical name, and data tagging the module label, if any)
        for i in tmpPkgList:
            i.module_label=""
          #i.cve_list=[]

            # If the binary package is a child package of source w/ same version, then we will use that srpm name instead:
            if str(i.version + "-" + i.release) in str(i.sourcerpm):
                i.rName = i.source_name
            else:
                i.rName = i.name
          
            # If we've already done this source RPM, skip to the next.  We don't want duplicates:
            pkgFound = False
            for p in self.pkg:
                if i.rName == p.rName and i.version == p.version and i.release == p.release:
                    #print("DEBUG :: Found matching version : " + i.rName + "-" + i.version + "-" + i.release)
                    pkgFound = True
          
            if pkgFound == True:
                continue


            # Modularity case:  if package is modular, we really need to find its moduleName:Stream, and mark it as such
            if ".module" in i.release:
                i.module_label = self.getModuleLabel(i, repos)
            
            # If latest is true, we check if this package is the most recent one (determined by build time, easier than comparing version strings)
            # If a later one is found in the same modular stream, we simply skip adding it
            # Conversely, if we find an *older* build in self.pkg with the same name, we need to delete it
            #
            # We use a copy of self.pkg list ("[:]" syntax) so we don't modify the list in the middle of looping
            discardMe = False
            if latest == True:
                for pk in self.pkg[:]:
                    if pk.rName == i.rName and pk.module_label == i.module_label and pk.buildtime > i.buildtime:
                        print("DEBUG :: " +  i.rName + "-" + i.version + "-" + i.release + " :: " + i.module_label + " is being discarded, buildTime " + str(i.buildtime) + " is determined to be older than " + pk.rName + "-" + pk.version + "-" + pk.release)
                        discardMe = True
                        break
                    if pk.rName == i.rName and pk.module_label == i.module_label and i.buildtime > pk.buildtime:
                        print("DEBUG :: " + pk.rName + "-" + pk.version + "-" + pk.release + " is being deleted, newer version discovered")
                        self.pkg.remove(pk)
                        
            
            if discardMe == True:
                continue
            
            
            # Add our slightly-modified package to the main self.pkg list:
            self.pkg.append(i)


        return

          # Scan changelog for mentions of "CVE-" to detect fixes:
          #for change in i.changelogs:
          #  for word in change["text"].split(" "):
          #    if str(word).startswith("CVE-") or str(word).startswith("cve-"):
          #      i.cve_list.append(str(word).strip())

          # Append this package to the final list:
          
          #print("DEBUG :: pkg[latest].module_label  == " +  str(pkg[len(pkg) -1].module_label) + "####" + i.module_label)


            #dnf.cli.cli.run("-q --repofrompath ' + repoTmp.id + ',' + repoTmp.baseurl[0] + ' --repoid ' + repoTmp.id + ' module provides ' + i.name + '-' + i.version + '-' + i.release")



    #def makeModuleMapping(self, pkgList, repos):
        

  #for j in i.changelogs:
  #  print(str(j))

    # Given a set of repos and a package, find out which module this package belongs to:
    def getModuleLabel(self, package, repos):     
        reposFromPath = ""
        repoIds = ""
        for r in repos:
            reposFromPath += "  --repofrompath " + r.id + "," + r.baseurl[0]
            repoIds += r.id + ","
        
        cmd = 'dnf -q --setopt=cachedir=/tmp/temp_dnf_cache'  + "  " + reposFromPath + "  --repoid " + repoIds + ' module provides ' + package.name + '-' + package.version + '-' + package.release

        # We're looking for the "Module   :   <module>:<stream>:<X>:<Y>" line in the dnf output here.  We can yoink the module:stream info from it:
        #for line in subprocess.run([cmd], shell=True, text=True).stdout.split("\n"):
        for line in str(subprocess.check_output(cmd, shell=True, text=True)).split("\n"):
            if line.startswith("Module  "):
                return str(line.split(":")[1].strip() + ':' +  line.split(":")[2].strip())
            
        # If we somehow didn't find a "Module   :" line in DNF output, return empty
        return ""

  #pp.pprint(i.changelogs)

#print(str(dnfBase.repos["testRocky"]))
#print(str(dnfConf.dump()))



