#!/usr/bin/python3

import dnf
import dnf.module.module_base
import hawkey, datetime, re
from collections import OrderedDict
from operator import itemgetter
import yaml

import os,shutil,subprocess,sys

def _profile_comparison_key(profile):
    return profile.getName()

# Configure DNF for a set of repositories, and load all package information into memory (returned as an object)
# We'll compare these objects (multiple sets of repos) in another class to determine changes, CVEs fixed, changelogs, etc.
#
# Need a set of repos given as a simple list of strings: ["https://reposite.com/repo/repo1", "http://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/"]
# We also feed a "latest" boolean.  If latest=true, only the most recent version from the repos are considered
#   (we have to determine this programmatically after finding module stream info, or else we end up discarding all but the latest module stream(!) )
class PackageRead:

    pkg = []
    dnfBase = set()
    buildTime = 0
    cveExtra = {}
    def __init__(self, repoList, repoDir, latest, bTime, cveFile):
        if os.path.exists('/tmp/temp_dnf_cache'):
            shutil.rmtree('/tmp/temp_dnf_cache')
        
        self.buildTime = bTime

        self.dnfBase = dnf.Base()

        # If repoDir has been set, we use that instead of system-default /etc/yum.repos.d/
        if repoDir != "":
            self.dnfBase.conf.reposdir = repoDir

        self.dnfBase.conf.gpgcheck=False
        self.dnfBase.conf.cachedir="/tmp/temp_dnf_cache"

        try:
            self.dnfBase.read_all_repos()
        except:
            print('Could not read repos', file=sys.stderr)
            sys.exit(1)

        # Enable only the repos specified on the command line ("repoList[]")
        for repo in self.dnfBase.repos:
            if repo not in repoList:
                self.dnfBase.repos[repo].disable()
            else:
                self.dnfBase.repos[repo].enable()
                self.dnfBase.repos[repo].load_metadata_other = True
                self.dnfBase.repos[repo].module_hotfixes = True
        
        self.dnfBase.fill_sack(load_system_repo=False)
        
        # Gather list of all packages in the repo to a temporary list:
        tmpPkgList = self.dnfBase.sack.query().available().filter()
        
        # If we have an extra YAML CVE-fixes file given on the command line, load that into a dict:
        if cveFile != "":
            with open(cveFile) as f:
                self.cveExtra = yaml.load(f, Loader=yaml.FullLoader)
        else:
            self.cveExtra = {}

        # Main loop: Go through every package we collected from our repos, find the matching source package, and create the de-duplicated pkg[] list
        # (with the source name as canonical name, and data tagging the module label, if any)
        for i in tmpPkgList:
            i.module_label="-"
            
            # Skip any package which falls outside our buildTime criteria:
            if i.buildtime < self.buildTime:
                continue
            
            # We are only interested in the srpm (avoids duplicates), so we get the version + release of that src given the artifact name:
            # (sometimes the child binary RPM has a different version, but we are only interested in the src rpm)
            i.source_version, i.source_release = self.getVersionFromSrpm(i.sourcerpm, i.source_name)
            
            # If we've already done this same version src rpm, skip to the next.  We don't want duplicates:
            pkgFound = False
            for p in self.pkg:
                if i.source_name == p.source_name and i.source_version == p.source_version and i.source_release == p.source_release:
                    pkgFound = True
          
            if pkgFound == True:
                continue


            # Modularity case:  if package is modular, we really need to find its moduleName:Stream, and mark it as such
            if ".module" in i.source_release:
                i.module_label = self.getModuleLabel(i)
            
            # If latest is true, we check if this package is the most recent one (determined by build time, easier than comparing version strings)
            # If a later one is found in the same modular stream, we simply skip adding it
            # Conversely, if we find an *older* build in self.pkg with the same name, we need to delete it
            #
            # We use a copy of self.pkg list ("[:]" syntax) so we don't modify the list in the middle of looping
            discardMe = False
            if latest == True:
                for pk in self.pkg[:]:
                    if pk.source_name == i.source_name and pk.module_label == i.module_label and pk.buildtime > i.buildtime:
                        discardMe = True
                        break
                    if pk.source_name == i.source_name and pk.module_label == i.module_label and i.buildtime > pk.buildtime:
                        self.pkg.remove(pk)
                        
            if discardMe == True:
                continue
            
            # Get filtered changelog entries (only changes since the 
            i.filter_changelogs = self.getFilteredChangeLog(i.changelogs)
            
            i.cve_dict = self.getCveFromChangeLog(i.filter_changelogs, i.source_name)
            
            # Add our slightly-modified package to the main self.pkg list:
            self.pkg.append(i)
        return


    # Filter changelog for only relevant entries (entries created after by timestamp)
    def getFilteredChangeLog(self, changelog): 
        filteredChanges = []
        
        # If changelog has none or 1 entry, simply return empty or that single entry
        # (first entry is always added, no matter what time)
        if len(changelog) < 1:
            return filteredChanges
        
        filteredChanges.append(changelog[0])
        if len(changelog) == 1:
            return filteredChanges
        
        # Only collect changes inside the desired date range
        # (the first change is always collected)
        for c in range(1, len(changelog)):
            if int(datetime.datetime.fromordinal(changelog[c]["timestamp"].toordinal()).timestamp()) > self.buildTime:
                filteredChanges.append(changelog[c])
        
        return filteredChanges    
    
    
    # Return a dictionary-list of date:cve's found in a package's changelog
    def getCveFromChangeLog(self, changelog, package):
        cveDict = {}
        cveRawList = []
        # Compile regex isolating  "CVE-####-#####" text
        cveRegex = re.compile('CVE-\d+-\d+',  re.IGNORECASE)
        for c in range(0, len(changelog)):
            tmpChange = changelog[c]["text"].upper()
            
            # Find all CVEs in the change text, de-duplicated in a list:
            cveList = list(dict.fromkeys(cveRegex.findall(tmpChange)))

            # If we already previously found a cve in another changelog entry, we don't want to duplicate:
            for i in cveList:
                if i in cveRawList:
                    cveList.remove(i)
            # Add list of CVEs to our dictionary of dates:
            if len(cveList) > 0:
                cveDict[str(changelog[c]["timestamp"])] = cveList
                cveRawList.extend(cveList)
        
        # Check the supplemental CVE-fixes yaml file and add those CVEs as well:
        if package in self.cveExtra and "CVE_Fixes" in self.cveExtra[package]:
            for date in self.cveExtra[package]["CVE_Fixes"]:

                # We don't consider CVEs in the YAML dated before our starting "buildTime":
                if int(datetime.datetime.strptime(str(date), "%Y-%m-%d").timestamp()) < self.buildTime:
                    continue
                cveList = self.cveExtra[package]["CVE_Fixes"][date]

                for i in cveList:
                    # Ensure each CVE item in the yaml is a CVE (or rlsa/rhsa) item, and we haven't already seen it:
                    if not i.startswith("CVE-") and not i.startswith("RLSA-") and not i.startswith("RHSA-"):
                        cveList.remove(i)
                        continue
                    if i in cveRawList:
                        cveList.remove(i)
                        continue

                if date in cveDict:
                    cveDict[date].extend(cveList)
                else:
                    cveDict[date] = cveList

                cveRawList.extend(cveList)

        return cveDict


    # Given a package object, find out which module this package belongs to:
    # Logic for this is lifted from _what_provides() in DNF's own module_base.py
    def getModuleLabel(self, package):     
        modulePackages = self.dnfBase._moduleContainer.getModulePackages()
        baseQuery = self.dnfBase.sack.query().filterm(empty=True).apply()
        getBestInitQuery = self.dnfBase.sack.query(flags=hawkey.IGNORE_MODULAR_EXCLUDES)
        

        subj = dnf.subject.Subject(str(package.name + '-' + package.version + '-' + package.release))
        baseQuery = baseQuery.union(subj.get_best_query(
            self.dnfBase.sack, with_nevra=True, with_provides=False, with_filenames=False,
            query=getBestInitQuery))

        baseQuery.apply()

        for modulePackage in modulePackages:
            artifacts = modulePackage.getArtifacts()
            if not artifacts:
                continue
            query = baseQuery.filter(nevra_strict=artifacts)
            if query:
                for pkg in query:
                    string_output = ""
                    profiles = []
                    for profile in sorted(modulePackage.getProfiles(), key=_profile_comparison_key):
                        if pkg.name in profile.getContent():
                            profiles.append(profile.getName())
                    lines = OrderedDict()
                    #print("DEBUG ::  package " +  package.source_name + '-' + package.source_version + '-' + package.source_release + "    found to be part of module  "  + str(modulePackage.getFullIdentifier().split(":")[0] + ":" + modulePackage.getFullIdentifier().split(":")[1]))
                    return str(modulePackage.getFullIdentifier().split(":")[0] + ":" + modulePackage.getFullIdentifier().split(":")[1])

        # catch-all just in case
        return ""
    
    # Get version + release given srpm artifact name
    def getVersionFromSrpm(self, srpm, srcName):
        srpm = srpm.replace(srcName + "-", "")
        srpm = srpm.replace(".src.rpm", "")
        srcVersion = srpm.split("-")[0]
        srcRelease = srpm.split("-")[1]
        return srcVersion, srcRelease

