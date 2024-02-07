#!/usr/bin/python3

# Specialist script for parsing the CVEs listed in the LTS publish log (exported to CSV)
# Takes CSV file as input, produces companion fixed-cve yaml file for use with repovis

# Very specific to CIQ internal docs - accepts CIQ LTS publish log table (exported from Confluence -> CSV) as the input file


import csv, re, yaml, sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('csvFile', type=str, nargs='+', help="CSV File export to read (need one)")  
args = parser.parse_args()

header={}
header["version"] = "v1alpha1"
cveDict = {}
filePath = args.csvFile[0]

# cve's are "CVE-####-#####" :
cveRegex = re.compile('CVE-\d+-\d+',  re.IGNORECASE)

with open(args.csvFile[0], newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if "CVE-" not in row[5]:
            continue

        # Define LTS version key:  cveDict["8.6"] cveDict["9.2"] etc.
        # Also add standard "version" (yaml meta-version) and "packages" dictionaries (cveDict["8.6"]["version"] , cveDict["8.6"]["packages"]
        if row[2] not in cveDict:
            cveDict[row[2]] = {}
            cveDict[row[2]]["packages"] = {}

        # Define package dict if not exists:  cveDict["8.6"]["packages"]["firefox"]
        if row[1] not in cveDict[row[2]]["packages"]:
            #print("making new dictionary for package:   " + row[1], file=sys.stderr)
            cveDict[row[2]]["packages"][row[1]] = {}
            cveDict[row[2]]["packages"][row[1]]["cve_fixes"] = {}

        # Date dict item is a list of CVEs : cveDict["8.6"]["firefox"]["CVE_Fixes"]["2023-12-23"]
        if row[0] not in cveDict[row[2]]["packages"][row[1]]["cve_fixes"]:
            cveDict[row[2]]["packages"][row[1]]["cve_fixes"][row[0]] = []

        # Get list of CVE codes from 6th column of this row:
        cveList = list(dict.fromkeys(cveRegex.findall(row[5])))

        # Add list of cves to the list:
        cveDict[row[2]]["packages"][row[1]]["cve_fixes"][row[0]].extend(cveList)

for lts in cveDict:
    f = open("lts-" + lts + "_CVE_Fixes.yaml", 'w')
    f.write(yaml.dump(header) + yaml.dump(cveDict[lts]))
    f.close()
    print('YAML CVE file written to:  ' + "lts-" + lts + "_CVE_Fixes.yaml", file=sys.stderr)
