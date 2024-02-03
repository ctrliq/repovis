#!/usr/bin/python3

import datetime, time
import os, shutil, sys

# Given package data (package list from PackageRead class), produce HTML, CSV, or other output:

class Output:
    pkgs = []
    title = ""
    description = ""
    
    # pkgs => PackageRead.pkg[] list of dictionaries, contains package data
    # outputType => CSV, HTML, etc.
    # title / description => goes in HTML page
    # startDate => epoch time where packages are first tracked from
    # outFile => optional file to write data to
    def __init__(self, pkgs, outFile):
        self.pkgs = pkgs
        self.outFile = outFile
        return

    def writeHTML(self, title, description, buildTime):
        startDate = str(datetime.datetime.utcfromtimestamp(buildTime).strftime('%Y-%m-%d'))
        tableData = ""
       
        for p in self.pkgs:
            tableData += "<tr>\n<td> <b>" + p.source_name + "</b> </td>\n<td> " + p.source_version + "-" + p.source_release + " </td>\n<td> " + str(p.module_label) + " </td>\n<td> " + str(datetime.datetime.utcfromtimestamp(p.buildtime).strftime('%Y-%m-%d')) + "</td>\n"
            
            # Get CVEs summary (marked by date):
            cveText = "<ul>"
            for date in p.cve_dict.keys():
                for cve in p.cve_dict[date]:
                    cveText += "<li>" + cve + "</li>\n"
                    
                #cveText += "</ul>\n"
            if cveText == "<ul>":
                cveText = "-"
            else:
                cveText += "</ul>"

            tableData += "<td> " + cveText + " </td>\n"

            # Loop through changelog, produce 4-line summary and (expandable) full-changelog:
            changeText = ""
            changeSummary = ""
            for c in range(0, len(p.filter_changelogs)):
                changeText += str(p.filter_changelogs[c]["timestamp"]) + "  :  \n" + str(p.filter_changelogs[c]["text"]) + "\n"
            
            changeText = changeText.strip()
            # Changelog longer than 5 lines ==> grab first 5 lines as a summary
            if len(changeText.split("\n")) >= 4:
                for line in range(0,3):
                    changeSummary += changeText.split("\n")[line] + "\n"
               
            changeSummary = changeSummary.replace("\n", "<br />\n")
            
            # Write out changelog data cell:
            if changeSummary == "":
                tableData += "<td> " + changeText.replace("\n","<br />\n") + "</td>\n"
            else:
                tableData +="<td> " + changeSummary + "<br /><a><u>[Show All]</u></a><pre>" + changeText + "</pre></td>\n"
                
            tableData += "</tr>\n\n"
            
            
        # write HTML:
        # Current timestamp
        TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        TIMESTAMP += " (" + time.tzname[1] + ")"

        # HTML template file should be in this same lib/ folder
        templateHtml = os.path.join(os.path.dirname(__file__), 'html', 'html_template.html')
        
        f = open(templateHtml, 'r')
        htmlData = f.read()
        f.close()
        
        htmlData = htmlData.replace("@@TITLE@@", title)
        htmlData = htmlData.replace("@@DESCRIPTION@@", description)
        htmlData = htmlData.replace("@@START_DATE@@", str(startDate))
        htmlData = htmlData.replace("@@TIMESTAMP@@", str(TIMESTAMP))
        htmlData = htmlData.replace("@@TABLE_DATA@@", str(tableData))
        
        if self.outFile != "":
            f = open(self.outFile, 'w')
            f.write(htmlData)
            f.close()
            outDir = os.path.dirname(os.path.abspath(self.outFile))
            
            # Copy html helper components (datatables/jquery) to HTML out dir
            shutil.copyfile(os.path.join(os.path.dirname(__file__), 'html', 'jquery-3.6.0.min.js'), os.path.join(outDir, 'jquery-3.6.0.min.js'))
            shutil.copyfile(os.path.join(os.path.dirname(__file__), 'html', 'datatables.min.js'), os.path.join(outDir, 'datatables.min.js'))
            shutil.copyfile(os.path.join(os.path.dirname(__file__), 'html', 'datatables.min.css'), os.path.join(outDir, 'datatables.min.css'))
            print('JS, CSS, and HTML output written to: ' + str(outDir), file=sys.stderr)
            
        else:
            print(htmlData)

    
    # write csv output
    def writeCSV(self):
        # csv header:
        csvData = "Package,Version,Module,Build Date,CVE Fixes\n"
        
        for p in self.pkgs:
            
            # Get CVE List text:
            cveText = " "
            for date in p.cve_dict.keys():
                for cve in p.cve_dict[date]:
                    cveText += cve + " " 
            
            csvData += p.source_name + "," + p.source_version + "-" + p.source_release + "," + p.module_label + "," + str(datetime.datetime.utcfromtimestamp(p.buildtime).strftime('%Y-%m-%d')) + "," + cveText + "\n"

        if self.outFile != "":
            f = open(self.outFile, 'w')
            f.write(csvData)
            f.close()
            print('CSV file written to: ' + str(self.outFile), file=sys.stderr)
        else:
            print(csvData)
