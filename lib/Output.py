#!/usr/bin/python3

import datetime
import time, os

# Given package build + changelog data, produce HTML, CSV, or other output:

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
     
     
    def writeHTML(self, title, description, startDate):
        tableData = ""
       
        for p in self.pkgs:
            tableData += "<tr>\n<td> <b>" + p.source_name + "</b> </td>\n<td> " + p.source_version + "-" + p.source_release + " </td>\n<td> " + str(datetime.datetime.utcfromtimestamp(p.buildtime).strftime('%Y-%m-%d')) + "</td>\n"
            
            # Get CVEs summary (marked by date):
            cveText = "<ul>"
            for date in p.cve_dict.keys():
                #cveText += "<li>" + str(date) + "</li>\n<ul>"
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
                print("DEBUG :: " + p.source_name + " -- Adding to changeSummary...")
                for line in range(0,3):
                    changeSummary += changeText.split("\n")[line] + "\n"
               
            changeSummary = changeSummary.replace("\n", "<br />\n")
            
            # Write out changelog data cell:
            if changeSummary == "":
                tableData += "<td> " + changeText.replace("\n","<br />\n") + "</td>\n"
            else:
                #print("DEBUG :: changeSummary for  "  + p.source_name + "  is : \n" + changeSummary)
                tableData +="<td> " + changeSummary + "<br /><a><u>[Show All]</u></a><pre>" + changeText + "</pre></td>\n"
                
            tableData += "</tr>\n\n"
            
            
            # write HTML:
            # Current timestamp
            TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
            TIMESTAMP += " (" + time.tzname[1] + ")"

            # HTML template file should be in this same lib/ folder
            templateHtml = os.path.join(os.path.dirname(__file__), 'html_template.html')
            
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
            else:
                print(htmlData)

            
            

