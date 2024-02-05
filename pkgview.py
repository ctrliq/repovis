#!/usr/bin/python3

from lib.PackageRead import *
from lib.Output import *
import time,datetime,sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--days', type=int, default=0, help='How many days back should the repository history be searched through')
parser.add_argument('-s', '--startdate', type=str, default="", help='What is the earliest date we should start searching repository history?  (Conflicts with --days)')
parser.add_argument('-f', '--file', type=str, default='', help='File to write report to (default is stdout). HTML output will have .css and .js files copied to same directory.')
parser.add_argument('-o', '--output', type=str, default='html', choices=['html', 'csv', 'yaml-cve'], help='Type of output to produce.  HTML web page, Comma separated value text, or a summary of CVEs in YAML form.')
parser.add_argument('-r', '--repodir', type=str, default="", help="Alternate DNF repository config directory, where *.repo files are located.  Default is /etc/yum.repos.d/")
parser.add_argument('-c', '--cveyaml', type=str, default="", help="Custom yaml file to add as input.  Contains additional dates + CVEs resolved.  See docs for specific YAML format.") 
parser.add_argument('-t', '--title', type=str, default="Repository Recent History Summary", help="Title at top of document for HTML and YAML output.  Defaults to something bland.")
parser.add_argument('--description', type=str, default="", help="Description header (below title) at top of document for HTML and YAML output.  Can also contain custom HTML.")
parser.add_argument('repos', type=str, nargs='+', help="DNF Repositories (one or more, space-separated) to consider. Must be the proper dnf name as expressed in \"dnf repolist\"")  

args = parser.parse_args()


# Calculate the "origin point": any packages built before this time are not checked for changes
if int(args.days) > 0:
    buildTime = int(time.time()) - int(args.days * 86400)

if args.startdate != "":
    buildTime = int(datetime.datetime.strptime(args.startdate, "%Y-%m-%d").timestamp())

if args.startdate == "" and int(args.days) <= 0:
    print("Error, *must* specify --days  or --startdate YYYY-MM-DD  on the command line!")
    sys.exit(1)


packages = PackageRead(args.repos,args.repodir, True, buildTime, args.cveyaml)

out = Output(packages.pkg, args.file)

if args.output == "html":
    out.writeHTML(args.title, args.description, buildTime)

if args.output == "csv":
    out.writeCSV()

if args.output == "yaml-cve":
    out.writeCveYAML(args.title, args.description)

sys.exit(0)

