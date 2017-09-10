<#
Author: Tom Daniels
File: Convert-MftCsvToString
Purpose: Outputs the results of the CSV file generated from the Mft2Csv program
#>
Param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

$csv = Import-Csv -Path $FilePath -Delimiter "|"

# Print out the timestamp of the file, the file type, and the file path
ForEach ($file in $csv){
    $file | Select-Object @{l="Timestamp";e={$_.Date.ToString() + " " + $_.Time.ToString()}},
    @{l="FileType";e={$_.SourceType}},@{l="Path";e={$_.Desc}},MACB | Format-Table *
}