<#
Author: Tom Daniels
File: Convert-MftCsvToString
Purpose: Outputs the results of the CSV file generated from the Mft2Csv program
         or dumps the $DATA section of a file
#>
Param(
    [Parameter(Mandatory=$true)]  # The directory the CSV is stored
    [string]$Path,

    [string]$GetData,             # The name of the file you want the $DATA section of

    [string]$Csv                  # The name of the CSV file to parse
)

# Check to make sure only $csv or $getdata is set, but not both
if($GetData -and $Csv){
    Write-Error "Only `$GetData or `$CSV should be set, but not both"
    return
}

# Make sure that the  directory ends with a '\'
if((-not ($Path.Substring($Path.Length-1) -eq "\")) -and (-not ($Path -eq "."))){
    $Path = $Path + "\"
}
if($Path -eq "."){
    $Path = ""
}

# If they specified a file, get the $DATA section of the file
if($GetData){
    # Get all files that match "*$GetData". Replaces "[" and "]" with "`[" and "`]" respectively
    # This is so Get-Content correctly parses them
    try{
        $Files = "$(((Get-ChildItem $Path -Include "*$GetData" -Recurse).FullName).Replace("[","``[").Replace("]","``]").Replace("$GetData ", "$GetData    "))".Split("    ")
    }catch{
        Write-Error "Could not find the specified file in the directory"
        return
    }

    # Print the name of each file followed by the $DATA section
    ForEach ($File in $Files){
        Write-Host -f Gray $File
        Get-Content $File
    }
}else{ # Otherwise, print out the results of the Mft2Csv tool
    $CsvFile = Import-Csv -Path ($Path + $Csv) -Delimiter "|"

    # Print out the timestamp of the file, the file type, and the file path
    ForEach ($File in $CsvFile){
        $File | Select-Object @{l="Timestamp";e={$_.Date.ToString() + " " + $_.Time.ToString()}},
        @{l="FileType";e={$_.SourceType}},@{l="Path";e={$_.Desc}},MACB | Format-Table *
    }
}