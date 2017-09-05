<#
Author: Tom Daniels <trd6577@g.rit.edu>
File: Get-Artifacts.ps1
Purpose: Retreives users/ADinfo/services/processes/networkConnections/and more from
         one or more computers. The information is output to either the screen, a
         csv file, or emailed to someone as a csv file. The email must be sent from
         a Gmail account that has allowed insecure app access and does not have 2
         factor authentication enabled
#>

param([string]$CsvPath = (Get-Item -Path ".\" -Verbose).FullName,  # Default path is location of cmdlet
      [switch]$Csv = $false,   # By default, do not write results to a csv file
      [string]$computers,      # The list of computers to get artifacts from
      [switch]$email = $false) # By default, do not send the csv file as an email

function collectArtifacts ($CsvPath, $Csv, $email, $emailCredentials, $emailRecipient, $remoteCredentials, $computer){
    if((-not ($computer -eq $null)) -and (-not($computer -eq ""))){
        Enter-PSSession -ComputerName $computer -Credential $remoteCredentials
    }
    # Create the CSV Object. This contains all of the information about a single computer system
    $csvData = New-Object -TypeName psobject

    # Get the date and computer/OS information and add it to the CSV object
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $date = Get-Date
    $lastBoot = $date - $operatingSystem.LastBootUpTime  # (Current time)-(date computer turned on) = Length of up time
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name ComputerName -Value $computerSystem.Name
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name Date -Value $date.ToString()
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name TimeZone -Value (Get-TimeZone).Id
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name LastBoot -Value ($lastBoot.Days.ToString() + " day(s) " + $lastBoot.Hours + " hour(s) " + $lastBoot.Minutes + " minute(s) and " + $lastBoot.Seconds + " second(s) ago")
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name Version -Value ($operatingSystem.Caption + " (" + ([System.Environment]::OSVersion.Version) + ")")

    # Get hardware information and add it to the CSV object
    $processor = Get-CimInstance -ClassName CIM_Processor
    $disks = Get-CimInstance -ClassName Win32_LogicalDisk | Select-Object DeviceID,VolumeName,FileSystem,@{l='Size';e={("{0:N2}GB" -f ($_.Size/1GB))}} # Convert bytes to GB w/2 decimal places
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name CPU -Value $processor.Name
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name RAM -Value ("{0:N2}GB" -f ($computerSystem.TotalPhysicalMemory/1GB)) # Convert bytes to GB w/2 decimal places
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name Disks -Value ($disks | Out-String)

    # Make sure the computer is part of a domain before retriving any domain-specific information
    if($computerSystem.PartOfDomain -eq $true){
        try{
            $addc = Get-ADDomainController
            $adUsers = Get-ADUser -Filter * | Select-Object SamAccountName,Name,Enabled,SID
            Add-Member -InputObject $csvData -MemberType NoteProperty -Name DomainName -Value $addc.Name
            Add-Member -InputObject $csvData -MemberType NoteProperty -Name DomainControllerAddress -Value $addc.IPv4Address
            Add-Member -InputObject $csvData -MemberType NoteProperty -Name ADUsers -Value ($adUsers | Out-String)
        }catch{
            Write-Error "Computer is on a domain but Remote System Administration Tools for powershell are not installed"
        }
    }else{
        Write-Debug ($computerSystem.Name + "is not connected to a domain. Not collecting domain information")
    }

    # Get user/account information and add them to the CSV object 
    $users = Get-LocalUser | Select-Object Name,FullName,Enabled,LastLogon,SID
    $systemAccounts = Get-CimInstance -ClassName Win32_SystemAccount | Select-Object Name,Domain,InstallDate,SID
    $serviceAccounts = @()
    for($i = 0; $i -lt $services.Length; $i++){ # Go through all of the services and grab all of the names of the accounts
        if(-not $serviceAccounts.Contains($services[$i].StartName)){
            $serviceAccounts += $services[$i].StartName
        }
    }
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name LocalUsers -Value ($users | Out-String)
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name SystemAccounts -Value ($systemAccounts | Out-String)
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name ServiceUsers -Value ($serviceAccounts | Out-String)

    # Get the programs/services that start on boot as well as any scheduled tasks. Add the new information to the CSV file
    $programs = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name,Command,Location
    $scheduledTasks = Get-ScheduledTask | Select-Object TaskName,TaskPath
    $services = Get-CimInstance -ClassName Win32_Service | Where-Object {$_.StartMode -eq "Auto"}
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name ServicesOnBoot -Value ($services | Out-String)
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name ProgramsOnBoot -Value ($programs | Out-String)
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name ScheduledTasks -Value ($scheduledTasks | Out-String)

    # Get the arp and routing tables and network interface information. Add the new information to the CSV file
    $arpTable = Get-NetNeighbor | Where-Object { (-not ($_.LinkLayerAddress -eq $null)) -and ($_.ifIndex -eq 3) } | Select-Object IPAddress,LinkLayerAddress
    $routingTable = Get-NetRoute | Select-Object DestinationPrefix,Nexthop
    $networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { -not ($_.MACAddress -eq $null)} | Select-Object Description,IPAddress,MACAddress,DefaultIPGateway,DHCPServer,InterfaceIndex
    ForEach ($adapter in $networkAdapters){
        Add-Member -InputObject $adapter -MemberType NoteProperty -Name DNSServer -Value (Get-DnsClientServerAddress | Where-Object {-not ($_.ServerAddresses.Length -eq 0) -and $_.InterfaceIndex -eq $adapter.InterfaceIndex}).ServerAddresses
    }
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name ArpTable -Value ($arpTable | Out-String)
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name Interfaces -Value ($networkAdapters | Out-String)
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name RoutingTable -Value ($routingTable | Out-String)


    # Get the results from netstat and filter them down to a Powershell object
    # Create the list of connections 
    $netstats = New-Object 'System.Collections.Generic.List[System.Object]'
    ForEach ($line in $((NETSTAT.EXE -ano).split("`r`n"))){
        # Ignore blank lines or lines with headings
        if(-not ($line -eq "") -and -not ($line -like "*Active*") -and -not ($line -like "*Proto*")){
            $line = $line.Trim()        # Get rid of the whitespace in the beginning and on the end
            $line = $line -split "\s+"  # and split the line on the whitespaces inbetween
            $connection = New-Object -TypeName psobject
            Add-Member -InputObject $connection -MemberType NoteProperty -Name Protocol -Value $line[0]
            Add-Member -InputObject $connection -MemberType NoteProperty -Name LocalAddress -Value $line[1]
            Add-Member -InputObject $connection -MemberType NoteProperty -Name ForeignAddress -Value $line[2]
            if($connection.Protocol -eq "TCP"){
                Add-Member -InputObject $connection -MemberType NoteProperty -Name PID -Value $line[4]
            }else{
                Add-Member -InputObject $connection -MemberType NoteProperty -Name PID -Value $line[3]
            }
            Add-Member -InputObject $connection -MemberType NoteProperty -Name ProcessName -Value (Get-Process -Id $connection.PID).ProcessName
            $netstats.Add($connection)
        }
    }
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name Netstat -Value ($netstats | Out-String)

    # Get the client DNS cache and add it to the CSV file
    $dnsCache = Get-DnsClientCache | Where-Object {$_.Status -eq 0} | Select-Object Name,Data
    if($dnsCache -eq $null){
        Write-Debug "No DNS information found"
    }else{
        Add-Member -InputObject $csvData -MemberType NoteProperty -Name DNSCache -Value ($dnsCache | Out-String)
    }

    # Add any wireless profiles to the CSV file
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name WirelessProfiles -Value (netsh.exe wlan show profiles)

    # Add network shares, printers, and all installed programs to the CSV file
    $netshares = Get-CimInstance -ClassName Win32_share | Where-Object {(-not ($_.Path -eq "")) -and (-not ($_.Path -eq $null))} | Select-Object Path
    $programs = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {(-not ($_.DisplayName -eq $null)) -and (-not ($_.DisplayName -eq ""))} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name NetwokShares -Value ($netshares | Out-String)
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name PrintDevices -Value (Get-Printer | Select-Object Name | Out-String)
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name InstalledSoftware -Value ($programs | Out-String)

    # Get the list of processes and add them to the CSV file (also get the owner of the process)
    $processes = Get-CimInstance -ClassName Win32_Process | Select-Object Name,ProcessID,ParentProcessID,Path,@{l='User';e={(Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User}}
    Add-Member -InputObject $csvData -MemberType NoteProperty -Name Processes -Value ($processes | Out-String)

    # Attempt to get the drivers on the computer. Fails if the user does not have the correct privileges
    try{
        $drivers = Get-WindowsDriver -All -Online | Select-Object Name,BootCritical,Path,Version,Date,ProviderName
        Add-Member -InputObject $csvData -MemberType NoteProperty -Name Drivers -Value ($drivers | Out-String)
    }Catch{
        Write-Warning "The current user does not have the permissions needed to get the drivers"
    }

    # For each user on the system, add the list of files in their documents/downloads directories to the CSV file
    $users = Get-ChildItem -Path "C:\Users" | Select-Object Name
    ForEach ($user in $users){
        try{
            $downloads = Get-ChildItem -Path ("C:\Users\" + $user.Name + "\Downloads") | Select-Object Name
            $documents = Get-ChildItem -Path ("C:\Users\" + $user.Name + "\Documents") | Select-Object Name
            Add-Member -InputObject $csvData -MemberType NoteProperty -Name ($user.Name + "Downloads") -Value ($downloads | Out-String)
            Add-Member -InputObject $csvData -MemberType NoteProperty -Name ($user.Name + "Documents") -Value ($documents | Out-String)
        }catch{
            Write-Debug ("Unable to access" + $users + "'s Documents/Downloads directory")
        }
    }

    # If -csv was specified in the arguments, then don't print the output
    if($csv -or (-not ($CsvPath -eq (Get-Item -Path ".\" -Verbose).FullName)) -or $email){
        # Make sure the path ends with '\'
        if(-not ($CsvPath.Substring($CsvPath.Length-1) -eq '\')){
            $CsvPath = ($CsvPath + "\")
        }
        $csvData | Export-Csv -Path ($CsvPath + "ComputerInformation.csv")
    }
    if($email){
        try{
            Send-MailMessage -From $emailCredentials.GetNetworkCredential().UserName -To $emailRecipient -Subject "CSV Forensic Results" -Attachments ($CsvPath + "ComputerInformation.csv") -SmtpServer "smtp.gmail.com" -Port 587 -UseSsl $true -Credential $emailCredentials
        }catch{
            Write-Error "Unable to send email. Is 2 factor auth enabled? Did you correctly enter your username/password? Did you allow insecure apps in your google account settings?"
        }
    }
    if((-not ($email)) -and (-not ($Csv))){
        Write-Host ($csvData | Out-String)
    }
    if((-not ($computer -eq $null)) -and (-not($computer -eq ""))){
        Exit-PSSession
    }
}

# If we're sending email, get the username and password for the account
if($email){
    Write-Debug "Note that this cmdlet only works with gmail accounts"
    $emailCredentials = Get-Credential -Message "Enter your email credentials"
    $emailRecipient = Read-Host -Prompt "Enter the destination email address"
}

# If we're connecting to multiple computers, get the credentials for those computers
if(-not ($computers -eq "")){
    $remoteCredentials = Get-Credential -Message "Enter credentials used to connect to multiple computers with Enter-PSSession"
    ForEach ($computer in $computers){
        collectArtifacts -CsvPath $CsvPath -Csv $Csv -email $email -emailCredentials $emailCredentials -emailRecipient $emailRecipient -remoteCredentials $remoteCredentials -computer $computer
    }
}else{
    collectArtifacts -CsvPath $CsvPath -Csv $Csv -email $email -emailCredentials $emailCredentials -emailRecipient $emailRecipient -remoteCredentials $null -computer $null
}