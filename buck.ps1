
param([String]$IOCFilePath)


Function Convert-IOCFromJson {
    
    $Group = Get-Content $IOCFilePath | ConvertFrom-Json
    Return $Group
}


Function Confirm-UsersDirectory {
    param([String]$Path)

    $NewPaths = @()
    $Users = Get-ChildItem -Path "c:\users\" -Name -Exclude "Public"

    ForEach ($User in $Users) {
        $NewPath = $Path.Replace("<user>", $user)
        $NewPaths += $NewPath
    }

    Return $NewPaths

}


Function Search-FilePathIOCs {
    param([String]$Path,
          [Array]$Files
         )

    if (Test-Path -Path $Path) {
        Write-Host "[Directory Found]: $Path" -ForegroundColor Yellow

        $ExistingFiles = $Files | Where-Object { Test-Path (Join-Path -Path $Path -ChildPath $_) }

        if ($ExistingFiles) {
            $ExistingFiles | ForEach-Object { Write-Host "`t[File IOC Found]: $_" -BackgroundColor Red}
        
        } else {
            Write-Host "`tNo matching file IOC found under this directory." -ForegroundColor Green
        }
    } else {
        Write-Host "[Directory Not Found]: $Path"
    }

    Return
}


Function Get-FilePathIOCs { 
    
    $Group = Convert-IOCFromJson

    Write-Host "=======================================================================[File IOCs]=======================================================================`n" -ForegroundColor Magenta
    Write-Output "Searching for potential file IOCs using Test-Path sub-module...`n"

    $FilePathIOCs = $Group.IOCs.FilePaths
    
    if ($FilePathIOCs) {

        ForEach ($FilePathIOC in $FilePathIOCs) {
            $Path = $FilePathIOC.Path
            $Files = $FilePathIOC.Files

            #Write-Output "`n"

            if ($Path.Contains("\<user>\")) {
            
                $NewPaths = Confirm-UsersDirectory -Path $Path

                ForEach ($NewPath in $NewPaths) {
                    Search-FilePathIOCs -Path $NewPath -Files $Files
                }
           
            } else {

                Search-FilePathIOCs -Path $Path -Files $Files
            }
        }

    } else {
        Write-Output "No file path IOC available. Skipping this search."
    }

}


Function Get-RemoteAddresses {

    $PrivateAddressRegex = '^((?:(?:^127\.)|(?:^192\.168\.)|(?:^10\.)|(?:^172\.1[6-9]\.)|(?:^172\.2[0-9]\.)|(?:^172\.3[0-1]\.)|(?:^::1$)|(?:^[fF][cCdD])/)|([a-zA-Z]))'
    
    $RemoteAddresses = Get-NetTCPConnection |
    Where-Object {
        $_.RemoteAddress -notmatch $PrivateAddressRegex -and $_.RemoteAddress -notin @('0.0.0.0', '::')
        } | 
        Select-Object -ExpandProperty RemoteAddress -Unique

    Return $RemoteAddresses
}


Function Get-AddressIOCs {

    #param([Hashtable]$Group)

    $Group = Convert-IOCFromJson
    
    Write-Host "`n=======================================================================[IP Address IOCs]=======================================================================`n" -ForegroundColor Magenta
    Write-Output "Searching for IP address IOCs..."

    $AddressIOCs = $Group.IOCs.Addresses

    if ($AddressIOCs) {
        
        Write-Host "Getting the list of remote addresses using the NetTCPConnection sub-module...`n"
        $RemoteAddresses = Get-RemoteAddresses
        
        Write-Host "Captured Remote Addresses"
        Write-Host "---------------------------------------"
        Write-Output $RemoteAddresses
        Write-Host "---------------------------------------`n"

        if ($RemoteAddresses) {
            Write-Output "Comparing remote IP addresses and the IP address IOCs..."
            $AddressIOCsOutput = Compare-Object -ReferenceObject $AddressIOCs -DifferenceObject $RemoteAddresses -IncludeEqual -ExcludeDifferent | Select-Object -ExpandProperty InputObject
        }

        if ($AddressIOCsOutput) {
            $AddressIOCsOutput | ForEach-Object { Write-Host "`t[Address IOC Found]: $_" -BackgroundColor Red }
        
        } else {
            Write-Host "`tNo matching IP address IOC found." -ForegroundColor Green
        }
    }    
}


Function Get-DomainIOCs {

    $Group = Convert-IOCFromJson

    Write-Host "`n=======================================================================[Domain IOCs]=======================================================================`n" -ForegroundColor Magenta
    Write-Output "Searching for domains IOCs..."

    $Hostname = Hostname
    $DomainIOCs = $Group.IOCs.Domains

    if ($DomainIOCs) {

        $RemoteAddresses = Get-RemoteAddresses

        Write-Output "`nCapturing DNS queries to external destinations from Windows DNS Client Event ID 3008..."
        $DNSClientEventEntries = Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |
            Where-Object {
                $_.Id -eq '3008' -and
                $_.Message -notmatch $Hostname -and
                $_.Message -notmatch "..localmachine"
            } |
            ForEach-Object {
                if ($_.Message -match "DNS query is completed for the name ([^,\s]+)") {
                    $matches[1]
                }
            } | Select-Object -Unique

        Write-Output "Gathering DNS client cache entries..."
        $DNSClientCacheEntries = Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique
    
        Write-Output "Performing reverse DNS lookup of remote addresses from NetTCPConnection sub-module..."
        $DNSResolution = $RemoteAddresses | 
            Where-Object {$_ -and $_ -ne ''} | 
            ForEach-Object {
                Resolve-DnsName $_ -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
            } | 
            Select-Object -ExpandProperty NameHost -Unique

        Write-Output "Consolidating gathered domain entries..."
        $CompleteDNS = ($DNSClientEventEntries + $DNSClientCacheEntries + $DNSResolution) | 
            ForEach-Object {
                if ($_ -match "((?:[a-zA-Z0-9-]+\.){0,2}(?!(\b(in-addr|ip6)\.arpa)$)[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)$") {
                    $matches[1]
                }
            } | Select-Object -Unique
    
        Write-Host "`nConsolidated Domain Entries"
        Write-Host "---------------------------------------"
        Write-Output $CompleteDNS
        Write-Host "---------------------------------------`n"

        Write-Output "Comparing consolidated domain entries and the domain IOCs..."
        $DomainIOCsOutput = Compare-Object -ReferenceObject $DomainIOCs -DifferenceObject $CompleteDNS -IncludeEqual -ExcludeDifferent | Select-Object -ExpandProperty InputObject

        if ($DomainIOCsOutput) {
            $DomainIOCsOutput | ForEach-Object { Write-Host "`t[Domain IOC Found]: $_" -BackgroundColor Red }
        
        } else {
            Write-Host "`tNo matching domain IOC found." -ForegroundColor Green
        }

    }

}


Function Get-HashIOCs {

    $Group = Convert-IOCFromJson

    Write-Host "`n=======================================================================[Hash IOCs]=======================================================================`n" -ForegroundColor Magenta
    Write-Output "Searching for file hash IOCs..."
    $FileHashIOCs = $Group.IOCs.FileHashes

    $FileCounter = 0
    
    if ($FileHashIOCs) {
        
        $Algorithm = $FileHashIOCs.Algorithm
        $Extensions = if ($FileHashIOCs.Extensions) {$FileHashIOCs.Extensions} else {"*.*"}
        $Directory = if ($FileHashIOCs.Directory) {$FileHashIOCs.Directory} else {"C:\"}
        $HashIOCs = $FileHashIOCs.Hashes

        Write-Output "`nCapturing all hashes from directory $Directory recusively..."
        Get-ChildItem -Path $Directory -Recurse -File -Force -Include $Extensions -ErrorAction SilentlyContinue | ForEach-Object {
           
            $FileHash = Get-FileHash -Path $_.FullName -Algorithm $Algorithm | Select-Object -ExpandProperty Hash
           
            Write-Progress -Activity "Searching for file hash IOCs..." -Status "Files processed: $FileCounter | Current Directory: $($_.Directory)"  -PercentComplete (($FileCounter %100) * 1)
            $FileCounter++

            if ($FileHash -in $HashIOCs) {
                Write-Host "`t[File Hash IOC Found]: $FileHash | $($_.FullName)" -BackgroundColor Red
            }

        }
    }

}

Convert-IOCFromJson -IOCFilePath $IOCFilePath
Get-FilePathIOCs
Get-AddressIOCs
Get-DomainIOCs
Get-HashIOCs

$BackdoorDiplomacy | ConvertTo-Json