
param([String]$IocFilePath)


Function Convert-IocFromJson {
    
    $Group = Get-Content $IocFilePath | ConvertFrom-Json
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


Function Search-FilePathIoc {
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


Function Get-FilePathIoc { 
    
    $Group = Convert-IocFromJson

    Write-Host "=======================================================================[File IOCs]=======================================================================`n" -ForegroundColor Magenta
    Write-Host "Searching for potential file IOCs using Test-Path sub-module...`n"

    $FilePathIocs = $Group.IOCs.FilePaths
    
    if ($FilePathIOCs) {

        ForEach ($FilePathIoc in $FilePathIocs) {
            $Path = $FilePathIoc.Path
            $Files = $FilePathIoc.Files

            if ($Path.Contains("\<user>\")) {
            
                $NewPaths = Confirm-UsersDirectory -Path $Path

                ForEach ($NewPath in $NewPaths) {
                    Search-FilePathIoc -Path $NewPath -Files $Files
                }
           
            } else {

                Search-FilePathIoc -Path $Path -Files $Files
            }
        }

    } else {
        Write-Output "No file path IOC available. Skipping this search."
    }

}


Function Get-RemoteAddress {

    $PrivateAddressRegex = '^((?:(?:^127\.)|(?:^192\.168\.)|(?:^10\.)|(?:^172\.1[6-9]\.)|(?:^172\.2[0-9]\.)|(?:^172\.3[0-1]\.)|(?:^::1$)|(?:^[fF][cCdD])/)|([a-zA-Z]))'
    
    $RemoteAddresses = Get-NetTCPConnection |
    Where-Object {
        $_.RemoteAddress -notmatch $PrivateAddressRegex -and $_.RemoteAddress -notin @('0.0.0.0', '::')
        } | 
        Select-Object -ExpandProperty RemoteAddress -Unique

    Return $RemoteAddresses
}


Function Get-AddressIoc {

    $Group = Convert-IocFromJson
    
    Write-Host "`n=======================================================================[IP Address IOCs]=======================================================================`n" -ForegroundColor Magenta
    Write-Output "Searching for IP address IOCs..."

    $AddressIocs = $Group.IOCs.Addresses

    if ($AddressIocs) {
        
        Write-Host "Getting the list of remote addresses using the NetTCPConnection sub-module...`n"
        $RemoteAddresses = Get-RemoteAddress
        
        Write-Host "Captured Remote Addresses"
        Write-Host "---------------------------------------"
        Write-Output $RemoteAddresses
        Write-Host "---------------------------------------`n"

        if ($RemoteAddresses) {
            Write-Output "Comparing remote IP addresses and the IP address IOCs..."
            $AddressIocOutput = Compare-Object -ReferenceObject $AddressIOCs -DifferenceObject $RemoteAddresses -IncludeEqual -ExcludeDifferent | Select-Object -ExpandProperty InputObject
        }

        if ($AddressIocOutput) {
            $AddressIocOutput | ForEach-Object { Write-Host "`t[Address IOC Found]: $_" -BackgroundColor Red }
        
        } else {
            Write-Host "`tNo matching IP address IOC found." -ForegroundColor Green
        }
    }    
}


Function Get-DnsClientEventEntries {

    $Hostname = Hostname

    Write-Host "`nCapturing DNS queries to external destinations from Windows DNS Client Event ID 3008..."
    $DnsClientEventEntries = Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" | Where-Object {
            $_.Id -eq '3008' -and
            $_.Message -notmatch $Hostname -and
            $_.Message -notmatch "..localmachine"
        } | ForEach-Object {
            if ($_.Message -match "DNS query is completed for the name ([^,\s]+)") {
                $matches[1]
            }
        } | Select-Object -Unique

    Return $DnsClientEventEntries

}


Function Get-DnsClientCacheEntries {

    Write-Host "Gathering DNS client cache entries..."
    $DnsClientCacheEntries = Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique

    Return $DnsClientCacheEntries

}


Function Get-DnsResolution {

    Write-Host "Performing reverse DNS lookup of remote addresses from Get-NetTCPConnection sub-module..."
    $RemoteAddresses = Get-RemoteAddress
    $DnsResolution = $RemoteAddresses | Where-Object {
        $_ -and
        $_ -ne ''
    } | ForEach-Object {
        Resolve-DnsName $_ -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
    } | Select-Object -ExpandProperty NameHost -Unique

    Return $DnsResolution

}


Function Get-DomainIoc {

    $Group = Convert-IocFromJson

    Write-Host "`n=======================================================================[Domain IOCs]=======================================================================`n" -ForegroundColor Magenta
    Write-Output "Searching for domains IOCs..."

    $DomainIocs = $Group.IOCs.Domains

    if ($DomainIocs) {

        $DnsClientEventEntries = Get-DnsClientEventEntries
        $DnsClientCacheEntries = Get-DnsClientCacheentries
        $DnsResolution = Get-DnsResolution

        Write-Output "Consolidating gathered domain entries..."
        $CombinedDnsEntries = ($DnsClientEventEntries + $DnsClientCacheEntries + $DnsResolution) | 
            ForEach-Object {
                if ($_ -match "((?:[a-zA-Z0-9-]+\.){0,2}(?!(\b(in-addr|ip6)\.arpa)$)[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)$") {
                    $matches[1]
                }
            } | Select-Object -Unique
    
        Write-Host "`nConsolidated Domain Entries"
        Write-Host "---------------------------------------"
        Write-Output $CombinedDnsEntries
        Write-Host "---------------------------------------`n"

        Write-Output "Comparing consolidated domain entries and the domain IOCs..."
        $DomainIocOutput = Compare-Object -ReferenceObject $DomainIOCs -DifferenceObject $CombinedDnsEntries -IncludeEqual -ExcludeDifferent | Select-Object -ExpandProperty InputObject

        if ($DomainIocOutput) {
            $DomainIocOutput | ForEach-Object { Write-Host "`t[Domain IOC Found]: $_" -BackgroundColor Red }
        
        } else {
            Write-Host "`tNo matching domain IOC found." -ForegroundColor Green
        }

    }

}


Function Get-HashIoc {

    $Group = Convert-IocFromJson

    Write-Host "`n=======================================================================[Hash IOCs]=======================================================================`n" -ForegroundColor Magenta
    Write-Output "Searching for file hash IOCs..."
    $FileHashIocs = $Group.IOCs.FileHashes

    $FileCounter = 0
    
    if ($FileHashIocs) {
        
        $Algorithm = $FileHashIocs.Algorithm
        $Extensions = if ($FileHashIocs.Extensions) {$FileHashIocs.Extensions} else {"*.*"}
        $Directory = if ($FileHashIocs.Directory) {$FileHashIocs.Directory} else {"C:\"}
        $HashIocs = $FileHashIocs.Hashes

        Write-Output "`nCapturing all hashes from directory $Directory recusively..."
        Get-ChildItem -Path $Directory -Recurse -File -Force -Include $Extensions -ErrorAction SilentlyContinue | ForEach-Object {
           
            $FileHash = Get-FileHash -Path $_.FullName -Algorithm $Algorithm | Select-Object -ExpandProperty Hash
           
            Write-Progress -Activity "Searching for file hash IOCs..." -Status "Files processed: $FileCounter | Current Directory: $($_.Directory)"  -PercentComplete (($FileCounter %100) * 1)
            $FileCounter++

            if ($FileHash -in $HashIocs) {
                Write-Host "`t[File Hash IOC Found]: $FileHash | $($_.FullName)" -BackgroundColor Red
            }

        }
    }

}

Convert-IocFromJson -IocFilePath $IocFilePath
Get-FilePathIoc
Get-AddressIoc
Get-DomainIoc
Get-HashIoc