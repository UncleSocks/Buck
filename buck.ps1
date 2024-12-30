
param([Array]$Group)


$BackdoorDiplomacy = @{
    Name = "BackdoorDiplomacy"
    MITREID = "G0135"
    Source = @{
        Researcher = "BitDefender"
        URL = "https://www.bitdefender.com/files/News/CaseStudies/study/426/Bitdefender-PR-Whitepaper-BackdoorDiplomacy-creat6507-en-EN.pdf"
    }
    AddressIOCs = @(
        "185.80.201.87",
        "140.82.38.177",
        "199.247.19.24",
        "208.85.23.64",
        "70.34.248.149",
        "136.244.112.39",
        "43.251.105.139",
        "103.152.14.162",
        "152.32.181.55",
        "192.155.86.128"
        )
    DomainIOCs = @(
        "cloud.microsoftshop.org",
        "info.fazlollah.net",
        "info.payamradio.com",
        "mail.irir.org",
        "news.alberto2011.com",
        "picture.efanshion.com",
        "plastic.delldrivers.in",
        "proxy.oracleapps.org",
        "srv.fazlollah.net",
        "srv.payamradio.com",
        "uc.ejalase.org",
        "www.iranwatch.tech",
        "www.iredugov.wiki",
        "mci.ejalase.org",
        "cloud.crmdev.org",
        "soap.crmdev.org",
        "cloud.fastpaymentservice.com",
        "cloud.skypecloud.net",
        "portal.skypecloud.net",
        "api.vmwareapi.net",
        "fcanet.microsoftshop.org",
        "www.iransec.services"
        )
    FileHashIOCs = @(
        @{ Algorithm = "SHA256"
           Hashes = @(
           "06faa40b967de7168d16fec0519b77c5e319c6dc021578ed1eb8b337879018fe",
           "eff22d43a0e66e4df60ab9355fa41b73481faea4b3aa6905eac3888bc1a62ffa",
           "bbcd7dc60406a9fa439d183a10ad253426bae59424a0a1b91051d83d26bb0964",
           "9d167adc290de378071c31cfd8f2059523e978c6f14a7079157d564f976c544b",
           "e2589f9942e9ec6b9c385fec897ffc3a71fcd8d7e440e3302efc78760c40f926",
           "c9d5dc956841e000bfd8762e2f0b48b66c79b79500e894b4efa7fb9ba17e4e9e",
           "ec6fcff9ff738b6336b37aaa22e8afa7d66d9f71411430942aed05e98b3f4cd5",
           "a43a4cd9c2561a4213011de36ac24ee1bf587663ed2f2ae1b1eac94aa2d48824",
           "7ed44a0e548ba9a3adc1eb4fbf49e773bd9c932f95efc13a092af5bed30d3595",
           "f293ab13a04ff32ebfbe925b42eca80a57604d231ae36e22834bea0dbdcf26e2",
           "d1948085fc662f7aed592af2eab9f367b3040bba873fec24b939395515f54a83",
           "99f31526fa18dc8c5f09b212909a9df889ea0bc3da979e4892666d626cc4aaf0",
           "07e8b2c8cf5fcdbd29cf864cda3c5c2df3999c35a5da28a18af5dedd5f1db60a",
           "6373ee72c811cf77a46e0cffd3c8f83d02173946b714d946e4c4c91cef41685f",
           "d583189d66b0aa09405a0ed2440c72f741caedb250525be2b17a1f9616fab9e6",
           "99e62952f66b487349493657d6aec8456afef0fb72aad084c388677912210bf9",
           "b87580211c1748c7f223d6bfc96cd8eca5a19022758d964b40612639dfbe147d",
           "363a2006c8faff9e533093d1562028c4b53d5be52028bb91259debc472399c9b",
           "23d5260c5cebf96814dda5edb06391fdbd02e0a79fb7efd9795c5415cacf2eb7",
           "280a511cded40de2368c2a01b6d96a31d51cb56df12c326836b68e8276d0c5f1",
           "290614b101a8a7161b5430eebbab653433c64634b39ea9b1688689b4f090689a",
           "e43d66b7a4fa09a0714c573fbe4996770d9d85e31912480e73344124017098f9",
           "0f3304c1e0f87d4250acd87eafe796969b507a9bd57bc0f6683f9c086dc8b18b",
           "a8dca2afb4956b1d9461f413254918669e2bfe7f1e54c7dbd44495574dab73fb",
           "54459379811848234156b7d10be87d5e0492921d218c251cd700527b9d114fd8",
           "86f49d43df677457d3d4c9466345e2f85d558cd469953c163e4a50daaa1efe1f",
           "0a3a57af259f2b064bf9d05d8d1d19269315cb92417fdda9fa138ef7bbcbe3b9",
           "7bd53a3dbebbd10ad610b8c2c7d7f0ba4ca80e119ede071d428bcea618af1039",
           "b2ddbd9059c64760394d227cdcf3722708eccf598b9efb20e969d7bd4623c963",
           "37b1a2eddcb54f8cc454cafaa82be6244cebfe5a04ee8b3681107f37c2948277",
           "b03fe49036c3830f149135068ff54f5c6c6622008a6fcb7edbf6b352e9a0acc0",
           "afd7a46d27101aaa92dee06b766a0ac54399aae5a7842b3aeb0ed468e182da15",
           "477526a54b84a987268dd4ad408ea24c448f7c3bb31f13b778a9f8c616b9021d",
           "e6e419601852d1d5f6e762a7b32b86197d554fb7e31611c006c73d39ea58b4c1",
           "631d335917c1c600a980391223ad47870278c6690d14bb8e9d3e73147aa18ed1",
           "588c3602af97e2076596b0f18169e18298a45a658b5b7d2aeb997c2f6e856b02",
           "15588f6d6bf9406387908474a85aad7dea7907c52fd96de4331a6dae760341fd",
           "e05648822e7fe93c8d87aedccdd1f80e6d579ef7d4ebc3504bf20d501931c46e",
           "51c4531b801552accb12e1e16fb0ecddb6400eeeb3fd8022dda4c9dfe428c62d",
           "76245b0d43f98a667ad8be6eb150133791de3a9075970a8fb9b7f305ace5168f",
           "1db80d7e464c60cb22badfa0897ea27ecb0650a12f86f8ebf58bbeb66a3af3ad",
           "0bac277831d35a66305fe09300ffb818cb489e3ead7389c12496cd688e74a747",
           "5f3e74001938c10d13bd3ffc578acdb7c9cb0ffa364a07ffa7e524d43333be0f",
           "57c9a4103dd3cc0ebab335debeb9cdb0935882dc9470c18e71e3bf9622852a59",
           "ba757a4d3560e18c198110ac2f3d610a9f4ffb378f29fd29cd91a66e2529a67c",
           "d2f10ece652babdf8f67385ab9bc881c34f6be996bfb6b65c936a8e2f2a682ab",
           "4e110a75e9141f9e1dd1a2b2e5af7e3d4205303ed8374d937c14345c426b5e47",
           "3a14984ac9671502be98d420b6475331ffa30ab1d1e4d00155d6a168620d562d",
           "b802d06e9026105c8015ecd4e59dd75c5cefd90ad8edb2b1f1b4a25834a12f3b",
           "177d89f01ab1b4bd8c78092f4a5d1927897d79596580ec2c23ffd4d9ad1dd351",
           "82c2d7df34a1299c55793b5ff1d09f7cd63352f5a14a5f12cf6bf3df99f28310",
           "d3eadfdc74766da80dba13ed5a74344e525cc0bc6ebf2364c4b41417d66c954e",
           "fcd08daed23591d77cd8031eb292ef30f1024d610d5716f4af75cddb1c729c04",
           "52a0130c9ef00fe5118dd93b8f383023867a3d694d7bed10abb213db934e82c3",
           "6f2617bc30f2e7b9d7ff979d08b3ce1939f1cfb3c154ccc722940b3cc9737b31",
           "558cb35b275eb1dbfe7378323d5e7259f1be114bca22e6806daf85c47131db20",
           "89fa21c871572c227274d7836c88e815b748db63f6a662553a43cc1dd086667c",
           "d2012430690fbd0f27cacc761a26cca544e29e926a23c7efe3a678080bc32b6e",
           "e0f096731f9095d6efdc65a36d14fce554fa6ba544eab835dbe1f424fb8e6d8c",
           "05acd1bb524d73d9bc4cae24f25b445a0d9194d702263cd16305499560ae6d3a",
           "ee7b0b19240e1083ca8c6183b578abc70f19b7c99c91af9842338524fa6b879e",
           "ab0bd2d1cd9f27532e8f0da8d0ebf6bbbfc1e5e96a78f436a52e62d6645d62a2",
           "bc5f0aa3235d6617910f04e7c2a30554fcead33560f8821cf40b3c0873d38a7b",
           "3c09739afdcefc7700e3bd48db576cc4156934c9556d6436e7aca7474ef638a2"
           )
        }
    )
    FilePathIOCs = @(
        @{ Path = "c:\program files (x86)\windows sidebar\gadgets\" 
           Files = @(
           "credwiz.exe"
           )
        },
        @{ Path = "c:\program files\windows nt\" 
           Files = @(
           "1.exe",
           "credwiz.exe",
           "duser.dll",
           "st.exe",
           "sw.exe"
           )
        },
        @{ Path = "c:\programdata\canon\oippesp\bb\"
           Files = @(
           "duser.dll",
           "uhsrvc.exe",
           "winlogout.exe"
           )
        },
        @{ Path = "c:\programdata\comms\"
           Files = @(
           "ag.exe",
           "cc.exe",
           "igfxpers.exe",
           "info.dat",
           "msd.exe",
           "rar.exe",
           "sll.bat",
           "ss.exe",
           "w3w.exe",
           "winlogout.exe",
           "wmiap.exe"
           )
        },
        @{ Path = "c:\programdata\filebeat\"
           Files = @(
           "sim.bat"
           )
        },
        @{ Path = "c:\programdata\intel\gcc\"
           Files = @(
           "sll.bat"
           )
        },
        @{ Path = "c:\programdata\microsoft\devicesync\"
           Files = @(
           "devicesync.exe",
           "devicesync.exe.exe",
           "log.bat",
           "log1.bat",
           "sdk.dll"
           )
        },
        @{ Path = "c:\programdata\microsoft\diagnosis\etllogs\bin\"
           Files = @(
           "reauto.bat",
           "s.bat",
           "shfolder.dll",
           "variety.mof",
           "vmnat.dll",
           "vmnat.exe"
           )
        },
        @{ Path = "c:\programdata\microsoft\diagnosis\etllogs\"
           Files = @(
           "shfolder.dll",
           "variety.mof",
           "vmnat.dll",
           "vmnat.exe"
           )
        },
        @{ Path = "c:\programdata\microsoft\drm\server\"
           Files = @(
           "drm.exe"
           )
        },
        @{ Path = "c:\programdata\microsoft\drm\server\s-1-5-18\"
           Files = @(
           "cert-machine.dll",
           "cert-machine.exe"
           )
        },
        @{ Path = "c:\programdata\microsoft\group policy\trace\"
           Files = @(
           "configer.dat",
           "pc2msupp.dll",
           "winseucerwmiload.dat",
           "winseucerwmiload.exe",
           "winseucerwmiload.ini"
           )
        },
        @{ Path = "c:\programdata\microsoft\netframework\breadcrumbstore\ngen\"
           Files = @(
           "nv.mpc",
           "nv.mpc",
           "nvsmartmax.dll",
           "nvsmartmax.dll",
           "run.bat"
           )
        },
        @{ Path = "c:\programdata\microsoft\network\connections\"
           Files = @(
           "lsh.bat",
           "netserver.exe"
           )
        },
        @{ Path = "c:\programdata\microsoft\uev\"
           Files = @(
           "wmiap.exe"
           )
        },
        @{ Path = "c:\programdata\microsoft\vault\"
           Files = @(
           "1.rar",
           "111.bat",
           "ass.bat",
           "e.exe",
           "f.bat",
           "igfxpers.exe",
           "nimscan.exe",
           "pt.exe",
           "rar.exe",
           "sf.exe",
           "sps.exe",
           "ss.bat"
           )
        },
        @{ Path = "c:\programdata\microsoft\wdf\"
           Files = @(
           "logoutui.exe"
           )
        },
        @{ Path = "c:\programdata\microsoft\windows\devicemetadatastore\en-us\"
           Files = @(
           "nvsmartmax.dll"
           )
        },
        @{ Path = "c:\programdata\microsoft\windows\"
           Files = @(
           "pt.exe"
           )
        },
        @{ Path = "c:\programdata\microsoft\windows\sqm\upload\"
           Files = @(
           "logoutui.exe"
           )
        },
        @{ Path = "c:\programdata\ssh\"
           Files = @(
           "sll.bat"
           )
        },
        @{ Path = "c:\programdata\usoprivate\updatestore\"
           Files = @(
           "in.bat"
           )
        },
        @{ Path = "c:\programdata\usoshared\logs\user\"
           Files = @(
           "updatesrv.exe"
           )
        },
        @{ Path = "c:\programdata\winseucitysys001\windefenderlogin\"
           Files = @(
           "winsecunicity.exe"
           )
        },
        @{ Path = "c:\programdata\wmiappsecuserv\wmiappsilveration\"
           Files = @(
           "configer.dat",
           "pc2msupp.dll",
           "winsecunicity.dat",
           "winsecunicity.exe",
           "winsecunicity.ini"
           )
        },
        @{ Path = "c:\users\<user>\appdata\local\temp\3\"
           Files = @(
           "acrobat17.exe"
           )
        },
        @{ Path = "c:\users\<user>\appdata\local\temp\4\"
           Files = @(
           "ld.dll",
           "rar.exe",
           "rar570.exe"
           )
        },
        @{ Path = "c:\users\<user>\appdata\local\temp\"
           Files = @(
           "acrobat17.exe",
           "ld.dll"
           )
        },
        @{ Path = "c:\users\<user>\appdata\local\virtualstore\"
           Files = @(
           "agent64.exe",
           "igfxpers.exe",
           "vmnat.exe"
           )
        },
        @{ Path = "c:\users\<user>\appdata\local\vmnat\"
           Files = @(
           "vmnat.exe"
           )
        },
        @{ Path = "c:\users\<user>\appdata\local\vmware\"
           Files = @(
           "t.exe",
           "vmnat.exe"
           )
        },
        @{ Path = "c:\users\<user>\appdata\roaming\microsoft\vault\"
           Files = @(
           "windowsazure.exe"
           )
        },
        @{ Path = "c:\users\<user>\saved games\"
           Files = @(
           "nethood.exe"
           )
        },
        @{ Path = "c:\users\<user>\appdata\roaming\microsoft\windows\network shortcuts\"
           Files = @(
           "nethood.exe"
           )
        },
        @{ Path = "c:\users\public\"
           Files = @(
           "1.bin",
           "11.bat",
           "all1.txt",
           "ass.bat",
           "bin.rar",
           "csvde_x64.exe",
           "e.exe",
           "ifsvc.exe",
           "igfxpers.exe",
           "info.bat",
           "javanet.exe",
           "logoutui.exe",
           "nimscan.exe",
           "procdump64.exe",
           "pt.exe",
           "ptg.exe",
           "rar.exe",
           "s.exe",
           "set_empty.exe",
           "sfthttpsrv.exe",
           "ss.txt",
           "sss.txt",
           "tscan.exe",
           "tscan32.exe",
           "winsecunicity.exe"
           )
        },
        @{ Path = "c:\users\public\nethood\"
           Files = @(
           "igfxpers.exe"
           )
        },
        @{ Path = "c:\windows\"
           Files = @(
           "alg.exe"
           )
        },
        @{ Path = "c:\windows\apppatch\apppatch64\"
           Files = @(
           "shfolder.dll"
           )
        },
        @{ Path = "c:\windows\apppatch\custom\custom64\"
           Files = @(
           "const.mof",
           "epprotected.exe",
           "instsrv.exe",
           "lsh.bat",
           "rdpsrv.exe",
           "sll.bat",
           "srvany.exe",
           "variety.mof"
           )
        },
        @{ Path = "c:\windows\assembly\temp\ahoax2nypi\"
           Files = @(
           "rundll64.exe",
           "variety.mof"
           )
        },
        @{ Path = "c:\windows\com\1025\"
           Files = @(
           "agent64.exe"
           )
        },
        @{ Path = "c:\windows\com\"
           Files = @(
           "2.bat",
           "3.bat",
           "agent.exe",
           "igfxpers.exe",
           "info.bat",
           "info.txt",
           "mstsc.bat",
           "nbtscan.exe",
           "rar.exe",
           "taskmgr.exe",
           "tscan.exe"
           )
        },
        @{ Path = "c:\windows\coms\"
           Files = @(
           "sll.bat"
           )
        },
        @{ Path = "c:\windows\diagtrack\settings\"
           Files = @(
           "reauto.bat"
           )
        },
        @{ Path = "c:\windows\inf\wmiaprpl\"
           Files = @(
           "if.dat",
           "in.dat",
           "info.dat",
           "lsh.bat",
           "skypesrv.exe",
           "sll.bat"
           )
        },
        @{ Path = "c:\windows\miracastview\pris\"
           Files = @(
           "const.mof",
           "lsh.bat",
           "reauto.bat",
           "tabtip64.exe",
           "updatesrv.exe",
           "variety.mof"
           )
        },
        @{ Path = "c:\windows\registration\crmlog\"
           Files = @(
           "2.bat",
           "logoutui.exe"
           )
        },
        @{ Path = "c:\windows\sysvol\<user>\scripts\"
           Files = @(
           "lsh.bat",
           "sim.bat"
           )
        },
        @{ Path = "c:\windows\syswow64\"
           Files = @(
           "appmgmt.dll",
           "bits.dll"
           )
        },
        @{ Path = "c:\windows\temp\crashpad\"
           Files = @(
           "svchost.bat"
           )
        },
        @{ Path = "c:\windows\temp\"
           Files = @(
           "exe.bat",
           "exe1.bat",
           "ntds.bat",
           "pd.bat",
           "set.txt",
           "sll.bat",
           "sys.bat",
           "test.dat",
           "trecert.bat"
           )
        },
        @{ Path = "c:\windows\web\wallpaper\windows\"
           Files = @(
           "wordpadfilter.exe"
           )
        }
    )
}

$CeranaKeeper = @{
    Name = "CeranaKeeper"
    MITREID = "N/A"
    Source = @{
        Researcher = "ESAT"
        URL = "https://github.com/eset/malware-ioc/tree/master/ceranakeeper"
    }
    AddressIOCs = @(
        "104.21.81.233",
        "172.67.165.197",
        "103.245.165.237",
        "103.27.202.185"
    )
    DomainIOCs = @(
        "www.toptipvideo.com",
        "dljmp2p.com",
        "inly5sf.com",
        "www.dl6yfsl.com",
        "www.uvfr4ep.com"
    )
    FileHashIOCs = @(
        @{ Algorithm = "SHA1"
           Extensions = @("*.dll", "*.exe", "*.orp")
           Hashes = @(
            "8e3b3c600ab812537a84409adfc5169518862fd3",
            "0b9efaef974c625d9f8e3935b33c16ffbc59d798",
            "7a5f5cf1aa0e1909f1cda4cf99cbcbef026c68d7",
            "322eb20377dbdb4acb3067a4f2aaa47631ca5ed5",
            "6db173c599a2fb0de200cabfbf0d4c07f090f82f",
            "37db71172ab64c108fedca85e5be51a499b2ba12",
            "50eee1b2601aebae0ce7b360d7c970b7c1ee0866",
            "42a3d252faa7d7457c7f708ec6f44f3c1afd843e",
            "f2329c6066497068ff3e1cec0be20461f23d80cc"
           )
        }
    )
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
            Write-Host "`tNo file IOC found under this directory." -ForegroundColor Green
        }
    } else {
        Write-Host "[Directory Not Found]: $Path"
    }

    Return
}


Function Get-FilePathIOCs { 
    
    Write-Output "=======================================================================[File IOCs]=======================================================================`n"
    Write-Output "Searching for potential file IOCs...`n"

    $FilePathIOCs = $Group.FilePathIOCs
    
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
        Write-Output "No file path IOC specified... skipping this search."
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
    
    Write-Output "`n=======================================================================[Comand & Control (C2) IOCs]=======================================================================`n"
    Write-Output "Searching for C2 IP address IOCs..."

    $AddressIOCs = $Group.AddressIOCs

    if ($AddressIOCs) {
        
        Write-Host "Getting the list of remote addresses using the NetTCPConnection sub-module...`n"
        $RemoteAddresses = Get-RemoteAddresses
        
        Write-Host "---------------------------------------"
        Write-Output $RemoteAddresses
        Write-Host "---------------------------------------`n"

        if ($RemoteAddresses) {
            Write-Output "Comparing remote IP addresses and the C2 IP address IOCs..."
            $AddressIOCsOutput = Compare-Object -ReferenceObject $AddressIOCs -DifferenceObject $RemoteAddresses -IncludeEqual -ExcludeDifferent
        }

    }    
}


Function Get-DomainIOCs {

    $Hostname = Hostname
    $DomainIOCs = $Group.DomainIOCs

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

        Write-Output "Capturing DNS client cache..."
        $DNSClientCacheEntries = Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique
    
        Write-Output "Performing reverse DNS lookup of remote addresses..."
        $DNSResolution = $RemoteAddresses | 
            Where-Object {$_ -and $_ -ne ''} | 
            ForEach-Object {
                Resolve-DnsName $_ -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
            } | 
            Select-Object -ExpandProperty NameHost -Unique

        Write-Output "`nConsolidated domains list:"
        $CompleteDNS = ($DNSClientEventEntries + $DNSClientCacheEntries + $DNSResolution) | 
            ForEach-Object {
                if ($_ -match "((?:[a-zA-Z0-9-]+\.){0,2}(?!in-addr\.arpa)[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)$") {
                    $matches[1]
                }
            } | Select-Object -Unique
    
    
        Write-Output $CompleteDNS

        Compare-Object -ReferenceObject $DomainIOCs -DifferenceObject $CompleteDNS -IncludeEqual -ExcludeDifferent

    }

}


Function Get-HashIOCs {

    Write-Output "Checking for hash IOCs"
    $FileHashIOCs = $Group.FileHashIOCs

    if ($FileHashIOCs) {
        
        $Algorithm = $FileHashIOCs.Algorithm
        $Extensions = if ($FileHashIOCs.Extensions) {$FileHashIOCs.Extensions} else {"*.*"}
        $Directory = if ($FileHashIOCs.Directory) {$FileHashIOCs.Directory} else {"c:\"}
        $HashIOCs = $FileHashIOCs.Hashes

        Write-Output "`nCapturing all hashes from directory $Directory recusively..."
        Get-ChildItem -Path $Directory -Recurse -File -Force -Include $Extensions -ErrorAction SilentlyContinue | ForEach-Object {
            
            $FileHash = Get-FileHash -Path $_.FullName -Algorithm $Algorithm | Select-Object -ExpandProperty Hash

            if ($FileHash -in $HashIOCs) {
                Write-Host "Matched a hash: $($_.FullName)" -ForegroundColor Green
            }

        }
        
        Write-Output "Detecting hash IOCs..."
        Compare-Object -ReferenceObject $HashIOCs -DifferenceObject $Hashes -IncludeEqual -ExcludeDifferent
    }

}


Get-FilePathIOCs -Group $Group
Get-AddressIOCs -Group $Group
Get-DomainIOCs -Group $Group
Get-HashIOCs -Group $Group