
param([Array]$Group)


$BackdoorDiplomacy = @{
    Name = "BackdoorDiplomacy"
    ID = "G0135"
    FilePathIOCs = @(
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




Function Search-FilePathIOCs { 
    
    $Name = $Group.Name
    Write-Output "Looking for file path IOCs of group: $Name"

    foreach ($FilePathIOC in $Group.FilePathIOCs) {
        $Path = $FilePathIOC.Path
        $Files = $FilePathIOC.Files

        Write-Output "`n"

        if (Test-Path -Path $Path) {
            Write-Output "Directory $Path exists. Checking for IOC files..."

            $ExistingFiles = $Files | Where-Object { Test-Path (Join-Path -Path $Path -ChildPath $_) }
            if ($ExistingFiles) {
                Write-Output "Potential file IOCs found under $Path"
                $ExistingFiles | ForEach-Object { Write-Output "$_ found!" }
           
            } else {
                Write-Output "No files present under the $Path"
            }
        } else {
            Write-Output "Directory $Path not found."
        }
    }

}

Search-FilePathIOCs -Group $Group