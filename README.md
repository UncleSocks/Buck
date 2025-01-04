# Buck: Automated Indicator of Compromise (IOC) Scanner

An open-source and easy-to-use PowerShell script to automate indicator of compromise (IOC) scanning on Windows machines. It checks for the following IOCs: File Paths, File Hashes, IP Addresses, and Domains. Users will need to specify a JSON file containing the IOCs (see files within the IOCs directory for reference) and run the script.

To run the script, specify the JSON file location with the `-IOCFilePath` option, for example:
```
.\buck.ps1 -IOCFilePath .\IOCs\BackdoorDiplomacy.json
```

![image](https://github.com/user-attachments/assets/a0d38368-8b2a-435b-8530-bb3afe4aec7a)


## PowerShell Modules Used for IOC Detection

The script's PowerShell (PS) modules and sub-modules are pre-built; no import is needed.

### File Paths

The script runs a **Test-Path** to check if a file exists within the specified path. This detection checks for the existence of complete file path IOCs (i.e., c:\programdata\microsoft\diagnosis\etllogs\vmnat.exe).

### File Hashes

The script captures the file hash with the **Get-FileHash** sub-module and supports MD5, SHA1, SHA256, SHA384, and SHA512 algorithms.

### IP Addresses

The **Get-NetTCPConnection** sub-module to identify remote addresses. It leverages a regular expression (regex) to remote private IP addresses (i.e., loopback and RFC 1918). 

Please note that this is a _point-in-time_ scan and can potentially miss certain connections depending on when the script was run. As a result, no connection state filter is applied to capture as many remote addresses as possible.

### Domains

Consolidated domain entries from _Winodws DNS Client Event ID 3008_, _DNS Client Cache_ (Get-DnsClientCache), and _reverse DNS lookup of Get-NetTCPConnection_ (Resolve-DnsName) are used by the script to detect potential external domain IOCs. 

This is also a _point-in-time_ detection, which can also potentially result in missed domain entries. Furthermore, if the _Winodws DNS Client_ event is disabled, fewer domain entries can be captured by the script.

## IOC JSON File

The script uses JSON files for its IOC feeds. You can refer to the files in the **IOC** directory for the format. The JSON file can also include additional information about the threat actor, such as its description, MITRE ID, etc. This will not affect the script's functionality.

For the file hash IOCs, you can specify a _directory_ and the _extensions_ to make the search efficient. If no _directory_ is specified, the script will attempt to capture all file hash recursively from the C: drive. Additionally, if no _extension_ is included, it will include all file extensions (i.e., *.*)

### Available JSON IOC Files

I have added JSON IOC files in this repository for others to use -- most are from the ESET research team (hats off to these guys).

## Output

The script divides the console output per IOC type and will highlight, in red, any IOC it finds. 

### File Paths

It will first check if the directory is present. If the directory (path) is present, it displays a yellow text. The script will then check if the files exist within the given path. If it matches an IOC, it highlights it. Otherwise, it will simply state no file IOC was found in the directory.

![image](https://github.com/user-attachments/assets/9394e391-39e7-4cd5-b0f4-ea2cfa34ce7e)


### IP Addresses

The script will display the captured remote addresses from the **Get-NetTCPConnection** sub-module. It uses the **Compare-Object** sub-module to check if an IP address matches an IOC, which will be highlighted at the end.

![image](https://github.com/user-attachments/assets/d33fcc7d-e2d3-4f09-8cfd-d9e82536c1bc)

### Domains

As previously stated, the script displays the consolidated domain entries from the three sources. The script will state, in green text, if no IOC matches.

![image](https://github.com/user-attachments/assets/a3ec4976-57dc-4134-8649-a0b64298b6fc)


### File Hashes

A progress bar will be shown, displaying the number of processed files and the current directory. To make the search more efficient, it is recommended to specify a directory and/or file extensions.

![image](https://github.com/user-attachments/assets/74f7dde2-ef82-432d-8164-aff58ef0cca1)

When a file hash IOC matches, it returns the hash and the full path location.

![image](https://github.com/user-attachments/assets/6fdf19ed-aa68-4100-8687-d5d15c40552f)

## Future Potential Developments
- Implement Windows Defender Firewall logs to capture more remote addresses.

