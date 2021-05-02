# Parsing Sysmon logs
The following are some windows lolbins to download more tools

## Get-WinEvent

This will list out every DNS event in the EventLog and expand the detailed message:
```
> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=22} | ForEach-Object {$_.message} 
```
This next command will list out each domain queried on an individual line
```
> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=22} | ForEach-Object {$_.message -split "`r`n"} | Select-String QueryName | %{$_.line.split()[-1]}
```

## Get-SysmonLogs
The following leverages [0DaySimpson's Get-SysmonLogs](https://github.com/0daysimpson/Get-SysmonLogs) to generate the same list of domains as above
```
> Import-Module Get-SysmonLogs.ps1
> Get-SysmonLogs -DNS  -Count 5 | ForEach-Object { $_.QueryName }
```
