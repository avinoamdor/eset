# eset

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}

mkdir C:\esettemp

netsh -c interface dump > C:\esettemp\NetworkSettings.txt
Import-Module BitsTransfer
Start-BitsTransfer -source "https://download.eset.com/com/eset/tools/installers/eset_apps_remover/latest/esetuninstaller.exe" -Destination C:\esettemp\esetuninstaller.exe
Set-Content -Path C:\esettemp\uninstall.bat -Value "C:\esettemp\esetuninstaller.exe /force & C:\esettemp\esetuninstaller.exe /force & C:\esettemp\esetuninstaller.exe /force & bcdedit /deletevalue {current} safeboot & sc delete ""ESET Removal"" & shutdown -r -f -t 0 " -Encoding ASCII

$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\esettemp\uninstall.lnk")
$Shortcut.TargetPath = "C:\esettemp\uninstall.bat"
$Shortcut.Save()

New-Service -Name "ESET Removal" -BinaryPathName 'cmd.exe /C C:\esettemp\uninstall.lnk'

New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal' -Name 'ESET Removal'
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\ESET Removal' -Name "(Default)" -Value "Service"

bcdedit /set '{default}' safeboot minimal
shutdown -r -f -t 0
