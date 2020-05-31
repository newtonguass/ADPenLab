new-item "C:\HackCollege\start Up" -itemtype directory

Install-WindowsFeature -name Web-Server -IncludeManagementTools
Install-WindowsFeature Web-Asp-Net45
echo "%windir%\system32\inetsrv\appcmd.exe set AppPool DefaultAppPool -processModel.identityType:LocalSystem" | Out-File -FilePath C:\\HackCollege\\runIISAsLocalSystem.bat -Encoding ASCII
$out=C:\\HackCollege\\runIISAsLocalSystem.bat
add-content "c:\\log.txt" -value "$(get-date -format 'u'): $out"


[System.Net.ServicePointManager]::SecurityProtocol = "tls12" #default powershell use tl1.0, will cause ssl error with github
invoke-webrequest -uri https://raw.githubusercontent.com/newtonguass/ADPenLab/master/ADEnvInit/joinDomain.ps1 -outFile "C:\HackCollege\joinDomain.ps1"
invoke-webrequest -uri https://raw.githubusercontent.com/newtonguass/ADPenLab/master/ADEnvInit/webServer/fileupload.aspx -outFile "C:\inetpub\wwwroot\upload.aspx"

try{
    $name = (Get-NetAdapter | select Name).Name
    Disable-NetAdapterBinding –InterfaceAlias $name –ComponentID "ms_tcpip6"
    add-content "c:\\log.txt" -value "$(get-date -format 'u'): disable tcpipv6"
}catch{
    add-content "c:\\log.txt" -value "$(get-date -format 'u'): $_.exception.message"
}
try{
    $index = (Get-NetAdapter | select IfIndex).IfIndex
    Set-NetConnectionProfile -InterfaceIndex $index -NetworkCategory Private
    Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses ("10.0.0.4")
    add-content "c:\\log.txt" -value "$(get-date -format 'u'): set network type as private and point dns to dc"
}catch{
    add-content "c:\\log.txt" -value "$(get-date -format 'u'): $_.exception.message"
}
try{
    New-ItemProperty -Name LocalAccountTokenFilterPolicy  -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -PropertyType DWord -Value 1
    Enable-PsRemoting -Force
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
    Restart-Service WinRM
    add-content "c:\\log.txt" -value "$(get-date -format 'u'): enable remote powershell execution"
}catch{
    add-content "c:\\log.txt" -value "$(get-date -format 'u'): $_.exception.message"
}
