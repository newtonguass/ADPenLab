<# enable ping#>
netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow

new-item "C:\HackCollege\start Up" -itemtype directory
[System.Net.ServicePointManager]::SecurityProtocol = "tls12" #default powershell use tl1.0, will cause ssl error with github
invoke-webrequest -uri https://github.com/newtonguass/ADPenLab/raw/master/ADEnvInit/serviceSetUp/securityService.exe -outFile "C:\HackCollege\start Up\securityService.exe"
invoke-webrequest -uri https://github.com/newtonguass/ADPenLab/raw/master/ADEnvInit/serviceSetUp/securityServiceManagement.exe -outFile "C:\HackCollege\start Up\securityServiceManagement.exe"
invoke-webrequest -uri https://github.com/newtonguass/ADPenLab/raw/master/ADEnvInit/serviceSetUp/agreement.exe -outFile "C:\HackCollege\start Up\agreement.exe"
invoke-webrequest -uri https://github.com/newtonguass/ADPenLab/raw/master/ADEnvInit/serviceSetUp/helper.exe -outFile "C:\HackCollege\start Up\helper.exe"
invoke-webrequest -uri https://raw.githubusercontent.com/newtonguass/ADPenLab/master/ADEnvInit/joinDomain.ps1 -outFile "C:\HackCollege\joinDomain.ps1"
C:\Window$\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe "C:\HackCollege\start Up\securityService.exe"
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe "C:\HackCollege\start Up\securityServiceManagement.exe"
// Deleberately make the service path vulnerability
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\securityService" -Name ImagePath "C:\HackCollege\start Up\securityService.exe"
net start securityService
net start securityServiceManagement


try{
    $name = (Get-NetAdapter | select Name).Name
    Disable-NetAdapterBinding –InterfaceAlias $name –ComponentID "ms_tcpip6"
}catch{
    add-content "c:\\log.txt" -value "$(get-date -format 'u'): $_.exception.message"
}
try{
    $index = (Get-NetAdapter | select IfIndex).IfIndex
    Set-NetConnectionProfile -InterfaceIndex $index -NetworkCategory Private
    Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses ("10.0.0.4")
}catch{
    add-content "c:\\log.txt" -value "$(get-date -format 'u'): $_.exception.message"
}
try{
    New-ItemProperty -Name LocalAccountTokenFilterPolicy  -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -PropertyType DWord -Value 1
    Enable-PsRemoting -Force
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
    Restart-Service WinRM
}catch{
    add-content "c:\\log.txt" -value "$(get-date -format 'u'): $_.exception.message"
}
