<#configuration to be done after domain service is up#>
$taskName = "adinit"
$script=@"
function addReverseDnsZone{
    try {
        Add-DnsServerPrimaryZone -NetworkId "10.0.0.0/24" -ReplicationScope "Forest"
        Add-Content "C:\\log.txt" -value "`$(get-date -format 'u'): Add DNS reverse zone successfully"
    } catch {
        add-content "c:\\log.txt" -value "`$(get-date -format 'u'): `$_.exception.message"
        start-sleep -s 10
        addReverseDnsZone
    }
}

function addOu{
    try{
        New-ADOrganizationalUnit -name "student" -path "Dc=hackcollege,DC=tw"
        foreach(`$i in (0..10)){
        `$name = "student" + `$i
        New-ADUser -Name `$name -SamAccountName `$name -UserPrincipalName (`$name+"`@hackcollege.tw") -Path "OU=student,DC=hackcollege,DC=tw" -AccountPassword (convertto-securestring ("Hackcollege`@2020"+`$i) -AsPlainText -Force) -Enabled `$true
        }
    }catch {
            add-content "c:\\log.txt" -value "`$(get-date -format 'u'): `$_.exception.message"
            start-sleep -s 10
            addou
        }
}
Add-Content "C:\\log.txt" -value "`$(get-date -format 'u'): Check services status Active Directory Domain Services, DFS Replication, DNS server, KDC"
While(((Get-service | where-object{`$_.Name -EQ "NTDS" } ).Status -ne "Running") -Or ((Get-service | where-object{`$_.Name -EQ "DNS" } ).Status -ne "Running") -Or ((Get-service | where-object{`$_.Name -EQ "DFSR" } ).Status -ne "Running") -Or ((Get-service | where-object{`$_.Name -EQ "kdc" } ).Status -ne "Running")  -Or ((Get-service | where-object{`$_.Name -EQ "ADWS" } ).Status -ne "Running")){Start-Sleep -s 10};
Add-Content "C:\\log.txt" -value "`$(get-date -format 'u'): Check the existing of forward zone"

Add-Content "C:\\log.txt" -value "`$(get-date -format 'u'): Add FilePermission GPO"
Expand-Archive C:\\HackCollege\\FilePermission.zip -DestinationPath C:\\HackCollege
addOu
addReverseDnsZone
import-gpo -BackupId D23D46C8-D2AB-4A5C-91B6-F26F2D0997F7 -TargetName FilePermission -Path C:\\HackCollege\\ -CreateIfNeeded
new-gplink -Name "FilePermission" -Target "dc=hackcollege,dc=tw"
Unregister-ScheduledTask -TaskName $taskName -Confirm:`$false
"@

Add-Content "C:\\startscript.ps1" -value $script
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-ExecutionPolicy Unrestricted -File C:\\startscript.ps1'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId System -LogonType ServiceAccount -RunLevel Highest
$definition = New-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Description "run adinit to add reverse dns zone and add OU and User"
Register-ScheduledTask -TaskName $taskName -InputObject $definition
Add-Content "C:\\log.txt" -value "$(get-date -format 'u'): Write starup task to conduct post ADDS installation configuration"

<#enable ping#>
netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow


<#disable ipv6#>
try{
    $name = (Get-NetAdapter | select Name).Name
    Disable-NetAdapterBinding –InterfaceAlias $name –ComponentID ms_tcpip6
    Add-Content "C:\\log.txt" -value "$(get-date -format 'u'): Disable IPv6"
}catch{

}
<#add securityService#>
new-item "C:\HackCollege\start Up" -itemtype directory
[System.Net.ServicePointManager]::SecurityProtocol = "tls12" #default powershell use tl1.0, will cause ssl error with github
invoke-webrequest -uri https://github.com/newtonguass/ADPenLab/raw/master/ADEnvInit/serviceSetUp/securityService.exe -outFile "C:\HackCollege\start Up\securityService.exe"
invoke-webrequest -uri https://github.com/newtonguass/ADPenLab/raw/master/ADEnvInit/serviceSetUp/agreement.exe -outFile "C:\HackCollege\start Up\agreement.exe"
invoke-webrequest -uri https://github.com/newtonguass/ADPenLab/raw/master/ADEnvInit/serviceSetUp/helper.exe -outFile "C:\HackCollege\start Up\helper.exe"
invoke-webrequest -uri https://github.com/newtonguass/ADPenLab/raw/master/ADEnvInit/gpo/FilePermission.zip -outFile "C:\HackCollege\FilePermission.zip"
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe "C:\HackCollege\start Up\securityService.exe"

<#start to install ADDS Service#>
Add-Content "C:\\log.txt" -value "$(get-date -format 'u'): Begin to install ADDS including RAST tools"
$domain = "hackcollege.tw"
$safePasswd = "Hackcollege@2020"
Install-windowsfeature AD-domain-services -includeManagementTools
Import-Module ADDSDeployment
Install-ADDSForest -Force -DomainName $domain -SafeModeAdministratorPassword (convertto-securestring($safePasswd) -AsPlainText -Force)
Add-Content "C:\\log.txt" -value "$(get-date -format 'u'): ADDS installation success, reboot the server"
Restart-Computer -Force
