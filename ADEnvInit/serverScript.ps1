$domain = hackcollege.com

Install-windowsfeature AD-domain-services -includeManagementTools
Import-Module ADDSDeployment
Install-ADDSForest
 -CreateDnsDelegation:$false `
 -DatabasePath "C:\Windows\NTDS" `
 -DomainMode "Win2016" `
 -DomainName $domain`
 -DomainNetbiosName "THEGEEKSTUFF" ` -ForestMode "Win2016" ` -InstallDns:$true `
 -LogPath "C:\Windows\NTDS" `
 -NoRebootOnCompletion:$false `
 -SysvolPath "C:\Windows\SYSVOL" `
 -Force:$true

Import-Module ServerManager
Add-WindowsFeature RSAT-ADDS-Tools

/*
The Add-DnsServerPrimaryZone cmdlet adds a specified primary zone on a Domain Name System (DNS) server.
You can add an Active Directory-integrated forward lookup zone, an Active Directory-integrated reverse lookup zone, a file-backed forward lookup zone, or a file-backed reverse lookup zone.
-netwrokid is to setup a reverse lookup zone
*/
Add-DnsServerPrimaryZone -networkid "192.168.1.0/24" -replicationscope "Forest"

//Adds an MX resource record to a DNS server
Add-DnsServerResourceRecordMX -Preference 10  -Name "." -TimeToLive 01:00:00 -MailExchange "mail.hackcollege.com" -ZoneName "hackcollege.com"
//Adds a DNS record that point to mail server
Add-DnsServerResourceRecordA -Name "mail" -ZoneName "hackcollege.com" -AllowUpdateAny -IPv4Address "192.168.1.115" -TimeToLive 01:00:00

New-ADOrganizationalUnit -name "ITSec" -path "Dc=hackschool,DC=COM"
foreach($i in (0..10)){
$name = "student" + $i
New-ADUser -Name $name -SamAccountName $name -UserPrincipalName ($name+"@hackschool.com") -Path "OU=student,DC=hackschool,DC=com" -AccountPassword(convertto-securestring ("hackschool@"+$i) -AsPlainText -Force) -Enabled $true
}
