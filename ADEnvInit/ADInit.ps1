<# Script for installing Active Directory Service and add OU and members #>
Import-Module PSWorkflow
Workflow run-book{
    inlinescript{
        $domain = "hackcollege.com"
        $safePasswd = "Hackschool@2020"
        Install-windowsfeature AD-domain-services -includeManagementTools
        Import-Module ADDSDeployment
        Install-ADDSForest -Force -DomainName $domain -SafeModeAdministratorPassword (convertto-securestring($safePasswd) -AsPlainText -Force)
    }
    Restart-Computer -Wait
    inlinescript{
        Import-Module ServerManager
        Add-WindowsFeature RSAT-ADDS-Tools
        <#
        The Add-DnsServerPrimaryZone cmdlet adds a specified primary zone on a Domain Name System (DNS) server.
        You can add an Active Directory-integrated forward lookup zone, an Active Directory-integrated reverse lookup zone, a file-backed forward lookup zone, or a file-backed reverse lookup zone. -netwrokid is to setup a reverse lookup zone
#>
        Add-DnsServerPrimaryZone -networkid "10.0.0.0/24" -replicationscope "Forest"

        <#Add the OU and members#>
        New-ADOrganizationalUnit -name "ITSec" -path "Dc=hackschool,DC=COM"
        New-ADOrganizationalUnit -name "student" -path "Dc=hackschool,DC=COM"
        foreach($i in (0..10)){
            $name = "student" + $i
            New-ADUser -Name $name -SamAccountName $name -UserPrincipalName ($name+"@hackschool.com") -Path "OU=student,DC=hackschool,DC=com" -AccountPassword (convertto-securestring ("hackschool@"+$i) -AsPlainText -Force) -Enabled $true
        }
    }
}

run-book
