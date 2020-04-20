try{
    $name = (Get-NetAdapter | select Name).Name
    Disable-NetAdapterBinding –InterfaceAlias $name –ComponentID ms_tcpip6
}catch{
    Write-Host "Fail to disable IPv6"
}
<#
try{
    $domain = "hackcollege.tw"
    $password = "Hackcollege@2020" | ConvertTo-SecureString -asPlainText -Force
    $username = "$domain\student"
    $credential = New-Object System.Management.Automation.PSCredential($username,$password)
    Add-Computer -DomainName $domain -Credential $credential -Restart
}catch{
    Write-Host "Fail to disable IPv6"
}
#>
