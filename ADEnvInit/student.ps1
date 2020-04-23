try{
    $name = (Get-NetAdapter | select Name).Name
    Disable-NetAdapterBinding –InterfaceAlias $name –ComponentID ms_tcpip6
}catch{
    add-content "c:\\log.txt" -value "$(get-date -format 'u'): $_.exception.message"
}
try{
    $index = (Get-NetAdapter | select IfIndex).IfIndex
    Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses ("10.0.0.4")
}catch{
    add-content "c:\\log.txt" -value "$(get-date -format 'u'): $_.exception.message"
}


$ports = 53, 88, 135, 389, 445
$notConnection = $true
while($notConnection){
    $notConnection= $false
    foreach($i in $ports){
        if((Test-NetConnection -ComputerName 10.0.0.4 -Port $i).TcpTestSucceeded -eq $false){
            add-content "c:\\log.txt" -value "$(get-date -format 'u'): service $i not on, waitting"
            $notConnection=$true
            break
        }else{
            add-content "c:\\log.txt" -value "$(get-date -format 'u'): service $i is on"
        } 
    }
}

$domain = "hackcollege.tw"
$username = "student"
$password =( "Hackcollege@2020" | ConvertTo-SecureString -asPlainText -Force)
$credential = New-Object System.Management.Automation.PSCredential $username,$password

function add-todomain{
    try{
        Add-Computer -DomainName $domain -Credential $credential -Restart
        add-content "c:\\log.txt" -value "$(get-date -format 'u'): add to domain successfully"
    }catch{
        add-content "c:\\log.txt" -value "$(get-date -format 'u'): $_.exception.message"
        add-todomain
    }
}
add-todomain
Restart-Computer -Force
