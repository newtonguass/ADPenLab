$domain = "hackcollege.tw"
$username = "hackcollege\student"
$password =( "Hackcollege@2020" | ConvertTo-SecureString -asPlainText -Force)
$credential = New-Object System.Management.Automation.PSCredential $username,$password

function add-todomain{
    try{
        Add-Computer -DomainName $domain -Credential $credential -Restart
        add-content "c:\\log.txt" -value "$(get-date -format 'u'): add to domain successfully"
    }catch{
        add-content "c:\\log.txt" -value "$(get-date -format 'u'): $_.exception.message"
    }
}
add-todomain
Restart-Computer -Force
