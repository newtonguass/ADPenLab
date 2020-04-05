try{
    $name = (Get-NetAdapter | select Name).Name
    Disable-NetAdapterBinding –InterfaceAlias $name –ComponentID ms_tcpip6
}catch{

}
