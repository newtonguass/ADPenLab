# ADPenTest Lab 
This repository ami to provide a quick setup for simple AD penetration environment, including
  - Azure AD PenTest Environment
    - Quick start template to build one domain controller and a compute ready for join domain
    - Leverage the Azure bastion server to RDP to enhance the ADPen environment.
  - Domain Attack Kill Chain Lab
      - Reconn
        - SPN scanning
        - User, Group, Computer enum
        - High privilege account hunting
        - Attacking path finding
      - PrivilegeEsclation
        - Exploiting group policy vulnerability
        - Hidden account
      - CredentialDumping & Lateral Movement
        - Responder
        - Handcraft of simple Mimikatz
        - Kerberoasting
      - Persistence
        - NTLM Relay
        - DC sync
<img width="650" src="https://cloudblogs.microsoft.com/uploads/prod/2016/11/Attack-Kill-Chain-1024x542-1024x542.jpg">

---
## AD Pen test environment quick setup in Azure

- This template creates three VM in Azure
    1. Domain Controller  
        - Win Server 2016
        - With some example OU and one unconstrained delegation account
        - Enable customized GPO
    1. client 
        - Win 10
        - With vulnerable service for privilege ecalation practice
    1. Relay Victim 
        - Win Server 2016
        - Very vulnerable web service for SSRF
        - High privileged computer account for realy practice(by using the cve2018-8581)
- Carefully select the VM size, because the quota for Azure free account is limited to 4 cores.
- Since default network security group does not allow inbound connection from internet and there are no public IP in those VMs, you need to use bastion server to connect VMs. if you want to RDP directly, you need to add public IP and change the network security group.
- If you not use the default user name and password, the computer will not join the domain automatically. You need to join the domain on your own.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnewtonguass%2FADPenLab%2Fmaster%2FADEnvInit%2FAzureDeployment%2FADPenTestEnvDeploy.json" rel="nofollow">
<img src="https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.png" style="max-width:100%;">
</a>

<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fnewtonguass%2FADPenLab%2Fmaster%2FADEnvInit%2FAzureDeployment%2FADPenTestEnvDeploy.json" target="_blank">
    <img src="https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/visualizebutton.png"/>
</a>


