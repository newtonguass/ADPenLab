# ADPenTest Lab 
This repository ami to provide a quick setup for simple AD penetration environment, including
  - Azure AD PenTest Environment
  - Domain Attack Kill Chain Lab
      - Reconn
      - PrivilegeEsclation
      - CredentialDumping
      - LateralMovement
      - Persistence
      - Defense&Detection
<img width="650" src="https://cloudblogs.microsoft.com/uploads/prod/2016/11/Attack-Kill-Chain-1024x542-1024x542.jpg">

---
## AD Pen test environment quick setup in Azure

- This template creates two VM in Azure. One is domain controller and the other one is computer that is for join domain.
- Since default network security group does not allow inbound connection from internet and there are no public IP in those VMs, you need to use bastion server to connect VMs. if you want to RDP directly, you need to add public IP and change the network security group.

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnewtonguass%2FADPenLab%2Fmaster%2FADEnvInit%2FAzureDeployment%2FADPenTestEnvDeploy.json" rel="nofollow">
<img src="https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.png" style="max-width:100%;">
</a>

<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fnewtonguass%2FADPenLab%2Fmaster%2FADEnvInit%2FAzureDeployment%2FADPenTestEnvDeploy.json" target="_blank">
    <img src="https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/visualizebutton.png"/>
</a>


---
### Tips
1. Change the VMs to what you want in the Azure deployment page.
1. Customize parameters in azuredeploy.parameters as you see appropriate, at the very least the adminPassword.
