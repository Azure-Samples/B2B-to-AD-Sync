# B2B-AAD-to-AD-Sync
Sample script that syncs Azure AD guests to On-prem AD to grant access to on-prem resources via Azure AD Application Proxy (KCD).

## Pre-requisites
### Create a Certificate for Authentication
Run the following on the machine that will be running the script to create a self-signed certificate. This is optional if you're using your own certificate (recommended approach).
- Copy the certificate thumbprint value for later use and move the .cer file to the device you will use to upload the certificate to Azure AD (see step #9 below).

```
$certsubject = "TODO" #Be sure to enter “CN=” and then the name. For example, “CN=SelfSignedCert”  
$certexportpath = "TODO" #Enter the path where you want the .cer file to be exported. Include what you want to name the certificate in the path. For example, “C:\Users\certs\SelfSignedCert.cer”. 

New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -Subject $certsubject -KeySpec KeyExchange  
$cert = Get-ChildItem -Path cert:\localMachine\my | Where-Object {$_.subject -match "$certsubject"} 
Export-Certificate -Cert $cert -FilePath $certexportpath 
$cert | Select-Object subject, thumbprint
```


### Create an App Registration in Azure AD
[How to create an App Registration (Microsoft Documentation)](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#register-an-application)
1. In a browser, go to https://aad.portal.azure.com and sign in with an admin account with one of the following roles:
- Global Administrator
- Cloud Application Administrator
- Application Administrator
2. Navigate to "Azure Active Directory" -> "App registrations" -> click "New Registration" 
3. Enter a name for the application.
4. Under Supported account types, select "Accounts in this organizational directory only (Aperture Science only - Single tenant)"
![Image 1](/DocImages/Image1.jpg)
5. Click "Register". You should then be taken to App Registration Overview blade.
6. At the app registration Overview blade, copy the "Application (client) ID" and "Directory (tenant) ID" values for later use.
7. Navigate to "Certificates & secrets"
8. Select the "Certificates" tab and click "Upload certificate"
9. Select the .cer file you created and (optionally) enter a description.
10. Click "Add" 
![Image 2](/DocImages/Image2.jpg)
11. Navigate to "API permissions"
12. Click "Add a permission"
13. Under the Microsoft APIs tab, select "Microsoft Graph"
![Image 3](/DocImages/Image3.jpg)
14. Select "Application permissions" 
15. Check the boxes for "User.read.all" and "Group.read.all". You can use the search bar to easily find these permissions.
16. Click "Add permissions"
![Image 4](/DocImages/Image4.jpg)
17. (Optional) You may remove the default "User.read" permission.
18. Click "Grant admin consent for <company name>". Click "Yes".
![Image 5](/DocImages/Image5.jpg) 

### Install Required Powershell Modules
You will need to install the following PowerShell modules on the server that will run the script. Open PowerShell as an administrator.
  - [Active Directory](https://docs.microsoft.com/en-us/windows-server/remote/remote-server-administration-tools)
  ```
  Install-WindowsFeature RSAT-AD-PowerShell
  ```
  - [Microsoft Graph PowerShell Module](https://docs.microsoft.com/en-us/graph/powershell/installation)
  ```
  Install-Module Microsoft.Graph -Scope AllUsers
  ```

### Insert Script Values
Replace the "TODO" values in the script with the appropriate values, some of which were obtained in the above steps. They include:
- Tenant ID of your Azure AD tenant
- Client ID of the Azure AD App Registration
- Certificate thumbprint used by application for authentication
- Object ID of the [Azure AD group](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-groups-create-azure-portal#create-a-basic-group-and-add-members) where you will add guest accounts you want to have synced
- [DistinguishedName](https://support.xink.io/support/solutions/articles/1000246165-how-to-find-the-distinguishedname-of-an-ou-) of the OU where Shadow Accounts will be created
- DistinguishedName of the OU where Shadow Accounts will be moved to if they are orphaned


You are now ready to run the script on your server.

## Automate Running the Script (Optional)
### Automation via Azure Automate
You can run PowerShell scripts from Azure by using Azure Automate. With Hybrid Runbook Workers, you can pull the scripts from Azure Automate and run them on your on-prem servers on a schedule.
1. Integrate Servers and Azure Automate with Hybrid Runbook Workers
  - If the server is an Azure VM, deploying [extension-based workers](https://docs.microsoft.com/en-us/azure/automation/extension-based-hybrid-runbook-worker-install) is recommended.
  - If the server is not an Azure VM, deploy [agent-based workers for Windows](https://docs.microsoft.com/en-us/azure/automation/automation-windows-hrw-install) or [Linux](https://docs.microsoft.com/en-us/azure/automation/automation-linux-hrw-install)
  
2. [Create a PowerShell Workflow Runbook in Azure Automate](https://docs.microsoft.com/en-us/azure/automation/learn/automation-tutorial-runbook-textual)

### Automation via Task Scheduler
Create a Group Managed Service Account
```
#Running this command requires Domain Administrator Credentials
$cpu = Get-ADComputer ComputerName #Enter the name of the server that will be running the script
$acctName = "gmsa_b2b_script"
New-ADServiceAccount -Description "Account for running the script that creates B2B guest shadow accounts" `
-DisplayName $acctName `
-DNSHostName "$acctName.contoso.com" `
-Name $acctName `
-PrincipalsAllowedToRetrieveManagedPassword $cpu

install-adserviceaccount $acctName
```
Create a task for running the script on a schedule
```
$action = New-ScheduledTaskAction -Execute powershell.exe `
-Argument "-NonInteractive -NoLogo -NoProfile -File c:\scripts\B2BGuestSync.ps1"
$trigger = New-ScheduledTaskTrigger -At 7:00am -Daily
$principal = New-ScheduledTaskPrincipal -UserId corp\gmsa_b2b_script$ -LogonType Password
Register-ScheduledTask SyncB2BUsers `
-Principal $principal `
-Action $action `
-Trigger $trigger
```
NOTE: To have the gMSA run the script as a scheduled task, you must grant the gMSA the ability to "log on as a batch job" and give them appropriate permissions such as adding them to the local admin group.
