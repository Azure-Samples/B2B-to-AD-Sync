#region 1 - Synopsis
<# 
.SYNOPSIS
    Sample script to create shadow accounts in AD for Azure AD Application Proxy KCD delegation for Azure AD B2B Guest accounts.
    Includes options to: 
    - Create shadow accounts in an OU of Azure AD guest users. This can be scoped to guests in a specific Azure AD group.
    - (Optional) Disable and move shadow accounts who no longer exist in Azure AD to a different OU
    - (Optional) Delete shadow accounts in the OU who no longer exist in Azure AD
    - (Optional) Restore orphaned shadow accounts if the corresponding guest user is re-added to the Azure AD group
    Shadow accounts will be created with the following properties:
            -AccountPassword = random strong password
            -ChangePasswordAtLogon = $false
            –PasswordNeverExpires = $true
            -SmartcardLogonRequired = $true
    NOTE: This does not support group nesting in the Azure AD Group
.DESCRIPTION
    Version: 1.0.3
    This is currently a beta level script and intended to be used as a demonstration script
.DISCLAIMER
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.
    Copyright (c) Microsoft Corporation. All rights reserved.
#>

<#
Recommended action items for production deployments
- Consider adding additional filters for performance improvements
- Add error handling
- Add reporting (limited reporting available via the What If mode)
#>
#endregion

#region 2 - Set script variables
$CreateMissingShadowAccounts = $true #If set to true, Shadow Accounts of guest users in the Azure AD group will be created in AD.
$RestoreDisabledAccounts = $true #If set to true, disabled Shadow Accounts can be restored to the ShadowAccountOU and be re-enabled if the guest account is added again to the Azure AD Group.
$WhatIf = $false #If set to true, no users will be created, disabled, deleted, or move OU's - overriding the values otherwise set. A report will show what would happen if the script ran. E.g. what users would be created, disabled, deleted, etc.

# Only one of the following should be true. If both are True then disable action takes precedence.
$DisableOrphanedShadowAccounts = $true #If set to true, guest users who are removed from the Azure AD group will be disabled and moved to the ShadowAccountOUArchive.
$DeleteOrphanedShadowAccounts = $false #If set to true, guest users who are removed from the Azure AD group will be deleted from AD.

# Replace all TODO values with the appropriate value.
# Requires additional configuration - refer to documentation
$B2BGroupID = "TODO" #Azure AD group's ObjectID
$ShadowAccountOU = "TODO" #DistinguishedName of an OU for placing shadow accounts
$DisabledShadowAccountOU = "TODO" #DistinguishedName of an OU for moving disabled shadow accounts
$AppID = "TODO" # Insert your application's Client ID
$TenantID = "TODO" # Tenant ID of Azure AD
$Cert = "TODO" #Certificate thumbprint used by application for authentication

# No need to modify more variables
# Variable initialization
$TenantGuestUsersHash = @{} 
$UsersInB2BGroupHash = @{}
$B2bShadowAccountsHash = @{}
$B2bDisabledShadowAccountsHash = @{}
$ReenabledShadowAccounts = @{}
#endregion

#region 3 - Populate Initial Hash Tables
Connect-MgGraph -ClientID $appID -TenantId $tenantID -CertificateThumbprint $Cert
#If you want to run under a user context, run Connect-MgGraph -Scopes "user.read.all","group.read.all" 

# Populate hash table with all Guest users from tenant using object ID as key
get-mguser -Filter "userType eq 'Guest' and accountenabled eq true" -all |  `
ForEach-Object {$TenantGuestUsersHash[$_.Id] = $_}

# Populate hash table with membership of target group from Azure AD using object ID as key
Get-MgGroupMember -GroupId $B2BGroupID -all | `
	ForEach-Object {$UsersInB2BGroupHash[$_.Id] = $_}

# Populate hash table with all accounts in shadow account OU using UPN as key
Get-AdUser -filter * -SearchBase $ShadowAccountOU | `
	Select-Object UserPrincipalName, Name, Description | ` 
	ForEach-Object {$B2bShadowAccountsHash[$_.UserPrincipalName] = $_}

Get-AdUser -filter * -SearchBase $DisabledShadowAccountOU | `
	Select-Object UserPrincipalName, Name, Description | ` 
	ForEach-Object {$B2bDisabledShadowAccountsHash[$_.UserPrincipalName] = $_}
#endregion 

#region 4 - Populate Hash Table Differencing Lists
ForEach($key in $($UsersInB2BGroupHash.Keys))
    {
    # remove non-guest users from the Azure AD Group list in case members are accidentally added to the group
    if($TenantGuestUsersHash.ContainsKey($key) -eq $false)
        {
        $UsersInB2BGroupHash.Remove($key)
        }
    # B2B guest user already has a shadow account remove from both lists
    # we'll then end up with 2 differencing lists
    elseif ($B2bShadowAccountsHash.ContainsKey($TenantGuestUsersHash[$key].userprincipalname))
        {
        $UsersInB2BGroupHash.Remove($key)
        $B2bShadowAccountsHash.Remove($TenantGuestUsersHash[$key].userprincipalname)
        }
    elseif ($B2bDisabledShadowAccountsHash.ContainsKey($TenantGuestUsersHash[$key].userprincipalname))
        {
        $ReenabledShadowAccounts.Add($TenantGuestUsersHash[$key].userprincipalname,$key)
        $UsersInB2BGroupHash.Remove($key)
        }
    }
#endregion

#region 5 - What If Mode
If($WhatIf -eq $true)
{
$CreateMissingShadowAccounts = $false
$RestoreDisabledAccounts = $false
$DisableOrphanedShadowAccounts = $false 
$DeleteOrphanedShadowAccounts = $false

Write-Host ""
Write-Host "*****Azure AD Guest Accounts that will have Shadow Accounts created*****"
ForEach($key in $($UsersInB2BGroupHash.Keys))
{
$TenantGuestUsersHash[$key].userprincipalname
}
Write-Host ""
Write-Host "*****Orphaned Shadow Accounts that will be disabled or deleted*****"
$B2bShadowAccountsHash.Keys
Write-Host ""
Write-Host "*****Disabled Shadow accounts whose Guest account has been re-added to the Azure AD group - Can be re-enabled*****"
$ReenabledShadowAccounts.Keys
Write-Host ""
}
#endregion

#region 6 - Create Shadow Accounts
If ($CreateMissingShadowAccounts -eq $true)
{
    ForEach($key in $($UsersInB2BGroupHash.keys))
        {
        $samaccountname = (-join $TenantGuestUsersHash[$key].userprincipalname.Split("@")[0][0..19]).TrimEnd('.') # sAMAccountName must be no longer than 20 characters long and final character cannot be a period https://learn.microsoft.com/en-us/archive/technet-wiki/11216.active-directory-requirements-for-creating-objects#objects-with-samaccountname-attribute
        $displayname = $TenantGuestUsersHash[$key].userprincipalname.Split('#')[0]
        # generate random password
        $bytes = New-Object Byte[] 32
        $rand = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rand.GetBytes($bytes)
        $rand.Dispose()
        $RandPassword = [System.Convert]::ToBase64String($bytes)
            
        # Create AD user account, setting adminDescription to 'User_', to filter account from sync via Entra Connect Sync - based on https://blogs.perficient.com/2016/04/11/office-365-the-previously-undocumented-aad-connect-filter/
	New-ADUser -Name $displayname `
            -SamAccountName $samaccountname `
            -Path $ShadowAccountOU `
            -UserPrincipalName $TenantGuestUsersHash[$key].userprincipalname `
            -Description "Shadow account of Azure AD guest account" `
            -DisplayName $TenantGuestUsersHash[$key].DisplayName `
	    -OtherAttributes @{'adminDescription'="User_FilterAzureAD"} `
            -AccountPassword (ConvertTo-SecureString $RandPassword -AsPlainText -Force) `
            -ChangePasswordAtLogon $false `
            –PasswordNeverExpires $true `
            -SmartcardLogonRequired $true
        Enable-ADAccount -Identity $samaccountname
        }
}
#endregion

#region 7 - Clean up
# Restoring disabled users that have been added back to the Azure AD group.
If ($RestoreDisabledAccounts -eq $true)
    {
     ForEach ($Shadow in $($ReenabledShadowAccounts.keys))
        {
            Get-AdUser -Filter {UserPrincipalName -eq $shadow} -SearchBase $DisabledShadowAccountOU | Set-ADUser -Enabled $true -Description "Shadow account of Azure AD guest account" 
            Get-AdUser -Filter {UserPrincipalName -eq $shadow} -SearchBase $DisabledShadowAccountOU | Move-ADObject -TargetPath $ShadowAccountOU
        }
    }

# Clean up Shadow accounts that have been removed from the Azure AD group.
 If ($DisableOrphanedShadowAccounts -eq $true -or $DeleteOrphanedShadowAccounts -eq $true)
 {
      ForEach ($shadow in $($B2bShadowAccountsHash.keys))
        {
            # $upn = the key from B2bShadowAccountsHash = $shadow
            # disable operation takes precedence over deletion
            If ($DisableOrphanedShadowAccounts -eq $true)
            {
                Get-AdUser -Filter {UserPrincipalName -eq $shadow} -SearchBase $ShadowAccountOU| Set-ADUser -Enabled $false -Description 'Disabled pending removal' 
                Get-AdUser -Filter {UserPrincipalName -eq $shadow} -SearchBase $ShadowAccountOU | Move-ADObject -TargetPath $DisabledShadowAccountOU         
            }
            ElseIf ($DeleteOrphanedShadowAccounts = $true)
            {
                Get-AdUser -Filter {UserPrincipalName -eq $shadow} -SearchBase $ShadowAccountOU | Remove-AdUser
            }
        }
  }
  #endregion
