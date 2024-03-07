#Username to be copied from
$copyuser = Read-Host "Please enter the Username to copy from (Ex. FLast)"
#New user username info
$newuser = Read-Host "Please enter the new employee Username (Ex. FLast)"
$firstname = Read-Host "Please enter the new employee's first name"
$lastname = Read-Host "Please enter the new employee's last name"
$email = "$newuser@DOMAIN.org"
$display = "$firstname $lastname"
$accountpassword = Read-Host "Please enter a password" -AsSecureString

$newuserattributes = Get-ADUser -Identity $copyuser -Properties StreetAddress,City,State,PostalCode,Office,Department,Title,Manager,ScriptPath,TelephoneNumber,Description,Fax,Company
New-ADUser -Name $display -GivenName $firstname -Surname $lastname -SAMAccountName $newuser -Instance $newuserattributes -DisplayName $display -UserPrincipalName $email -path "OU=Employees,DC=DOMAIN,DC=local" -AccountPassword $accountpassword -ChangePasswordAtLogon $false -Enabled $true
Get-ADUser -Identity $copyuser -Properties memberof | Select-Object -ExpandProperty memberof | Add-ADGroupMember -Members $newuser
Set-ADUser -Identity $newuser -HomeDirectory "\\fp01\users\$newuser" -HomeDrive Z: -EmailAddress $email

#Create the home folder for new user
New-Item -Path "\\fp01\Users" -Name "$newuser" -Type Directory
# Get the ACL for an existing folder
$existingAcl = Get-Acl -Path \\fp01\Users\$newuser
# Set the permissions that you want to apply to the folder
$permissions = $newuser, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
# Create a new FileSystemAccessRule object
$rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permissions
# Modify the existing ACL to include the new rule
$existingAcl.SetAccessRule($rule)
# Apply the modified access rule to the folder
$existingAcl | Set-Acl -Path \\fp01\Users\$newuser
#Check permissions
(Get-ACL -Path "\\fp01\Users\$newuser").Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize

#Run AD sync for changes to reflect across environment
Set-ExecutionPolicy RemoteSigned -Force
$UserCredential = Get-Credential
$Session = New-PSSession -ComputerName DC2 -Credential $UserCredential
Invoke-Command -Session $Session -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}
Remove-PSSession $Session

$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://MAIL01.DOMAIN.Local/PowerShell/ -Authentication Kerberos -Credential $UserCredential
Import-PSSession $Session -AllowClobber
Enable-RemoteMailbox $newuser -RemoteRoutingAddress "$newuser@DOMAIN.mail.onmicrosoft.com"
Remove-PSSession $Session
