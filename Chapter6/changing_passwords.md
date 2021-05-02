# Changing passwords
The following are some basic loops to change all user account passwords on a machine

## chpasswd on Linux
This oneliner will roll all user passwords on a Linux system to a random 9 charcter password :
```
# while IFS=: read u x nn rest; do if [ $nn -ge 999 ]; then NEWPASS=`openssl rand -base64 9`; echo “${u]:${NEWPASSW}” | chpasswd; fi  done < /etc/passwd
```
## Changing passwords on Windows
Using the modified [Invoke-PasswordRoll.ps1](https://github.com/ahhh/Cybersecurity-Tradecraft/blob/main/Chapter6/Invoke-PasswordRoll.ps1) we can change all local passwords on a Windows machine:
```
> Invoke-PasswordRoll -LocalAccounts @("Administrator", "example_user") -TsVFileName "newpws.tsv" -EncryptionKey "secretvalue"
```
We can use the original [Invoke-PasswordRoll.ps1](https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30) on a remote Windows machine with:
```
> Invoke-PasswordRoll -Computer RemoteWinHost -LocalAccounts @("Administrator", "example_user") -TsVFileName "newpws.tsv" -EncryptionKey "secretvalue"
```
To decrypt these new passwords use the ConvertTo-CleartextPassword script with the EncryptedPassword:
```
> ConvertTo-CleartextPassword -EncryptionKey "secretvalue"  
-EncryptedPassword 76492d1116743f0423413b16050a5345MgB8ADQANAB4AEcATwBkAGYATQA4AFQAWgBZAEsAOQBrAGYANQBpADMAOQBwAFEAPQA9AHwANwBjADEAZgA2ADgAMAAwADIAOAAxAGUANgBlADQAOQA2ADQAYwBkADUAYwBhADIANgA1ADgANwA5AGQAYwA4ADAAYgBiAGUAZgBhADkANwBlADMANwA2ADMAMQA3AGMAZQAyADIAZgA4ADMANwBiAGQANwA3ADcAYwAwADQAZgAyAGUANAAxAGEAZQA1ADcAYgAxADYAMABkADMAZABjADgAZQBhAGQAZgAyADIAZQBjADEAYgAwADkAZgA4AGMA
```
To force Windows domain users to change their password at next login:
```
> Get-ADUser -Filter * -SearchScope Subtree -SearchBase "OU=Accounts,DC=ad,DC=contoso,DC=com" | Set-ADUser -ChangePasswordAtLogon $true
```
