#Requires -Version 5.1
<# Run on SERVER or CLIENT. Applies computer policy and triggers the auto-enrollment task now
   instead of waiting for the next policy refresh. #>
gpupdate /target:computer /force | Out-String
Start-Sleep -Seconds 5
certutil -pulse | Out-Null
Start-Sleep -Seconds 45
