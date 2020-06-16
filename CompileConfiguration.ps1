## Install required DSC resources to compile configuration
Install-Module -Name CertificateDsc, NetworkingDsc, XenDesktop7, xWebAdministration -Scope CurrentUser

Set-Location -Path ~\Documents

## Ensure we have a domain credential with local admin privileges
if (-not $Credential) { $Credential = Get-Credential 'LAB\Administrator' }

## Register the 'CUGUKDsc' DSC configuration
. .\CUGUKDsc.ps1

## Generate node LCM configurations
CUGUKLcm -OutputPath .\CVAD1912 -ConfigurationData .\CUGUK.psd1

## Generate node MOF files using our configuration data
CUGUKDsc -OutputPath .\CVAD1912 -ConfigurationData .\CUGUK.psd1 -Credential $Credential
