# The following lines are for clean-up and compaction purposes. They could take hours and degrade performance.
# Save this file with a .ps1 extension. This will disable ALL features (you might want .net 3.5 or 4..) and most capabilities except for Basic English.

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}
$ErrorActionPreference= 'silentlycontinue'
Write-Progress -Activity "Downloading PolicyFileEditor" -Status "Progress:" -PercentComplete 1
Write-Host "Installing PolicyFileEditor"
install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Write-Progress -Activity "Downloading PolicyFileEditor" -Status "Progress:" -PercentComplete 5
Write-Host "Seting up Repository"
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
Write-Progress -Activity "Downloading PolicyFileEditor" -Status "Progress:" -PercentComplete 10
Write-Host "Installing PolicyFileEditor Module"
install-module PolicyFileEditor
Write-Progress -Activity "Downloading PolicyFileEditor" -Status "Progress:" -PercentComplete 15
Write-Host "Importing PolicyFileEditor Module"
import-module PolicyFileEditor
Write-Progress -Activity "Downloading PolicyFileEditor" -Status "Progress:" -PercentComplete 100
Write-Host "Compacting O/S Files"
Compact.exe /F /CompactOS:always
Write-Host "Emptying Temp Files"
$tempfolders = @(“C:\Windows\Temp\*”, “C:\Windows\Prefetch\*”, “C:\Documents and Settings\*\Local Settings\temp\*”, “C:\Users\*\Appdata\Local\Temp\*”)
Remove-Item $tempfolders -force -recurse
Write-Host "Enabling NTFS Compression"
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "System\CurrentControlSet\Policies" -ValueName NtfsDisableCompression -Type DWord -Data 0

Write-Host "Cleaning TEMP Files"
cleanmgr.exe /d c: sageset:1 | Out-Null
cleanmgr.exe /sagerun:1 | Out-Null

Write-Host "Cleaning extra crap out/disabling default features."
Dism.exe /online /Remove-Capability /CapabilityName:Language.Handwriting~~~en-US~0.0.1.0
Dism.exe /online /Remove-Capability /CapabilityName:Language.OCR~~~en-US~0.0.1.0
Dism.exe /online /Remove-Capability /CapabilityName:Language.Speech~~~en-US~0.0.1.0
Dism.exe /online /Remove-Capability /CapabilityName:Language.TextToSpeech~~~en-US~0.0.1.0
Dism.exe /online /Remove-Capability /CapabilityName:RetailDemo.OfflineContent.Content~~~~0.0.1.0
Dism.exe /online /Remove-Capability /CapabilityName:RetailDemo.OfflineContent.Content~~~en-US~0.0.1.0
Dism.exe /online /Disable-Feature /FeatureName:FaxServicesClientPackage
Dism.exe /online /Disable-Feature /FeatureName:MSRDC-Infrastructure
Dism.exe /online /Disable-Feature /FeatureName:WCF-Services45
Dism.exe /online /Disable-Feature /FeatureName:WCF-HTTP-Activation45
Dism.exe /online /Disable-Feature /FeatureName:WCF-TCP-Activation45
Dism.exe /online /Disable-Feature /FeatureName:WCF-TCP-PortSharing45
Dism.exe /online /Disable-Feature /FeatureName:NetFx4-AdvSrvs
Dism.exe /online /Disable-Feature /FeatureName:Printing-XPSServices-Features
Dism.exe /online /Disable-Feature /FeatureName:Printing-PrintToPDFServices-Features
Dism.exe /online /Disable-Feature /FeatureName:Xps-Foundation-Xps-Viewer
Dism.exe /online /Disable-Feature /FeatureName:NetFx3
Dism.exe /online /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64

Write-Host "Dism Cleanup..."
Dism.exe /online /Cleanup-Image /StartComponentCleanup | Out-Null
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
Dism.exe /online /Cleanup-Image /SPSuperseded | Out-Null
powercfg /h off

# Disable automatic pagefile management
$cs = gwmi Win32_ComputerSystem
if ($cs.AutomaticManagedPagefile) {
    $cs.AutomaticManagedPagefile = $False
    $cs.Put()
}
# Disable a *single* pagefile if any
$pg = gwmi win32_pagefilesetting
if ($pg) {
    $pg.Delete()
}

Write-Host
Write-Host "Press any key to restart your system..." -ForegroundColor Black -BackgroundColor White
$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host "Restarting..."
Restart-Computer