##########
# Win10 Initial Setup Script
# Author: Disassembler, Gr1d:, TheRoc
# Edited by Gr1D:
# dasm's script: https://github.com/Disassembler0/Win10-Initial-Setup-Script/
# Gr1D:'s Script: https://gist.github.com/TheRoboKitten/98b5b25345105a5e79f56d61eec4bc65
# TheROC's E.T. Disable script: https://gist.github.com/thoroc/86d354d029dda303598a

# THIS IS VERSION 5.5, error suppression is turned on. PLEASE be patient and PLEASE restart after running the script.
# This script leaves more MS defaults on, including MSE and smart-screen, 
# but blocks a ton of domains and disables remote assistance secures java, sets up ipsec..
# (please set your own key - SEE BELOW A FEW LINES) and disables SSL. Even changes your mac and takes steps to secure Google Chrome,
# Adobe Acrobat and Adobe Reader DC. To disable skynet turn off smartscreen and antivirus.

# NOTE: READ THIS SCRIPT CAREFULLY BEFORE RUNNING IT. ADJUST COMMENTS AS APPROPRIATE.
# This script will reboot your machine when completed.
# Setting up a new machine? See http://ninite.com (for devs, http://chocolatey.org)
##########
 
# Ask for elevated permissions if required

$ErrorActionPreference= 'silentlycontinue'

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}


#
# PLEASE EDIT THE BELOW LINE TO SET YOUR IPSEC PASSWORD (This may be randomly generated in the future)
$ThePreSharedKey = 'PasswordCHANGEME'


Write-Progress -Activity "Backing up registry. This may take awhile..." -Status "Progress:" -PercentComplete 1
del C:\registry-backup-hklm.reg
del C:\registry-backup-hkcu.reg
del C:\registry-backup-hkcr.reg

reg export HKLM C:\registry-backup-hklm.reg | Out-Null
reg export HKCU C:\registry-backup-hkcu.reg | Out-Null
reg export HKCR C:\registry-backup-hkcr.reg | Out-Null
Write-Progress -Activity "Backing up registry. This may take awhile..." -Status "Progress:" -PercentComplete 100
##########
# Privacy Settings
##########
Write-Progress -Activity "Setting some privacy settings..." -Status "Progress:" -PercentComplete 1
# Disable Telemetry
# Disable Telemetry
Write-Host "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

# Enable Telemetry
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3

# Disable Wi-Fi Sense
Write-Host "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
Write-Progress -Activity "Setting some privacy settings..." -Status "Progress:" -PercentComplete 15
# Enable Wi-Fi Sense
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1
 
# Disable SmartScreen Filter
# Write-Host "Disabling SmartScreen Filter..."
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0
 
# Enable SmartScreen Filter
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "RequireAdmin"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation"
 
# Disable Bing Search in Start Menu
Write-Host "Disabling Bing Search in Start Menu..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
 
# Enable Bing Search in Start Menu
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled"

Write-Progress -Activity "Setting some privacy settings..." -Status "Progress:" -PercentComplete 30
# Disable Start Menu suggestions
# Write-Host "Disabling Start Menu suggestions..."
# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0

# Enable Start Menu suggestions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 1

# Disable Location Tracking
Write-Host "Disabling Location Tracking..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
 
# Enable Location Tracking
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1
Write-Progress -Activity "Setting some privacy settings..." -Status "Progress:" -PercentComplete 45
# Disable Feedback
Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
 
# Enable Feedback
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod"
 
# Disable Advertising ID
Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
 
# Enable Advertising ID
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled"
Write-Progress -Activity "Setting some privacy settings..." -Status "Progress:" -PercentComplete 60
# Disable Cortana
Write-Host "Disabling Cortana..."
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
 
# Enable Cortana
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy"
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts"
 
# Restrict Windows Update P2P only to local network
Write-Host "Restricting Windows Update P2P only to local network..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3
 Write-Progress -Activity "Setting some privacy settings..." -Status "Progress:" -PercentComplete 75
# Unrestrict Windows Update P2P
# Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode"
 
# Remove AutoLogger file and restrict directory
Write-Host "Removing AutoLogger file and restricting directory..."
$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
    Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
 
# Unrestrict AutoLogger directory
# $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
# icacls $autoLoggerDir /grant:r SYSTEM:`(OI`)`(CI`)F | Out-Null
 
# Stop and disable Diagnostics Tracking Service
Write-Host "Stopping and disabling Diagnostics Tracking Service..."
Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled
 
# Enable and start Diagnostics Tracking Service
# Set-Service "DiagTrack" -StartupType Automatic
# Start-Service "DiagTrack"
Write-Progress -Activity "Setting some privacy settings..." -Status "Progress:" -PercentComplete 90
# Stop and disable WAP Push Service
Write-Host "Stopping and disabling WAP Push Service..."
Stop-Service "dmwappushservice"
Set-Service "dmwappushservice" -StartupType Disabled
 
# Enable and start WAP Push Service
# Set-Service "dmwappushservice" -StartupType Automatic
# Start-Service "dmwappushservice"
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "DelayedAutoStart" -Type DWord -Value 1
 
Write-Progress -Activity "Setting some privacy settings..." -Status "Progress:" -PercentComplete 100
 
##########
# Service Tweaks
##########
Write-Progress -Activity "Setting some service tweaks..." -Status "Progress:" -PercentComplete 1
# Lower UAC level
# Write-Host "Lowering UAC level..."
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
 
# Raise UAC level
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
 
# Enable sharing mapped drives between users
# Write-Host "Enabling sharing mapped drives between users..."
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1
 
# Disable sharing mapped drives between users
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections"
 
# Disable Firewall
# Write-Host "Disabling Firewall..."
# Set-NetFirewallProfile -Profile * -Enabled False
 
# Enable Firewall
Set-NetFirewallProfile -Profile * -Enabled True
 
# Disable Windows Defender
# Write-Host "Disabling Windows Defender..."
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1

#### Configure the two below options when NOT running windows defender. (These sound pretty shady.. SKYNET!)

# Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ValueName **del.SpynetReporting -Type String -Data ""
# Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ValueName SubmitSamplesConsent -Type DWord -Data 2

# Enable Windows Defender
Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0
Write-Progress -Activity "Setting some service tweaks..." -Status "Progress:" -PercentComplete 45

# Disable Windows Update automatic restart
Write-Host "Disabling Windows Update automatic restart..def."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1
 
# Enable Windows Update automatic restart
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 0
 
# Stop and disable Home Groups services
Write-Host "Stopping and disabling Home Groups services..."
Stop-Service "HomeGroupListener"
Set-Service "HomeGroupListener" -StartupType Disabled
Write-Progress -Activity "Setting some service tweaks..." -Status "Progress:" -PercentComplete 80
Stop-Service "HomeGroupProvider"
Set-Service "HomeGroupProvider" -StartupType Disabled
 
# Enable and start Home Groups services
# Set-Service "HomeGroupListener" -StartupType Manual
# Set-Service "HomeGroupProvider" -StartupType Manual
# Start-Service "HomeGroupProvider"

# Disable Remote Assistance
Write-Host "Disabling Remote Assistance..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
Write-Progress -Activity "Setting some service tweaks..." -Status "Progress:" -PercentComplete 80
# Enable Remote Assistance
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
 
# Enable Remote Desktop w/o Network Level Authentication
# Write-Host "Enabling Remote Desktop w/o Network Level Authentication..."
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0
 
# Disable Remote Desktop
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
Write-Progress -Activity "Setting some service tweaks..." -Status "Progress:" -PercentComplete 100
 
 
##########
# UI Tweaks
##########
Write-Progress -Activity "Setting some UI tweaks..." -Status "Progress:" -PercentComplete 1
# Disable Action Center
Write-Host "Disabling Action Center..."
If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
  New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
 
# Enable Action Center
# Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled"
 
# Disable Lock screen
# Write-Host "Disabling Lock screen..."
# If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
# 	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Out-Null
# }
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1

# Enable Lock screen
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen"

# Disable Lock screen (Anniversary Update workaround)
#If ([System.Environment]::OSVersion.Version.Build -gt 14392) { # Apply only for Redstone 1 or newer
#	$service = New-Object -com Schedule.Service
#	$service.Connect()
#	$task = $service.NewTask(0)
#	$task.Settings.DisallowStartIfOnBatteries = $false
#	$trigger = $task.Triggers.Create(9)
#	$trigger = $task.Triggers.Create(11)
#	$trigger.StateChange = 8
#	$action = $task.Actions.Create(0)
#	$action.Path = "reg.exe"
#	$action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
#	$service.GetFolder("\").RegisterTaskDefinition("Disable LockScreen", $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
#}

# Enable Lock screen (Anniversary Update workaround)
#If ([System.Environment]::OSVersion.Version.Build -gt 14392) { # Apply only for Redstone 1 or newer
#	Unregister-ScheduledTask -TaskName "Disable LockScreen" -Confirm:$false -ErrorAction SilentlyContinue
#}
Write-Progress -Activity "Setting some UI tweaks..." -Status "Progress:" -PercentComplete 15
# Disable Autoplay
Write-Host "Disabling Autoplay..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

# Enable Autoplay
# Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0

# Disable Autorun for all drives
Write-Host "Disabling Autorun for all drives..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
  New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
 
# Enable Autorun
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun"
Write-Progress -Activity "Setting some UI tweaks..." -Status "Progress:" -PercentComplete 30
#Disable Sticky keys prompt
Write-Host "Disabling Sticky keys prompt..." 
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
 
# Enable Sticky keys prompt
# Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510"
 
# Hide Search button / box I THINK THIS BREAKS OR THE DEVICEACCESS KEYS
# Write-Host "Hiding Search Box / Button..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
 
# Show Search button / box
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode"
 
# Hide Task View button
# Write-Host "Hiding Task View button..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
 
# Show Task View button
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton"
 
# Show small icons in taskbar
# Write-Host "Showing small icons in taskbar..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
 
# Show large icons in taskbar
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons"
 
# Show titles in taskbar
# Write-Host "Showing titles in taskbar..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1
 
# Hide titles in taskbar
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel"
 
# Show all tray icons
# write-Host "Showing all tray icons..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
 
# Hide tray icons as needed
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray"
Write-Progress -Activity "Setting some UI tweaks..." -Status "Progress:" -PercentComplete 45
# Show known file extensions
Write-Host "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
 
# Hide known file extensions
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
 
# Show hidden files
Write-Host "Showing hidden files..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
 
# Hide hidden files
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
 
# Change default Explorer view to "Computer"
Write-Host "Changing default Explorer view to `"Computer`"..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
Write-Progress -Activity "Setting some UI tweaks..." -Status "Progress:" -PercentComplete 75
# Change default Explorer view to "Quick Access"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo"
 
# Show Computer shortcut on desktop
Write-Host "Showing Computer shortcut on desktop..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
  New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
Write-Progress -Activity "Setting some UI tweaks..." -Status "Progress:" -PercentComplete 100
# Hide Computer shortcut from desktop
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
 
# Remove Desktop icon from computer namespace
# Write-Host "Removing Desktop icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue
 
# Add Desktop icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
 
# Remove Documents icon from computer namespace
# Write-Host "Removing Documents icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
 
# Add Documents icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"
 
# Remove Downloads icon from computer namespace
# Write-Host "Removing Downloads icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue
 
# Add Downloads icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"
 
# Remove Music icon from computer namespace
# Write-Host "Removing Music icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
 
# Add Music icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"
 
# Remove Pictures icon from computer namespace
# Write-Host "Removing Pictures icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue
 
# Add Pictures icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"
 
# Remove Videos icon from computer namespace
# Write-Host "Removing Videos icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue
 
# Add Videos icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"
 
## Add secondary en-US keyboard
#Write-Host "Adding secondary en-US keyboard..."
#$langs = Get-WinUserLanguageList
#$langs.Add("en-US")
#Set-WinUserLanguageList $langs -Force
 
# Remove secondary en-US keyboard
Set-WinUserLanguageList En-US -Force
 
 
 
##########
# Remove unwanted applications
##########
Write-Progress -Activity "Removing Unwanted Apps" -Status "Progress:" -PercentComplete 1
# Disable OneDrive
Write-Host "Disabling OneDrive..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
 
# Enable OneDrive
# Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC"
 
# Uninstall OneDrive
Write-Host "Uninstalling OneDrive... May sometimes hang"
Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
Start-Sleep -s 3
$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
If (!(Test-Path $onedrive)) {
    $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
}
Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
Start-Sleep -s 3
Stop-Process -Name explorer -ErrorAction SilentlyContinue
Start-Sleep -s 3
Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
    Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
}
If (!(Test-Path "HKCR:")) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
 
# Install OneDrive
# $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
# If (!(Test-Path $onedrive)) {
#   $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
# }
# Start-Process $onedrive -NoNewWindow
 
# Uninstall Almost Everything.

# Get a list of all apps
$AppArrayList = Get-AppxPackage -PackageTypeFilter Bundle | Select-Object -Property Name, PackageFullName | Sort-Object -Property Name
 
# Start a log file for apps removed successfully from OS.
$Location = "C:\Windows\Logs\Software"
If((Test-Path $Location) -eq $False) {
new-item -path C:\Windows\Logs\Software -ItemType Directory
}
get-date | Out-File -append C:\Windows\Logs\Software\OSDRemovedApps.txt
 
# Loop through the list of apps
foreach ($App in $AppArrayList) {
# Exclude essential Windows apps
if (($App.Name -in "Microsoft.WindowsCalculator","Microsoft.WindowsStore","Microsoft.Appconnector","Microsoft.WindowsSoundRecorder","Microsoft.WindowsAlarms","Microsoft.MicrosoftStickyNotes")) {
Write-Output -InputObject "Skipping essential Windows app: $($App.Name)"
}
# Remove AppxPackage and AppxProvisioningPackage
else {
# Gather package names
$AppPackageFullName = Get-AppxPackage -Name $App.Name | Select-Object -ExpandProperty PackageFullName
$AppProvisioningPackageName = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $App.Name } | Select-Object -ExpandProperty PackageName
# Attempt to remove AppxPackage
try {
Write-Output -InputObject "Removing AppxPackage: $AppPackageFullName"
# Write the name of the removed apps to a logfile
$AppProvisioningPackageName | Out-File -append C:\Windows\Logs\Software\OSDRemovedApps.txt
Remove-AppxPackage -Package $AppPackageFullName -ErrorAction Stop
}
catch [System.Exception] {
Write-Warning -Message $_.Exception.Message
}
# Attempt to remove AppxProvisioningPackage
try {
Write-Output -InputObject "Removing AppxProvisioningPackage: $AppProvisioningPackageName"
Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -ErrorAction Stop
}
catch [System.Exception] {
Write-Warning -Message $_.Exception.Message
}
}
}

Write-Progress -Activity "Installing Wanted Apps" -Status "Progress:" -PercentComplete 1
# Install default Microsoft applications..
Write-Host "Installing desired packages"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.3DBuilder").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingFinance").InstallLocation)\AppXManifest.xml"
Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingNews").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingSports").InstallLocation)\AppXManifest.xml"
Write-Progress -Activity "Installing Wanted Apps" -Status "Progress:" -PercentComplete 15
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingWeather").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Getstarted").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.MicrosoftOfficeHub").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Office.OneNote").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.People").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.SkypeApp").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Windows.Photos").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsAlarms").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsCamera").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.windowscommunicationsapps").InstallLocation)\AppXManifest.xml"
Write-Progress -Activity "Installing Wanted Apps" -Status "Progress:" -PercentComplete 30
Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsCalculator").InstallLocation)\AppXManifest.xml"
Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsStore").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsMaps").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsPhone").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsSoundRecorder").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.XboxApp").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ZuneMusic").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ZuneVideo").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.AppConnector").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ConnectivityStore").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Office.Sway").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Messaging").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.CommsPhone").InstallLocation)\AppXManifest.xml"
Write-Progress -Activity "Installing Wanted Apps" -Status "Progress:" -PercentComplete 45
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "9E2F88E3.Twitter").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "king.com.CandyCrushSodaSaga").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "4DF9E0F8.Netflix").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Drawboard.DrawboardPDF").InstallLocation)\AppXManifest.xml"
Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.MicrosoftStickyNotes").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.OneConnect").InstallLocation)\AppXManifest.xml"
Write-Progress -Activity "Installing Wanted Apps" -Status "Progress:" -PercentComplete 60
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "D52A8D61.FarmVille2CountryEscape").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "GAMELOFTSA.Asphalt8Airborne").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsFeedbackHub").InstallLocation)\AppXManifest.xml"
# In case you have removed them for good, you can try to restore the files using installation medium as follows
# New-Item C:\Mnt -Type Directory | Out-Null
# dism /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mnt
# robocopy /S /SEC /R:0 "C:\Mnt\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
# dism /Unmount-Image /Discard /MountDir:C:\Mnt
# Remove-Item -Path C:\Mnt -Recurse
Write-Progress -Activity "Installing Wanted Apps" -Status "Progress:" -PercentComplete 75

#Install .net
Dism /online /Enable-feature /featurename:NetFx3 /All
Get-AppxPackage -allusers Microsoft.NET.* | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register “$($_.InstallLocation)\AppXManifest.xml”}


# Disable Xbox DVR
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null (fix this)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

# Enable Xbox DVR
# New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
# Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue

# Uninstall Windows Media Player
# Write-Host "Uninstalling Windows Media Player..."
# dism /online /Disable-Feature /FeatureName:MediaPlayback /Quiet /NoRestart
 
# Install Windows Media Player
# dism /online /Enable-Feature /FeatureName:MediaPlayback /Quiet /NoRestart
 
# Uninstall Work Folders Client
Write-Host "Uninstalling Work Folders Client..."
dism /online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart
 
# Install Work Folders Client
# dism /online /Enable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart
Write-Progress -Activity "Installing Wanted Apps" -Status "Progress:" -PercentComplete 100

# Set Photo Viewer as default for bmp, gif, jpg and png
Write-Host "Setting Photo Viewer as default for bmp, gif, jpg, png and tif..."
If (!(Test-Path "HKCR:")) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
    New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
    New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
    Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
    Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
}
 
# Remove or reset default open action for bmp, gif, jpg and png
If (!(Test-Path "HKCR:")) {
  New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
Remove-Item -Path "HKCR:\Paint.Picture\shell\open" -Recurse
Remove-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "MuiVerb"
Set-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "CommandId" -Type String -Value "IE.File"
Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "(Default)" -Type String -Value "`"$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe`" %1"
Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "DelegateExecute" -Type String -Value "{17FE9752-0B5A-4665-84CD-569794602F5C}"
Remove-Item -Path "HKCR:\jpegfile\shell\open" -Recurse
Remove-Item -Path "HKCR:\pngfile\shell\open" -Recurse

# Show Photo Viewer in "Open with..."
Write-Host "Showing Photo Viewer in `"Open with...`""
If (!(Test-Path "HKCR:")) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
 
# Remove Photo Viewer from "Open with..."
# If (!(Test-Path "HKCR:")) {
#   New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
# }
# Remove-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Recurse
 
# Enable F8 boot menu options
# Write-Host "Enabling F8 boot menu options..."
# bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null

# Disable F8 boot menu options
# bcdedit /set `{current`} bootmenupolicy Standard | Out-Null

# Install Powershell man pages locally (low priority, uses bandwidth)
# Update-Help

Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 1
# Install Packages to edit Hosts file.
Write-Host "Installing PsHosts CMDlet to edit hosts file. Please be Patient. This may be slow sometimes buggy"
install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 10
Write-Host "Seting up Repository"
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 20
Write-Host "Installing PSHosts Module"
install-module PsHosts
Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 30
Write-Host "Importing PSHosts Module"
import-module PsHosts
Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 40
# Hosts to block are below
Write-Host "Editing Hosts File..."
Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 50
# Clean old Hosts file
Remove-HostEntry *

# Add Hosts Entries
Add-HostEntry vortex.data.microsoft.com 127.0.0.1
Add-HostEntry vortex-win.data.microsoft.com 127.0.0.1
Add-HostEntry telecommand.telemetry.microsoft.com 127.0.0.1
Add-HostEntry telecommand.telemetry.microsoft.com.nsatc.net 127.0.0.1
Add-HostEntry oca.telemetry.microsoft.com 127.0.0.1
Add-HostEntry oca.telemetry.microsoft.com.nsatc.net 127.0.0.1
Add-HostEntry sqm.telemetry.microsoft.com 127.0.0.1
Add-HostEntry sqm.telemetry.microsoft.com.nsatc.net 127.0.0.1
Add-HostEntry watson.telemetry.microsoft.com 127.0.0.1
Add-HostEntry watson.telemetry.microsoft.com.nsatc.net 127.0.0.1
Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 60
Add-HostEntry redir.metaservices.microsoft.com 127.0.0.1
Add-HostEntry choice.microsoft.com 127.0.0.1
Add-HostEntry choice.microsoft.com.nsatc.net 127.0.0.1
Add-HostEntry df.telemetry.microsoft.com 127.0.0.1
Add-HostEntry reports.wes.df.telemetry.microsoft.com 127.0.0.1
Add-HostEntry wes.df.telemetry.microsoft.com 127.0.0.1
Add-HostEntry services.wes.df.telemetry.microsoft.com 127.0.0.1
Add-HostEntry sqm.df.telemetry.microsoft.com 127.0.0.1
Add-HostEntry telemetry.microsoft.com 127.0.0.1
Add-HostEntry watson.ppe.telemetry.microsoft.com 127.0.0.1
Add-HostEntry telemetry.appex.bing.net 127.0.0.1
Add-HostEntry telemetry.urs.microsoft.com 127.0.0.1
Add-HostEntry telemetry.appex.bing.net:443 127.0.0.1
Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 70
Add-HostEntry settings-sandbox.data.microsoft.com 127.0.0.1
Add-HostEntry vortex-sandbox.data.microsoft.com 127.0.0.1
Add-HostEntry survey.watson.microsoft.com 127.0.0.1
Add-HostEntry watson.live.com 127.0.0.1
Add-HostEntry watson.microsoft.com 127.0.0.1
Add-HostEntry statsfe2.ws.microsoft.com 127.0.0.1
Add-HostEntry corpext.msitadfs.glbdns2.microsoft.com 127.0.0.1
Add-HostEntry compatexchange.buttapp.net 127.0.0.1
Add-HostEntry cs1.wpc.v0cdn.net 127.0.0.1
Add-HostEntry a-0001.a-msedge.net 127.0.0.1
Add-HostEntry statsfe2.update.microsoft.com.akadns.net 127.0.0.1
Add-HostEntry sls.update.microsoft.com.akadns.net 127.0.0.1
Add-HostEntry fe2.update.microsoft.com.akadns.net 127.0.0.1
Add-HostEntry diagnostics.support.microsoft.com 127.0.0.1
Add-HostEntry corp.sts.microsoft.com 127.0.0.1
Add-HostEntry statsfe1.ws.microsoft.com 127.0.0.1
Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 75
Add-HostEntry pre.footprintpredict.com 127.0.0.1
Add-HostEntry i1.services.social.microsoft.com 127.0.0.1
Add-HostEntry i1.services.social.microsoft.com.nsatc.net 127.0.0.1
Add-HostEntry feedback.windows.com 127.0.0.1
Add-HostEntry feedback.microsoft-hohm.com 127.0.0.1
Add-HostEntry feedback.search.microsoft.com 127.0.0.1
Add-HostEntry ad.doubleclick.net 127.0.0.1
Add-HostEntry ads.msn.com 127.0.0.1
Add-HostEntry ads1.msads.net 127.0.0.1
Add-HostEntry ads1.msn.com 127.0.0.1
Add-HostEntry a.ads1.msn.com 127.0.0.1
Add-HostEntry a.ads2.msn.com 127.0.0.1
Add-HostEntry adnexus.net 127.0.0.1
Add-HostEntry adnxs.com 127.0.0.1
Add-HostEntry aidps.atdmt.com 127.0.0.1
Add-HostEntry apps.skype.com 127.0.0.1
Add-HostEntry az361816.vo.msecnd.net 127.0.0.1
Add-HostEntry az512334.vo.msecnd.net 127.0.0.1
Add-HostEntry a.rad.msn.com 127.0.0.1
Add-HostEntry a.ads2.msads.net 127.0.0.1
Add-HostEntry ac3.msn.com 127.0.0.1
Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 80
Add-HostEntry aka-cdn-ns.adtech.de 127.0.0.1
Add-HostEntry b.rad.msn.com 127.0.0.1
Add-HostEntry b.ads2.msads.net 127.0.0.1
Add-HostEntry b.ads1.msn.com 127.0.0.1
Add-HostEntry bs.serving-sys.com 127.0.0.1
Add-HostEntry c.msn.com 127.0.0.1
Add-HostEntry cdn.atdmt.com 127.0.0.1
Add-HostEntry cds26.ams9.msecn.net 127.0.0.1
Add-HostEntry c.atdmt.com 127.0.0.1
Add-HostEntry db3aqu.atdmt.com 127.0.0.1
Add-HostEntry ec.atdmt.com 127.0.0.1
Add-HostEntry flex.msn.com 127.0.0.1
Add-HostEntry g.msn.com 127.0.0.1
Add-HostEntry h2.msn.com 127.0.0.1
Add-HostEntry h1.msn.com 127.0.0.1
Add-HostEntry live.rads.msn.com 127.0.0.1
Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 85
Add-HostEntry msntest.serving-sys.com 127.0.0.1
Add-HostEntry m.adnxs.com 127.0.0.1
Add-HostEntry m.hotmail.com 127.0.0.1
Add-HostEntry preview.msn.com 127.0.0.1
Add-HostEntry pricelist.skype.com 127.0.0.1
Add-HostEntry rad.msn.com 127.0.0.1
Add-HostEntry rad.live.com 127.0.0.1
Add-HostEntry secure.flashtalking.com 127.0.0.1
Add-HostEntry static.2mdn.net 127.0.0.1
Add-HostEntry s.gateway.messenger.live.com 127.0.0.1
Add-HostEntry secure.adnxs.com 127.0.0.1
Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 90
Add-HostEntry sO.2mdn.net 127.0.0.1
Add-HostEntry ui.skype.com 127.0.0.1
Add-HostEntry view.atdmt.com 127.0.0.1
# The Below two domains may impact your network connectivity detection.
Add-HostEntry www.msftncsi.com 127.0.0.1
Add-HostEntry msftncsi.com 127.0.0.1

Write-Progress -Activity "Editing Hosts File" -Status "Progress:" -PercentComplete 100

# Edit Group Policy to set Chrome settings that cannot be set through registry.
# Refer to https://www.powershellgallery.com/packages/PolicyFileEditor/2.0.2
Write-Host "Installing PolicyFileEditor Module"
Install-Module -Name PolicyFileEditor

Write-Host "Importing PolicyFileEditor Module"
import-module -Name PolicyFileEditor

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

Write-Host "Setting Chrome Settings..."

$MachineDir = "$env:systemroot\system32\GroupPolicy\Machine\registry.pol"
$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'AutoFillEnabled'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'HomepageLocation'
$RegData = 'https://www.google.com'
$RegType = 'String'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'ProxyServerMode'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'SafeBrowsingEnabled'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'SavingBrowserHistoryDisabled'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'SearchSuggestEnabled'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'SyncDisabled'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'MetricsReportingEnabled'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

# Use * to disable all plugins in place of DISABLEDPLUGINID
# To add more than one disabled plugin, copy the 5 lines below and mark the regname as 2..3..4..5 and so on after re-pasting.
$RegPath = 'Software\Policies\Google\Chrome\DisabledPlugins'
$RegName = '1'
$RegData = 'DISABLEDPLUGINID'
$RegType = 'String'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

# Use * to disable all extensions in place of DISABLEDEXTENSIONID
# To add more than one disabled extension, copy the 5 lines below and mark the regname as 2..3..4..5 and so on after re-pasting.
$RegPath = 'Software\Policies\Google\Chrome\ExtensionInstallBlacklist'
$RegName = '1'
$RegData = 'DISABLEDEXTENSIONID'
$RegType = 'String'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

# Use * to ENABLE all extensions in place of ENABLEDEXTENSIONID
# To add more than one enabled extension, copy the 5 lines below and mark the regname as 2..3..4..5 and so on after re-pasting.
$RegPath = 'Software\Policies\Google\Chrome\ExtensionInstallWhitelist'
$RegName = '1'
$RegData = 'ENABLEDEXTENSIONID'
$RegType = 'String'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

# Use the below to blacklist URLs in chrome. You could probably use * to blacklist everything.
# To add more than one URL, copy the 5 lines below and append regname with the next number in the list.. 2..3..4..5 and so on.
$RegPath = 'Software\Policies\Google\Chrome\URLBlacklist'
$RegName = '1'
$RegData = 'www.tacos.com'
$RegType = 'String'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

# Use the below to whitelist URLs in chrome.
# To add more than one URL, copy the 5 lines below and append regname with the next number in the list.. 2..3..4..5 and so on.
$RegPath = 'Software\Policies\Google\Chrome\URLWhitelist'
$RegName = '1'
$RegData = '*'
$RegType = 'String'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

# Use the below to make a list of forced installed extensions, This will also delete any values to remove any rogue extensions as a security feature if they are within the
# list of 1-10 in the policy.
# To add more than one force installed extension, copy the 5 lines below and mark the regname as 2..3..4..5 and so on after re-pasting.
$RegPath = 'Software\Policies\Google\Chrome\ExtensionInstallForcelist'
$RegName = '1'
$RegData = 'EXTENSIONID'
$RegType = 'String'
Remove-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName 1
Remove-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName 2
Remove-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName 3
Remove-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName 4
Remove-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName 5
Remove-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName 6
Remove-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName 7
Remove-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName 8
Remove-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName 9
Remove-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName 10
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'AllowOutdatedPlugins'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'BackgroundModeEnabled'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'BookmarkBarEnabled'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'DefaultBrowserSettingEnabled'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'DeveloperToolsDisabled'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'EnableMediaRouter'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'ForceGoogleSafeSearch'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'FullscreenAllowed'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'NetworkPredictionOptions'
$RegData = '2'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'SafeBrowsingEnabled'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'SafeBrowsingExtendedReportingOptInAllowed'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'SearchSuggestEnabled'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'SpellCheckServiceEnabled'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'SSLVersionMin'
$RegData = 'tls1'
$RegType = 'String'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Google\Chrome'
$RegName = 'WelcomePageOnOSUpgradeEnabled'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

# End Chrome GP Settings
#
# Begin Adobe Acrobat/Reader DC Settings
$RegPath = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
$RegName = 'bProtectedMode'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
$RegName = 'bUsageMeasurement'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cIPM'
$RegName = 'bDontShowMsgWhenViewingDoc'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cIPM'
$RegName = 'bShowMsgAtLaunch'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown'
$RegName = 'bUsageMeasurement'
$RegData = '1'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown'
$RegName = 'iProtectedView'
$RegData = '2'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

$RegPath = 'Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cIPM'
$RegName = 'bShowMsgAtLaunch'
$RegData = '0'
$RegType = 'DWord'
Set-PolicyFileEntry -Path $MachineDir -Key $RegPath -ValueName $RegName -Data $RegData -Type $RegType

# End Adobe Acrobat and Reader DC Settings
#

# Force DEP to always on for every application (available options are: AlwaysOff, AlwaysOn, OptIn, OptOut)
Write-Host "Turning on DEP for all applications."
bcdedit /set nx AlwaysON

# Enable SEHOP (Exception write-protection function of DEP.)
Write-Host "Enable Exception Write-Protection SEHOP"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 0 /f

# Check Cryptography Protection
Write-Host "Checking Cryptography Protection."

# If the following query shows that MasterKeyLegacyCompliance is set to a non-zero number,
# then it is bad sign that hackers or malware have set this value deliberately to weaken
# the security of DPAPI-protected secrets like cached passwords or private keys.
reg query HKLM\SOFTWARE\Microsoft\Cryptography\Protect\Providers\df9d8cd0-1501-11d1-8c7a-00c04fc297eb /v MasterKeyLegacyCompliance

# Run the following command to delete the MasterKeyLegacyCompliance value, which
# is the default on Windows XP and later, and is best for security.
reg delete HKLM\SOFTWARE\Microsoft\Cryptography\Protect\Providers\df9d8cd0-1501-11d1-8c7a-00c04fc297eb /v MasterKeyLegacyCompliance /f

# Disable NetBios (Forces File Sharing over port 445 DirectSMB/stops various worms.)
Write-Host "Disabling Outdated NetBIOS Protocol..."
sc.exe config netbt start= disabled 

# Reset NerBios Configuration to Default.
# sc.exe config netbt start= system

# Set LAN connection to DHCP and renew.
# netsh.exe int ip set address "Local Area Connection" dhcp
# netsh.exe int ip set dns "Local Area Connection" dhcp
# ipconfig /renew

# Set LAN connection to static and release.
# ipconfig /release
# netsh.exe int ip set dns "Local Area Connection" static 10.4.1.1 
# netsh.exe int ip set address "Local Area Connection" static 10.4.1.1 255.255.0.0 

# Enable IPsec NAT
Write-Host "Enabling IPSec NAT..."
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent" /v AssumeUDPEncapsulationContextOnSendRule /t REG_DWORD /d 00000002 /f

# Use these commands to audit logging policies.
# auditpol.exe /get /category:*
# auditpol.exe /get /subcategory:"MPSSVC rule-level Policy Change,Filtering Platform policy change,IPsec Main Mode,IPsec Quick Mode,IPsec Extended Mode,IPsec Driver,Other System Events,Filtering Platform Packet Drop,Filtering Platform Connection"

# Disable a lot of security logging (See end of command)
# auditpol.exe /set /subcategory:"MPSSVC rule-level Policy Change,Filtering Platform policy change,IPsec Main Mode,IPsec Quick Mode,IPsec Extended Mode,IPsec Driver,Other System Events,Filtering Platform Packet Drop,Filtering Platform Connection" /success:Disable /failure:Disable

# Enable a lot of security logging (See end of command)
auditpol.exe /set /subcategory:"MPSSVC rule-level Policy Change,Filtering Platform policy change,IPsec Main Mode,IPsec Quick Mode,IPsec Extended Mode,IPsec Driver,Other System Events,Filtering Platform Packet Drop,Filtering Platform Connection" /success:Enable /failure:Enable

# Enable oakley IPSec Diagnostics logging.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent\Oakley" /v EnableLogging /t REG_DWORD /d 00000001 /f

# Enable Local IPSec Connections for ports 3389,135,139,445,21,20,23
Write-Host "Enabling Local Network IPSEC on this machine if supported."
netsh.exe advfirewall consec add rule name=Testing-IPSec-NETSH endpoint1=any port1=any endpoint2=localsubnet port2=3389,135,139,445,21,20,23 protocol=tcp profile=any action=requireinrequestout interfacetype=any auth1=computerpsk auth1psk=$ThePreSharedKey enable=yes

# Disable Local IPSec Connections for ports 3389,135,139,445,21,20,23
# Write-Host "Disabling Local Network IPSEC on this machine if supported."
# netsh.exe advfirewall consec add rule name=Testing-IPSec-NETSH endpoint1=any port1=any endpoint2=localsubnet port2=3389,135,139,445,21,20,23 protocol=tcp profile=any action=requireinrequestout interfacetype=any auth1=computerpsk auth1psk=$ThePreSharedKey enable=no

Write-Progress -Activity "Configuring SSL/TLS" -Status "Progress:" -PercentComplete 1
#
# 
# The Two Lines Below Enable Superfectch and Prefetch
Write-Host "Enabling Superfetch and Prefetch..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 00000003 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 00000003 /f

# The Lines Below Disable SSL!!!
Write-Host "Disabling SSL..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v Enabled /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v Enabled /t REG_DWORD /d 00000000 /f
Write-Progress -Activity "Configuring SSL/TLS" -Status "Progress:" -PercentComplete 25
# The Lines Below Force And Enable TLS!!!
Write-Host "Forcing and Enabling TLS!!!"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v DisabledByDefault /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v DisabledByDefault /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v DisabledByDefault /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v DisabledByDefault /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
Write-Progress -Activity "Configuring SSL/TLS" -Status "Progress:" -PercentComplete 70
# The Registry Parameters Below are for TCP Security, I'm not sure what some of them do.
Write-Host "Upgrading TCP Security..."
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IPEnableRouter /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v SynAttackProtect /t REG_DWORD /d 00000002 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpen /t REG_DWORD /d 00000064 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpenRetried /t REG_DWORD /d 00000050 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 00000002 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableDeadGWDetect /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v KeepAliveTime /t REG_DWORD /d 0x000493E0 /f
Write-Progress -Activity "Configuring SSL/TLS" -Status "Progress:" -PercentComplete 100
# Disable NTFS Last-Access Timestamp
# Write-Host "Disabling NTFS Last-Access Timestamps..."
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 00000001 /f

# Enable NTFS Last-Access Timestamp
Write-Host "Enabling NTFS Last-Access Timestamps..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 00000000 /f

# Disable IPV6
Write-Host "Disabling IPV6..."
reg add "HKLM\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xffffffff /f

# Enable IPV6
# Write-Host "EnTabling IPV6..."
# reg add "HKLM\SYSEM\CurrentControlSet\services\TCPIP6\Parameters" /v DisabledComponents /t REG_DWORD /d 0 /f

# Force High Level of Remote Desktop Encryption and TLS Authentication.
Write-Host "Requiring Strong Remote Desktop Encryption if enabled... And forcing TLS Authentication"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel /t REG_DWORD /d 00000003 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 00000002 /f

# Disabling TCP/IP AutoTuning (see http://technet.microsoft.com/en-us/magazine/2007.01.cableguy.aspx)
Write-Host "Disabling TCP/IP Auto-Tuning..."
netsh.exe interface tcp set global autotuninglevel= disabled

# Enabling TCP/IP AutoTuning
# netsh.exe interface tcp set global autotuninglevel= normal

# Reset Firewall To factory Defaults!!!
# netsh.exe firewall reset
#



# Begin Java Security Setting Script
#
#

Write-host "The next bit of code will either enable or disable java system-wide."

# Construct the strings for the deployment.properties file.
# Be mindful of the below property, setting webjava to false will unisntall java and you will need to manually re-enable in IE.

$propertiesfile = "deployment.webjava.enabled=true "

# Default to locking the security level and browser plug-in state, i.e., they are visible but greyed out in Java Control Panel.
$propertiesfile += "`ndeployment.webjava.enabled.locked `ndeployment.security.level.locked "

# Default to security level being set to VERY_HIGH (see Security tab of Java Control Panel).
$propertiesfile += "`ndeployment.security.level=VERY_HIGH" 


# Possibly delete the configuration files and exit, but leave the folder alone though.
write-host "Deleting system-wide Java configuration files, if they exist..."
remove-item $env:WinDir\Sun\Java\Deployment\deployment.config -Force
remove-item $env:WinDir\Sun\Java\Deployment\deployment.properties -Force
        


# Create the $env:WinDir\Sun\Java\Deployment folder for the system-wide Java configuration files.
New-Item -Path $env:WinDir\Sun\Java\Deployment -ItemType Directory -Force | Out-Null

# Create the deployment.config file.
"deployment.system.config=$env:WinDir\Sun\Java\Deployment\deployment.properties" | 
    Out-File -FilePath $env:WinDir\Sun\Java\Deployment\deployment.config -Force -Encoding ASCII
if (-not $? -or -not $(Test-Path $env:WinDir\Sun\Java\Deployment\deployment.config))
   { "`nCould not create the deployment.config file, exiting.`n" ; exit -1 } 


# Create the deployment.properties file.
$propertiesfile | Out-File -FilePath $env:WinDir\Sun\Java\Deployment\deployment.properties -Force -Encoding ASCII
if (-not $? -or -not $(Test-Path $env:WinDir\Sun\Java\Deployment\deployment.properties))
   { "`nCould not create the deployment.properties file, exiting.`n" ; exit -1 } 


# Show system-wide deployment.properties file contents FYI.
"`nCurrent contents of the deployment.properties file:`n"
get-content $env:WinDir\Sun\Java\Deployment\deployment.properties ; "`n"



# Run latest ssvagent.exe for both x86 and x64, but not on Java Platform 6 or earlier, and 
# hope future Javas support these switches (man, what a mess, doomed to rewrites...):
if ($propertiesfile -like '*deployment.webjava.enabled=false*')
{
    # Try the x64 version, if any:
    $ssvagent = $null
    if (Test-Path -Path "$env:ProgramFiles\Java\")
    {
        $ssvagent = dir "$env:ProgramFiles\Java\*.exe" -Recurse | 
                where { $_.name -eq 'ssvagent.exe' -and $_.fullname -notmatch '\\jre[1-6]\\'} | 
                sort LastWriteTimeUtc -desc | select -first 1 
    }

    if ($ssvagent -ne $null) 
    { 
        $expression = $ssvagent.FullName.Replace("Program Files","'Program Files'") + " -disablewebjava"
        "Executing: $expression `n"
        invoke-expression -command $expression
    }


    # Now for the x86 version second, because this is the Oracle-preferred:
    $ssvagent = $null
    if (Test-Path -Path "${env:ProgramFiles(x86)}\Java\")
    {
        $ssvagent = dir "${env:ProgramFiles(x86)}\Java\*.exe" -Recurse | 
                where { $_.name -eq 'ssvagent.exe' -and $_.fullname -notmatch '\\jre[1-6]\\'} | 
                sort LastWriteTimeUtc -desc | select -first 1 
    }

    if ($ssvagent -ne $null) 
    { 
        $expression = $ssvagent.FullName.Replace("Program Files (x86)","'Program Files (x86)'") + " -disablewebjava"
        "Executing: $expression `n"
        invoke-expression -command $expression
    }
}
elseif ($propertiesfile -like '*deployment.webjava.enabled=true*')
{
    # Try the x64 version, if any:
    $ssvagent = $null
    $ssvagent = dir "$env:ProgramFiles\Java\*.exe" -Recurse | 
                where { $_.name -eq 'ssvagent.exe' -and $_.fullname -notmatch '\\jre[1-6]\\'} | 
                sort LastWriteTimeUtc -desc | select -first 1 
    if ($ssvagent -ne $null) 
    { 
        $expression = $ssvagent.FullName.Replace("Program Files","'Program Files'") + " -forceinstall -register -new -high"  #Only -high exists?
        "Executing: $expression `n"
        invoke-expression -command $expression
    }

    # Now for the x86 version second, to let it possibly overwrite x64 settings, since x86 is Oracle-preferred:
    $ssvagent = $null
    $ssvagent = dir "${env:ProgramFiles(x86)}\Java\*.exe" -Recurse | 
                where { $_.name -eq 'ssvagent.exe' -and $_.fullname -notmatch '\\jre[1-6]\\'} | 
                sort LastWriteTimeUtc -desc | select -first 1 
    if ($ssvagent -ne $null) 
    { 
        $expression = $ssvagent.FullName.Replace("Program Files (x86)","'Program Files (x86)'") + " -forceinstall -register -new -high"  #Only -high exists?
        "Executing: $expression `n"
        invoke-expression -command $expression
    }
}

# End Java Security Settings Script
#
#

# Disable scheduled tasks

Write-Progress -Activity "Disabling scheduled tasks" -Status "Progress:" -PercentComplete 0
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
Write-Progress -Activity "Disabling scheduled tasks" -Status "Progress:" -PercentComplete 25
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
Write-Progress -Activity "Disabling scheduled tasks" -Status "Progress:" -PercentComplete 50
# Network stuff
schtasks /Change /TN "Microsoft\Windows\NetCfg\BindingWorkItemQueueHandler" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
Write-Progress -Activity "Disabling scheduled tasks" -Status "Progress:" -PercentComplete 75
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
# Maintenanace Tasks
# schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
# schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
# schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
# schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
# schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
# schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
# schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
# schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
# schtasks /Change /TN "Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /Disable
Write-Progress -Activity "Disabling scheduled tasks" -Status "Progress:" -PercentComplete 80
# Smartscreen
# schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
# Defender
# schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
# schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
# schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
# schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

# Some random scheduled task that is alittle fishy but halts the script
# Unregister-ScheduledTask -TaskName BackgroundUploadTask -Confirm:$false

Write-Progress -Activity "Disabling scheduled tasks" -Status "Progress:" -PercentComplete 100


Write-Progress -Activity "Disabling services" -Status "Progress:" -PercentComplete 0
cmd /c sc config DiagTrack start= disabled | out-null
cmd /c sc config dmwappushservice start= disabled | out-null
cmd /c sc config diagnosticshub.standardcollector.service start= disabled | out-null
cmd /c sc config TrkWks start= disabled | out-null
cmd /c sc config WMPNetworkSvc start= disabled | out-null # Shouldn't exist but just making sure ...
# Making sure the DiagTrack log is empty (tinfoil)
Set-Content C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl -Value "" -Force
Write-Progress -Activity "Disabling services" -Status "Progress:" -PercentComplete 100

# Tweak settings app
Write-Progress -Activity "Tweaking settings app" -Status "Progress:" -PercentComplete 0
# Privacy -> General -> let websites provide locally relevant content by accessing my language list
Remove-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Internet Explorer\International" -Name "AcceptLanguage" -Force
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Value 1 | Out-Null
# Privacy -> General -> turn on smartscreen filter to check web content that windows store apps use
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\" -Name EnableWebContentEvaluation -Value 0 -Force | Out-Null
# Privacy -> Camera -> let apps use my camera
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -Name "Value" -Type String -Value "Deny" | Out-Null
# Privacy -> Microphone -> let apps use my microphone
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}\" -Name "Value" -Type String -Value "Deny" | Out-Null
# Privacy -> Account info -> let apps access my name, picture and other account info
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}\" -Name "Value" -Type String -Value "Deny" | Out-Null
# Privacy -> Calendar -> let apps access my calendar
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}\" -Name "Value" -Type String -Value "Deny" | Out-Null
# Privacy -> Messaging -> let apps read or send sms and text messages
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}\" -Name "Value" -Type String -Value "Deny" | Out-Null
# Privacy -> Radio -> let apps control radios
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}\" -Name "Value" -Type String -Value "Deny" | Out-Null
# Privacy -> Other devices -> sync with devices
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled\" -Name "Value" -Type String -Value "Deny" | Out-Null
# Privacy -> Feedback & Diagnostics -> feedback frequency
New-Item -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:SOFTWARE\Microsoft\Siuf\Rules" -Name NumberOfSIUFInPeriod -Value 0 -Force | Out-Null
Remove-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Siuf\Rules" -Name PeriodInNanoSeconds
# Ease of Access -> Other options -> Visual options -> play animations
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:Control Panel\Desktop\WindowMetrics" -Name MinAnimate -Value 0 | Out-Null
# Update & Security -> Windows Update -> Advanced -> Choose how updates are delviered -> Updates from more than one place (this is a GUI bug, registry is set properly even though it may show 'ON')
New-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DownloadMode" -PropertyType DWORD -Value 0 | Out-Null
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0 | Out-Null
Set-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\" -Name "SystemSettingsDownloadMode" -Value 0 | Out-Null
Write-Progress -Activity "Tweaking settings app" -Status "Progress:" -PercentComplete 100

#
#
# More Group Policy Tweaks

Write-Progress -Activity "Securing local group policy for privacy (this might take a minute or two)" -Status "Progress:" -PercentComplete 1
# The reason I'm waiting 1s after each edit is to let the filesystem make necessary edits in the background, without the delay this will break local policies
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName AllowTelemetry -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" -ValueName TurnOffSidebar -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" -ValueName NoActiveHelp -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Biometrics" -ValueName Enabled -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Conferencing" -ValueName NoRDS -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\InputPersonalization" -ValueName AllowInputPersonalization -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" -ValueName PolicyDisableGeolocation -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -ValueName NoUpdateCheck -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName DoNotTrack -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" -ValueName EnableInPrivateBrowsing -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -ValueName DisableCustomerImprovementProgram -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName CEIP -Type DWord -Data 2
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Messenger\Client" -ValueName PreventAutoRun -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -ValueName Cookies -Type DWord -Data 2
Start-Sleep 1
Write-Progress -Activity "Securing local group policy for privacy (this might take a minute or two)" -Status "Progress:" -PercentComplete 10
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -ValueName DoReport -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -ValueName ForceQueueMode -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName DWFileTreeRoot -Type String -Data ""
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName DWNoExternalURL -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName DWNoFileCollection -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName DWNoSecondLevelCollection -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" -ValueName DWReporteeName -Type String -Data ""
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\SearchCompanion" -ValueName DisableContentFileUpdates -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\SQMClient\Windows" -ValueName CEIPEnable -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0080000000F0000F0D0B4EB5D3C24F17D10AE531C7DCEF4A94F4A085AD0D4C88B75082573E36F857A" -ValueName Category -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0080000000F0000F0D0B4EB5D3C24F17D10AE531C7DCEF4A94F4A085AD0D4C88B75082573E36F857A" -ValueName CategoryReadOnly -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -ValueName NoGenTicket -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\IIS" -ValueName PreventIISInstall -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -ValueName PhysicalLocation -Type String -Data anonymous
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -ValueName DisabledByGroupPolicy -Type DWord -Data 1
Start-Sleep 1
Write-Progress -Activity "Securing local group policy for privacy (this might take a minute or two)" -Status "Progress:" -PercentComplete 20
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ValueName AITEnable -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ValueName DisableInventory -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\AppCompat" -ValueName DisableUAR -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -ValueName PreventDeviceMetadataFromNetwork -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -ValueName DisableSendGenericDriverNotFoundToWER -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -ValueName DisableSendRequestAdditionalSoftwareToWER -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName NoUseStoreOpenWith -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\GameUX" -ValueName DownloadGameInfo -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\GameUX" -ValueName GameUpdateOptions -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\GameUX" -ValueName ListRecentlyPlayed -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -ValueName ExitOnMSICW -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -ValueName DisableLocation -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\OneDrive" -ValueName DisableFileSyncNGSC -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PowerShell" -ValueName EnableScripts -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PowerShell" -ValueName ExecutionPolicy -Type String -Data "RemoteSigned"
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ValueName **del.EnableExperimentation -Type String -Data ""
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ValueName AllowBuildPreview -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ValueName EnableConfigFlighting -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName AsyncScriptDelay -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName EnableLogonScriptDelay -Type DWord -Data 1
Start-Sleep 1
Write-Progress -Activity "Securing local group policy for privacy (this might take a minute or two)" -Status "Progress:" -PercentComplete 50
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{186f47ef-626c-4670-800a-4a30756babad}" -ValueName ScenarioExecutionEnabled -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{2698178D-FDAD-40AE-9D3C-1371703ADC5B}" -ValueName **del.EnabledScenarioExecutionLevel -Type String -Data ""
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{2698178D-FDAD-40AE-9D3C-1371703ADC5B}" -ValueName ScenarioExecutionEnabled -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{67144949-5132-4859-8036-a737b43825d8}" -ValueName **del.EnabledScenarioExecutionLevel -Type String -Data ""
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{67144949-5132-4859-8036-a737b43825d8}" -ValueName ScenarioExecutionEnabled -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{86432a0b-3c7d-4ddf-a89c-172faa90485d}" -ValueName ScenarioExecutionEnabled -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -ValueName ScenarioExecutionEnabled -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{a7a5847a-7511-4e4e-90b1-45ad2a002f51}" -ValueName **del.EnabledScenarioExecutionLevel -Type String -Data ""
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{a7a5847a-7511-4e4e-90b1-45ad2a002f51}" -ValueName ScenarioExecutionEnabled -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{C295FBBA-FD47-46ac-8BEE-B1715EC634E5}" -ValueName ScenarioExecutionEnabled -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{dc42ff48-e40d-4a60-8675-e71f7e64aa9a}" -ValueName EnabledScenarioExecutionLevel -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{dc42ff48-e40d-4a60-8675-e71f7e64aa9a}" -ValueName ScenarioExecutionEnabled -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{ecfb03d1-58ee-4cc7-a1b5-9bc6febcb915}" -ValueName ScenarioExecutionEnabled -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{ffc42108-4920-4acf-a4fc-8abdcc68ada4}" -ValueName **del.EnabledScenarioExecutionLevel -Type String -Data ""
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WDI\{ffc42108-4920-4acf-a4fc-8abdcc68ada4}" -ValueName ScenarioExecutionEnabled -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName Disabled -Type DWord -Data 1
Start-Sleep 1
Write-Progress -Activity "Securing local group policy for privacy (this might take a minute or two)" -Status "Progress:" -PercentComplete 60
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ValueName DontSendAdditionalData -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName AllowCortana -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName AllowSearchToUseLocation -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName ConnectedSearchPrivacy -Type DWord -Data 3
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName ConnectedSearchSafeSearch -Type DWord -Data 3
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName ConnectedSearchUseWeb -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName ConnectedSearchUseWebOverMeteredConnections -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName DisableWebSearch -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName DeferUpgrade -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName DoNotConnectToWindowsUpdateInternetLocations -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName **del.AutomaticMaintenanceEnabled -Type String -Data ""
Start-Sleep 1
Write-Progress -Activity "Securing local group policy for privacy (this might take a minute or two)" -Status "Progress:" -PercentComplete 75
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName **del.DetectionFrequency -Type String -Data ""
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName AUOptions -Type DWord -Data 2
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName DetectionFrequencyEnabled -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName EnableFeaturedSoftware -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName NoAutoUpdate -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName ScheduledInstallDay -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName ScheduledInstallTime -Type DWord -Data 3
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\Machine\registry.pol -Key "SOFTWARE\Policies\Microsoft\WMDRM" -ValueName DisableOnline -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName NoInstrumentation -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Policies\Microsoft\Internet Explorer\Privacy" -ValueName EnableInPrivateBrowsing -Type DWord -Data 0
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -ValueName DisableLogging -Type DWord -Data 1
Start-Sleep 1
Set-PolicyFileEntry -Path $env:systemroot\system32\GroupPolicy\User\registry.pol -Key "Software\Policies\Microsoft\Windows\EdgeUI" -ValueName DisableMFUTracking -Type DWord -Data 1
gpupdate /force
Write-Progress -Activity "Securing local group policy for privacy (this might take a minute or two)" -Status "Progress:" -PercentComplete 100

# More Registry Tweaks
# Fix DPI scaling blurry/fuzzy display at 125% (Might get reset by reboot/windows update)
Write-Progress -Activity "More Registry Tweaks!" -Status "Progress:" -PercentComplete 5

New-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Control Panel\Desktop" -Name "DpiScalingVer" -Value "0x00001018" -PropertyType DWORD -Force
New-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Value "0x00000001" -PropertyType DWORD -Force
# This sets it to 125% DPI scaling, un-comment if you do need it (you use 125% dpi scaling)
# New-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Value "0x00000078" -PropertyType DWORD -Force

# Add a 'Take Owner' option in your right-click menu (Powershell has problems with '*', using reg.exe)

echo Y | reg add "HKEY_CLASSES_ROOT\*\shell\runas" /ve /t REG_SZ /d "Take Ownership" /f
echo Y | reg add "HKEY_CLASSES_ROOT\*\shell\runas" /v NoWorkingDirectory /t REG_SZ /d "" /f
echo Y | reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \`"%1\`" && icacls \`"%1\`" /grant administrators:F" /f
echo Y | reg add "HKEY_CLASSES_ROOT\*\shell\runas\command" /v IsolatedCommand /t REG_SZ /d "cmd.exe /c takeown /f \`"%1\`" && icacls \`"%1\`" /grant administrators:F" /f
Write-Progress -Activity "More Registry Tweaks!" -Status "Progress:" -PercentComplete 25
New-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas"
New-Item -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas\command"
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas" -Name '(Default)' -Value "Take Ownership"
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas" -Name NoWorkingDirectory -Value ""
Write-Progress -Activity "More Registry Tweaks!" -Status "Progress:" -PercentComplete 50
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas\command" -Name '(Default)' -Value "cmd.exe /c takeown /f `"%1`" /r /d y && icacls `"%1`" /grant administrators:F /t"
New-ItemProperty -ErrorAction SilentlyContinue -Force -Path "HKCR:\Directory\shell\runas\command" -Name IsolatedCommand -Value "cmd.exe /c takeown /f `"%1`" /r /d y && icacls `"%1`" /grant administrators:F /t"

# Show file extensions
New-ItemProperty -ErrorAction SilentlyContinue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -PropertyType DWORD -Value 0 -Force
Write-Progress -Activity "More Registry Tweaks!" -Status "Progress:" -PercentComplete 75



# Enabling .NET 3.5 framework because a lot of programs still use it
Dism /online /Enable-Feature /FeatureName:NetFx3 /quiet /norestart
Write-Progress -Activity "More Registry Tweaks!" -Status "Progress:" -PercentComplete 100

#
#
# Change Mac Menu




$Title = "Welcome"
$Info = "To Change Or Not Change Your Mac (May not support Hyper-V)"
 
$options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No", "&Quit")
[int]$defaultchoice = 1
$opt =  $host.UI.PromptForChoice($Title , $Info , $Options,$defaultchoice)
switch($opt)
{
0 {
#
#
# The Below Script Enable a random mac on wifi. This may not work on all computers!!! (Especially HYPER-V)

Write-Host "Enabling Random MAC address on WIFI!!! Please be patient... This may not work on all computers!!! (Especially HYPER-V)"
function random-mac ($ManufacturerName, $ManufacturerID, $Delimiter, [Switch] $TotallyRandom, [Switch] $LocallyAdministered, [Switch] $Multicast)
{   
	# $mac will be padded with random hex later, but add a random vendor ID by default.
    if ($TotallyRandom) { $mac = "" }  
	else
	{
		# First three bytes will come from the manufacturer ID number.
		# Some input checking of the manufacturer selection...
		if ($ManufacturerName -and $ManufacturerName.StartsWith("3")) { $ManufacturerName = "ThreeCom" } 
		if ($ManufacturerName -and $ManufacturerName.ToUpper().StartsWith("D-")) { $ManufacturerName = "DLink" }
		if ($ManufacturerID -and $ManufacturerID.ToString().length -gt 12) { $ManufacturerID = $ManufacturerID.ToString().SubString(0,12) } 
		
		# Manufacturer identifiers last updated on 5.Feb.2011:
		$vendor = @{
			"Netgear" = "0024B2 0026F2 30469A A021B7 C03F0E C43DC7 E0469A E091F5 000FB5 00146C 00184D 001B2F 001E2A 001F33 00223F 00095B" ;
			"DLink" = "00055D 000D88 000F3D 001195 001346 0015E9 00179A 00195B 001B11 001CF0 001E58 002191 0022B0 002401 00265A 0050BA 0080C8 14D64D 1CAFF7 1CBDB9 340804 5CD998 F07D68" ;
			"ThreeCom" = "000102 000103 00029C 00040B 00051A 00068C 000A04 000A5E 000BAC 000D54 000E6A 000FCB 00104B 00105A 0012A9 00147C 0016E0 00186E 001AC1 001CC5 001EC1 0020AF 002257 002473 002654 00301E 005004 005099 0050DA 006008 00608C 006097 009004 00A024 00D096 00D0D8 02608C 02C08C 08004E 20FDF1 4001C6" ;
			"Intel" = "0002B3 000347 000423 0007E9 000CF1 000E0C 000E35 001111 0012F0 001302 001320 0013CE 0013E8 001500 001517 00166F 001676 0016EA 0016EB 0018DE 0019D1 0019D2 001B21 001B77 001CBF 001CC0 001DE0 001DE1 001E64 001E65 001E67 001F3B 001F3C 00207B 00215C 00215D 00216A 00216B 0022FA 0022FB 002314 002315 0024D6 0024D7 0026C6 0026C7 00270E 002710 0050F1 009027 00A0C9 00AA00 00AA01 00AA02 00D0B7 081196 0CD292 100BA9 183DA2 247703 4025C2 448500 4C8093 502DA2 58946B 648099 64D4DA 685D43 74E50B 78929C 809B20 88532E 8CA982 A088B4 AC7289 BC7737 DCA971" ;
			"HP" = "0001E6 0001E7 0002A5 0004EA 000802 000883 0008C7 000A57 000BCD 000D9D 000E7F 000EB3 000F20 000F61 001083 0010E3 00110A 001185 001279 001321 001438 0014C2 001560 001635 001708 0017A4 001871 0018FE 0019BB 001A4B 001B78 001CC4 001E0B 001F29 00215A 002264 00237D 002481 0025B3 002655 00306E 0030C1 00508B 0060B0 00805F 0080A0 080009 18A905 1CC1DE 2C27D7 3C4A92 643150 68B599 78ACC0 78E3B5 78E7D1 984BE1 B499BA B8AF67 D48564 D8D385 F4CE46" ;
			"Apple" = "000393 000502 000A27 000A95 000D93 0010FA 001124 001451 0016CB 0017F2 0019E3 001B63 001CB3 001D4F 001E52 001EC2 001F5B 001FF3 0021E9 002241 002312 002332 00236C 0023DF 002436 002500 00254B 0025BC 002608 00264A 0026B0 0026BB 003065 0050E4 00A040 041E64 080007 1093E9 109ADD 18E7F4 24AB81 28E7CF 34159E 3C0754 40A6D9 40D32D 442A60 581FAA 5855CA 58B035 5C5948 60334B 60FB42 64B9E8 70CD60 78CA39 7C6D62 7CC537 7CF05F 88C663 8C5877 8C7B9D 9027E4 90840D 9803D8 A46706 A4B197 B8FF61 C42C03 C82A14 C8BCC8 CC08E0 D49A20 D83062 D89E3F D8A25E DC2B61 E0F847 E4CE8F E80688 F0B479 F81EDF" ;
			"AlliedTelesis" = "0000CD 0000F4 000941 000A79 000DDA 001130 001577 001AEB 002687 009099 00A0D2 ECCD6D" ;
			"QLogic" = "000E1E 001B32 0024FF 00C0DD 00E08B"
		}

		# Check that $ManufacturerName actually matches one of the valid $vendors here.
		if ($ManufacturerName -and ($vendor.keys -notcontains $ManufacturerName)) 
		{ throw "`nYou must choose a vendor from this list:`n" + $vendor.keys } 
		
		# Generate the first three bytes of the MAC or use the $ManufacturerID instead.
		if ($ManufacturerID) { $mac = $ManufacturerID.ToString().ToUpper() -replace '[^A-F0-9]',"" }
		elseif ($ManufacturerName) { $mac = get-random -input @($vendor.$ManufacturerName -split " ") } 
		else { $mac = get-random -input @($vendor.$(get-random -input @($vendor.keys)) -split " ") } 
    }
    
    # Now padright with random hex characters until we have twelve chars.
    while ($mac.length -lt 12) 
	{ 
		$mac += "{0:X}" -f $(get-random -min 0 -max 16) 
	} 
    
	# Now set the unicast/multicast flag bit.
	# First low-order bit (right-most bit): 0 = unicast, 1 = multicast
    # For the bit flags, see http://en.wikipedia.org/wiki/MAC_address	
	[Byte] $firstbyte = "0x" + $mac.substring(0,2)      # Convert first two hex chars to a byte.

	if ($multicast)
	{
		$firstbyte = [Byte] $firstbyte -bor [Byte] 1     # Set low-order bit to 1: multicast
		$mac = ("{0:X}" -f $firstbyte).padleft(2,"0") + $mac.substring(2) 
	}
	else
	{
		$firstbyte = [Byte] $firstbyte -band [Byte] 254  # Set low-order bit to 0: unicast
		$mac = ("{0:X}" -f $firstbyte).padleft(2,"0") + $mac.substring(2) 
	}
	
	
	# Now set the vendor-unique/locally-administered flag.
	# Next-to-low-order bit (second from right): 0 = unique vendor, 1 = locally administered
	if ($locallyadministered)
	{
		$firstbyte = [Byte] $firstbyte -bor [Byte] 2     # Set second low-order bit to 1: locally
		$mac = ("{0:X}" -f $firstbyte).padleft(2,"0") + $mac.substring(2) 
	}
	else
	{
		$firstbyte = [Byte] $firstbyte -band [Byte] 253  # Set second low-order bit to 0: vendor unique
		$mac = ("{0:X}" -f $firstbyte).padleft(2,"0") + $mac.substring(2) 
	}
	
		
    # Add delimiter, if any, and return the $mac.
    if ($Delimiter) 
    { 
		for ($i = 0 ; $i -le 10 ; $i += 2) 
		{ $newmac += $mac.substring($i,2) + $Delimiter }
		$newmac.substring(0,$($newmac.length - $Delimiter.length)) 
	} 
    else
    { $mac } 
}


# Get the NICs which are not tunnels, not for virtual machines, and not for bluetooth.
$nics = @(Get-WmiObject -Query "select * from win32_networkadapter where adaptertype != 'Tunnel' and adaptertype is not null" | `
where { $_.description -notmatch 'VMware|Virtual|WAN Miniport|ISATAP|RAS Async|Teredo|Windows Mobile Remote|6to4|Bluetooth' } )

# If more than one physical NIC, prompt the user to select one, if the index number was not given.
if ($nics.count -eq 0) { "`nCannot identify a valid network interface device, quitting...`n" ; exit }
elseif ($nics.count -eq 1 -and -not $InterfaceIndexNumber) { $index = $nics[0].index } 
else 
{
    if ($InterfaceIndexNumber) { $index = $InterfaceIndexNumber } 
    else
    {
        # Print a list of interfaces and prompt user to choose one.
        "`n"; $nics | format-table index,macaddress,netconnectionid,description -autosize
        $index = read-host -prompt "`nEnter the index number of the desired interface" 
    }
} 

# Check that a valid index number was actually entered.
$good = $false; switch ($nics | foreach {$_.index}) { $index { $good = $true } } 
if (-not $good) { "`n$index is not a valid index number, quitting...`n" ; exit } 

# Confirm that you can get the NIC by the index number, so that it can be disabled/enabled later too.
$thenic = Get-WmiObject -Query "select * from win32_networkadapter where deviceid = $index"
if (-not $?) { "`nThere was a problem getting the interface, quitting...`n" ; exit } 

# The registry key for the nic always has four digits, so padleft, then get the key.
$index = $index.tostring().padleft(4,"0")
$regkey = get-item "hklm:\system\CurrentControlSet\control\class\{4D36E972-E325-11CE-BFC1-08002BE10318}\$index" 
if (-not $?) { "`nThere was a problem getting the registry key, quitting...`n" ; exit } 

# Show how WMI sees the current MAC address.
("`nWMI reports the current MAC address for interface $index as " + $thenic.macaddress + ".").replace(":","")

# Show current registry value for MAC address, if any.
$macaddress = $regkey.getvalue("NetworkAddress")
if ($macaddress -eq $null) {"Custom MAC address registry value does not exist for interface index $index."} 
else {"Current registry MAC value for interface $index is $macaddress."}

# If requested, delete the registry value for a custom MAC, which resets to the default burnt-in 
# MAC; otherwise, set the registry value for a custom MAC address.
if ($resetdefault)
{
	if ($macaddress -ne $null)
	{
		"Deleting registry value for a custom MAC, which resets to the default MAC address."
		$regpath = "hklm:\system\CurrentControlSet\control\class\{4D36E972-E325-11CE-BFC1-08002BE10318}\$index"
		remove-itemproperty -path $regpath -name "NetworkAddress"
		if (-not $?) { "`nFAILED to delete the registry value for the MAC address!`n" ; exit } 
	}
}
else
{
	# Set new value for MAC address.
	$regpath = "hklm:\system\CurrentControlSet\control\class\{4D36E972-E325-11CE-BFC1-08002BE10318}\$index"
	if ($wireless)
	{
		set-itemproperty -path $regpath -name "NetworkAddress" -value $(random-mac -locallyadministered) 
	}
	else
	{
		set-itemproperty -path $regpath -name "NetworkAddress" -value $(random-mac) 
	}
	if (-not $?) { "`nFAILED to set the registry value for the MAC address!`n" ; exit } 

	# Show new registry value for MAC address.
	$macaddress = $regkey.getvalue("NetworkAddress")
	if ($macaddress -eq $null) { "`nFAILED to change the registry value for a custom MAC address`n" ; exit } 
	else {"The new registry MAC value for interface $index is $macaddress."}
}

# Release DHCP leases, disable the interface, re-enable, renew DHCP.
if ($DoNotResetInterface)
{   "Changes will not take effect until after the interface has been disabled and enabled.`n" } 
else
{
    "Refreshing the interface, this may take a few seconds..."
    ipconfig.exe /release """$($thenic.netconnectionid)"""   | out-null
    ipconfig.exe /release6 """$($thenic.netconnectionid)"""  | out-null
    $thenic.disable() | out-null
    if (-not $?) { "FAILED to disable the interface!" } 
    $thenic.enable() | out-null
    if (-not $?) { "FAILED to enable the interface!" } 
    ipconfig.exe /renew """$($thenic.netconnectionid)"""  | out-null
    ipconfig.exe /renew6 """$($thenic.netconnectionid)""" | out-null
    "...done refreshing the interface."

    # Confirm through WMI again that the change actually took effect.
    $thenic = Get-WmiObject -Query "select * from win32_networkadapter where deviceid = $index"
    ("WMI reports the current MAC address for interface $index as " + $thenic.macaddress + ".`n").replace(":","")
}

# END-MAC-SCRIPT

##########
# Restart
##########
Write-Host
Write-Host "Press any key to restart your system..." -ForegroundColor Black -BackgroundColor White
$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host "Restarting..."
Restart-Computer
}

1 {
Write-Host
Write-Host "Press any key to restart your system..." -ForegroundColor Black -BackgroundColor White
$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host "Restarting..."
Restart-Computer
}
}