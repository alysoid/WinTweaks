##########
# Service Tweaks
##########

<#
    .DESCRIPTION
        Disable offering of Malicious Software Removal Tool through Windows Update
#>
Function DisableUpdateMSRT {
    Write-Output "Disabling Malicious Software Removal Tool offering..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable offering of Malicious Software Removal Tool through Windows Update
#>
Function EnableUpdateMSRT {
    Write-Output "Enabling Malicious Software Removal Tool offering..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable offering of drivers through Windows Update
        Note: This doesn't work properly if you use a driver intended for another hardware model. E.g. Intel I219-V on WinServer works only with I219-LM driver.
        Therefore Windows update will repeatedly try and fail to install I219-V driver indefinitely even if you use the tweak.
#>
Function DisableUpdateDriver {
    Write-Output "Disabling driver offering through Windows Update..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable offering of drivers through Windows Update
#>
Function EnableUpdateDriver {
    Write-Output "Enabling driver offering through Windows Update..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable receiving updates for other Microsoft products via Windows Update
#>
Function EnableUpdateMSProducts {
    Write-Output "Enabling updates for other Microsoft products..."
    (New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") | Out-Null
}

<#
    .DESCRIPTION
        Disable receiving updates for other Microsoft products via Windows Update
#>
Function DisableUpdateMSProducts {
    Write-Output "Disabling updates for other Microsoft products..."
    If ((New-Object -ComObject Microsoft.Update.ServiceManager).Services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d"}) {
        (New-Object -ComObject Microsoft.Update.ServiceManager).RemoveService("7971f918-a847-4430-9279-4a52d1efe18d") | Out-Null
    }
}

<#
    .DESCRIPTION
        Disable Windows Update automatic downloads
#>
Function DisableUpdateAutoDownload {
    Write-Output "Disabling Windows Update automatic downloads..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2
}

<#
    .DESCRIPTION
        Enable Windows Update automatic downloads
#>
Function EnableUpdateAutoDownload {
    Write-Output "Enabling Windows Update automatic downloads..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable automatic restart after Windows Update installation
        The tweak is slightly experimental, as it registers a dummy debugger for MusNotification.exe
        which blocks the restart prompt executable from running, thus never schedulling the restart
#>
Function DisableUpdateRestart {
    Write-Output "Disabling Windows Update automatic restart..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -Type String -Value "cmd.exe"
}

<#
    .DESCRIPTION
        Enable automatic restart after Windows Update installation
#>
Function EnableUpdateRestart {
    Write-Output "Enabling Windows Update automatic restart..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable nightly wake-up for Automatic Maintenance and Windows Updates
#>
Function DisableMaintenanceWakeUp {
    Write-Output "Disabling nightly wake-up for Automatic Maintenance..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable nightly wake-up for Automatic Maintenance and Windows Updates
#>
Function EnableMaintenanceWakeUp {
    Write-Output "Enabling nightly wake-up for Automatic Maintenance..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Automatic Restart Sign-on - Applicable since 1903
        See https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/winlogon-automatic-restart-sign-on--arso-
#>
Function DisableAutoRestartSignOn {
    Write-Output "Disabling Automatic Restart Sign-on..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable Automatic Restart Sign-on - Applicable since 1903
#>
Function EnableAutoRestartSignOn {
    Write-Output "Enabling Automatic Restart Sign-on..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Shared Experiences - Applicable since 1703. Not applicable to Server
        This setting can be set also via GPO, however doing so causes reset of Start Menu cache. See https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/145 for details
#>
Function DisableSharedExperiences {
    Write-Output "Disabling Shared Experiences..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable Shared Experiences - Applicable since 1703. Not applicable to Server
#>
Function EnableSharedExperiences {
    Write-Output "Enabling Shared Experiences..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable Clipboard History - Applicable since 1809. Not applicable to Server
#>
Function EnableClipboardHistory {
    Write-Output "Enabling Clipboard History..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable Clipboard History - Applicable since 1809. Not applicable to Server
#>
Function DisableClipboardHistory {
    Write-Output "Disabling Clipboard History..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Autoplay
#>
Function DisableAutoplay {
    Write-Output "Disabling Autoplay..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable Autoplay
#>
Function EnableAutoplay {
    Write-Output "Enabling Autoplay..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Disable Autorun for all drives
#>
Function DisableAutorun {
    Write-Output "Disabling Autorun for all drives..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}

<#
    .DESCRIPTION
        Enable Autorun for removable drives
#>
Function EnableAutorun {
    Write-Output "Enabling Autorun for all drives..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable System Restore for system drive - Not applicable to Server
        Note: This does not delete already existing restore points as the deletion of restore points is irreversible. In order to do that, run also following command.
        vssadmin Delete Shadows /For=$env:SYSTEMDRIVE /Quiet
#>
Function DisableRestorePoints {
    Write-Output "Disabling System Restore for system drive..."
    Disable-ComputerRestore -Drive "$env:SYSTEMDRIVE"
}

<#
    .DESCRIPTION
        Enable System Restore for system drive - Not applicable to Server
        Note: Some systems (notably VMs) have maximum size allowed to be used for shadow copies set to zero. In order to increase the size, run following command.
        vssadmin Resize ShadowStorage /On=$env:SYSTEMDRIVE /For=$env:SYSTEMDRIVE /MaxSize=10GB
#>
Function EnableRestorePoints {
    Write-Output "Enabling System Restore for system drive..."
    Enable-ComputerRestore -Drive "$env:SYSTEMDRIVE"
}

<#
    .DESCRIPTION
        Enable Storage Sense - automatic disk cleanup - Applicable since 1703
#>
Function EnableStorageSense {
    Write-Output "Enabling Storage Sense..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "StoragePoliciesNotified" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable Storage Sense - Applicable since 1703
#>
Function DisableStorageSense {
    Write-Output "Disabling Storage Sense..."
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable scheduled defragmentation task
#>
Function DisableDefragmentation {
    Write-Output "Disabling scheduled defragmentation..."
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

<#
    .DESCRIPTION
        Enable scheduled defragmentation task
#>
Function EnableDefragmentation {
    Write-Output "Enabling scheduled defragmentation..."
    Enable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

<#
    .DESCRIPTION
        Stop and disable Superfetch service
#>
Function DisableSuperfetch {
    Write-Output "Stopping and disabling Superfetch service..."
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
}

<#
    .DESCRIPTION
        Start and enable Superfetch service
#>
Function EnableSuperfetch {
    Write-Output "Starting and enabling Superfetch service..."
    Set-Service "SysMain" -StartupType Automatic
    Start-Service "SysMain" -WarningAction SilentlyContinue
}

<#
    .DESCRIPTION
        Stop and disable Windows Search indexing service
#>
Function DisableIndexing {
    Write-Output "Stopping and disabling Windows Search indexing service..."
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
}

<#
    .DESCRIPTION
        Start and enable Windows Search indexing service
#>
Function EnableIndexing {
    Write-Output "Starting and enabling Windows Search indexing service..."
    Set-Service "WSearch" -StartupType Automatic
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Type DWord -Value 1
    Start-Service "WSearch" -WarningAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Modern UI swap file
        This disables creation and use of swapfile.sys and frees 256 MB of disk space. Swapfile.sys is used only by Modern UI apps. The tweak has no effect on the real swap in pagefile.sys.
#>
Function DisableSwapFile {
    Write-Output "Disabling Modern UI swap file..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Type Dword -Value 0
}

<#
    .DESCRIPTION
        Enable Modern UI swap file
#>
Function EnableSwapFile {
    Write-Output "Enabling Modern UI swap file..."
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Recycle Bin - Files will be permanently deleted without placing into Recycle Bin
#>
Function DisableRecycleBin {
    Write-Output "Disabling Recycle Bin..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecycleFiles" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable Recycle Bin
#>
Function EnableRecycleBin {
    Write-Output "Enable Recycle Bin..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecycleFiles" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable NTFS paths with length over 260 characters
#>
Function EnableNTFSLongPaths {
    Write-Output "Enabling NTFS paths with length over 260 characters..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable NTFS paths with length over 260 characters
#>
Function DisableNTFSLongPaths {
    Write-Output "Disabling NTFS paths with length over 260 characters..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Disable updating of NTFS last access timestamps
#>
Function DisableNTFSLastAccess {
    Write-Output "Disabling updating of NTFS last access timestamps..."
    # User Managed, Last Access Updates Disabled
    fsutil behavior set DisableLastAccess 1 | Out-Null
}

<#
    .DESCRIPTION
        Enable updating of NTFS last access timestamps
#>
Function EnableNTFSLastAccess {
    Write-Output "Enabling updating of NTFS last access timestamps..."
    If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
        # System Managed, Last Access Updates Enabled
        fsutil behavior set DisableLastAccess 2 | Out-Null
    } Else {
        # Last Access Updates Enabled
        fsutil behavior set DisableLastAccess 0 | Out-Null
    }
}

<#
    .DESCRIPTION
        Set BIOS time to UTC
#>
Function SetBIOSTimeUTC {
    Write-Output "Setting BIOS time to UTC..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Set BIOS time to local time
#>
Function SetBIOSTimeLocal {
    Write-Output "Setting BIOS time to Local time..."
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable Hibernation - Do not use on Server with automatically started Hyper-V hvboot service as it may lead to BSODs (Win10 with Hyper-V is fine)
#>
Function EnableHibernation {
    Write-Output "Enabling Hibernation..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 1
    powercfg /HIBERNATE ON 2>&1 | Out-Null
}

<#
    .DESCRIPTION
        Disable Hibernation
#>
Function DisableHibernation {
    Write-Output "Disabling Hibernation..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0
    powercfg /HIBERNATE OFF 2>&1 | Out-Null
}

<#
    .DESCRIPTION
        Disable Sleep start menu and keyboard button
#>
Function DisableSleepButton {
    Write-Output "Disabling Sleep start menu and keyboard button..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
    powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
}

<#
    .DESCRIPTION
        Enable Sleep start menu and keyboard button
#>
Function EnableSleepButton {
    Write-Output "Enabling Sleep start menu and keyboard button..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 1
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
    powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
}

<#
    .DESCRIPTION
        Disable display and sleep mode timeouts
#>
Function DisableSleepTimeout {
    Write-Output "Disabling display and sleep mode timeouts..."
    powercfg /X monitor-timeout-ac 0
    powercfg /X monitor-timeout-dc 0
    powercfg /X standby-timeout-ac 0
    powercfg /X standby-timeout-dc 0
}

<#
    .DESCRIPTION
        Enable display and sleep mode timeouts
#>
Function EnableSleepTimeout {
    Write-Output "Enabling display and sleep mode timeouts..."
    powercfg /X monitor-timeout-ac 10
    powercfg /X monitor-timeout-dc 5
    powercfg /X standby-timeout-ac 30
    powercfg /X standby-timeout-dc 15
}

<#
    .DESCRIPTION
        Disable Fast Startup
#>
Function DisableFastStartup {
    Write-Output "Disabling Fast Startup..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable Fast Startup
#>
Function EnableFastStartup {
    Write-Output "Enabling Fast Startup..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable automatic reboot on crash (BSOD)
#>
Function DisableAutoRebootOnCrash {
    Write-Output "Disabling automatic reboot on crash (BSOD)..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable automatic reboot on crash (BSOD)
#>
Function EnableAutoRebootOnCrash {
    Write-Output "Enabling automatic reboot on crash (BSOD)..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 1
}
