##########
# Security Tweaks
##########

<#
    .DESCRIPTION
        Lower UAC level (disabling it completely would break apps)
#>
Function SetUACLow {
    Write-Output "Lowering UAC level..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Raise UAC level
#>
Function SetUACHigh {
    Write-Output "Raising UAC level..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable sharing mapped drives between users
#>
Function EnableSharingMappedDrives {
    Write-Output "Enabling sharing mapped drives between users..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable sharing mapped drives between users
#>
Function DisableSharingMappedDrives {
    Write-Output "Disabling sharing mapped drives between users..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable implicit administrative shares
#>
Function DisableAdminShares {
    Write-Output "Disabling implicit administrative shares..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable implicit administrative shares
#>
Function EnableAdminShares {
    Write-Output "Enabling implicit administrative shares..."
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Firewall
#>
Function DisableFirewall {
    Write-Output "Disabling Firewall..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable Firewall
#>
Function EnableFirewall {
    Write-Output "Enabling Firewall..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide Windows Defender SysTray icon
#>
Function HideDefenderTrayIcon {
    Write-Output "Hiding Windows Defender SysTray icon..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Type DWord -Value 1
    If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
    } ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
    }
}

<#
    .DESCRIPTION
        Show Windows Defender SysTray icon
#>
Function ShowDefenderTrayIcon {
    Write-Output "Showing Windows Defender SysTray icon..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -ErrorAction SilentlyContinue
    If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
    } ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 17134) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%ProgramFiles%\Windows Defender\MSASCuiL.exe"
    } ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17763) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe"
    }
}

<#
    .DESCRIPTION
        Disable Windows Defender
#>
Function DisableDefender {
    Write-Output "Disabling Windows Defender..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
    If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
    } ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
    }
}

<#
    .DESCRIPTION
        Enable Windows Defender
#>
Function EnableDefender {
    Write-Output "Enabling Windows Defender..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
    } ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 17134) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%ProgramFiles%\Windows Defender\MSASCuiL.exe"
    } ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17763) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe"
    }
}

<#
    .DESCRIPTION
        Disable Windows Defender Cloud
#>
Function DisableDefenderCloud {
    Write-Output "Disabling Windows Defender Cloud..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
}

<#
    .DESCRIPTION
        Enable Windows Defender Cloud
#>
Function EnableDefenderCloud {
    Write-Output "Enabling Windows Defender Cloud..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable Controlled Folder Access (Defender Exploit Guard feature) - Applicable since 1709, requires Windows Defender to be enabled
#>
Function EnableCtrldFolderAccess {
    Write-Output "Enabling Controlled Folder Access..."
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Controlled Folder Access (Defender Exploit Guard feature) - Applicable since 1709, requires Windows Defender to be enabled
#>
Function DisableCtrldFolderAccess {
    Write-Output "Disabling Controlled Folder Access..."
    Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable Core Isolation Memory Integrity - Part of Windows Defender System Guard virtualization-based security - Applicable since 1803
        Warning: This may cause old applications and drivers to crash or even cause BSOD
        Problems were confirmed with old video drivers (Intel HD Graphics for 2nd gen., Radeon HD 6850), and old antivirus software (Kaspersky Endpoint Security 10.2, 11.2)
#>
Function EnableCIMemoryIntegrity {
    Write-Output "Enabling Core Isolation Memory Integrity..."
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable Core Isolation Memory Integrity - Applicable since 1803
#>
Function DisableCIMemoryIntegrity {
    Write-Output "Disabling Core Isolation Memory Integrity..."
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable Windows Defender Application Guard - Applicable since 1709 Enterprise and 1803 Pro. Not applicable to Server
        Not supported on VMs and VDI environment. Check requirements on https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard
#>
Function EnableDefenderAppGuard {
    Write-Output "Enabling Windows Defender Application Guard..."
    Enable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

<#
    .DESCRIPTION
        Disable Windows Defender Application Guard - Applicable since 1709 Enterprise and 1803 Pro. Not applicable to Server
#>
Function DisableDefenderAppGuard {
    Write-Output "Disabling Windows Defender Application Guard..."
    Disable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

<#
    .DESCRIPTION
        Hide Account Protection warning in Defender about not using a Microsoft account
#>
Function HideAccountProtectionWarn {
    Write-Output "Hiding Account Protection warning..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows Security Health\State")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Force | Out-Null
    }
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Show Account Protection warning in Defender
#>
Function ShowAccountProtectionWarn {
    Write-Output "Showing Account Protection warning..."
    Remove-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable blocking of downloaded files (i.e. storing zone information - no need to do File\Properties\Unblock)
#>
Function DisableDownloadBlocking {
    Write-Output "Disabling blocking of downloaded files..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable blocking of downloaded files
#>
Function EnableDownloadBlocking {
    Write-Output "Enabling blocking of downloaded files..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Windows Script Host (execution of *.vbs scripts and alike)
#>
Function DisableScriptHost {
    Write-Output "Disabling Windows Script Host..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable Windows Script Host
#>
Function EnableScriptHost {
    Write-Output "Enabling Windows Script Host..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable strong cryptography for old versions of .NET Framework (4.6 and newer have strong crypto enabled by default)
        https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls#schusestrongcrypto
#>
Function EnableDotNetStrongCrypto {
    Write-output "Enabling .NET strong cryptography..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable strong cryptography for old versions of .NET Framework
#>
Function DisableDotNetStrongCrypto {
    Write-output "Disabling .NET strong cryptography..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable Meltdown (CVE-2017-5754) compatibility flag - Required for January and February 2018 Windows updates
        This flag is normally automatically enabled by compatible antivirus software (such as Windows Defender).
        Use the tweak only if you have confirmed that your AV is compatible but unable to set the flag automatically or if you don't use any AV at all.
        As of March 2018, the compatibility check has been lifted for security updates.
        See https://support.microsoft.com/en-us/help/4072699/windows-security-updates-and-antivirus-software for details
#>
Function EnableMeltdownCompatFlag {
    Write-Output "Enabling Meltdown (CVE-2017-5754) compatibility flag..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Disable Meltdown (CVE-2017-5754) compatibility flag
#>
Function DisableMeltdownCompatFlag {
    Write-Output "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable F8 boot menu options
#>
Function EnableF8BootMenu {
    Write-Output "Enabling F8 boot menu options..."
    bcdedit /set `{current`} BootMenuPolicy Legacy | Out-Null
}

<#
    .DESCRIPTION
        Disable F8 boot menu options
#>
Function DisableF8BootMenu {
    Write-Output "Disabling F8 boot menu options..."
    bcdedit /set `{current`} BootMenuPolicy Standard | Out-Null
}

<#
    .DESCRIPTION
        Disable automatic recovery mode during boot
        This causes boot process to always ignore startup errors and attempt to boot normally
        It is still possible to interrupt the boot and enter recovery mode manually. In order to disable even that, apply also DisableRecoveryAndReset tweak
#>
Function DisableBootRecovery {
    Write-Output "Disabling automatic recovery mode during boot..."
    bcdedit /set `{current`} BootStatusPolicy IgnoreAllFailures | Out-Null
}

<#
    .DESCRIPTION
        Enable automatic entering recovery mode during boot
        This allows the boot process to automatically enter recovery mode when it detects startup errors (default behavior)
#>
Function EnableBootRecovery {
    Write-Output "Enabling automatic recovery mode during boot..."
    bcdedit /deletevalue `{current`} BootStatusPolicy | Out-Null
}

<#
    .DESCRIPTION
        Disable System Recovery and Factory reset
        Warning: This tweak completely removes the option to enter the system recovery during boot and the possibility to perform a factory reset
#>
Function DisableRecoveryAndReset {
    Write-Output "Disabling System Recovery and Factory reset..."
    reagentc /disable 2>&1 | Out-Null
}

<#
    .DESCRIPTION
        Enable System Recovery and Factory reset
#>
Function EnableRecoveryAndReset {
    Write-Output "Enabling System Recovery and Factory reset..."
    reagentc /enable 2>&1 | Out-Null
}

<#
    .DESCRIPTION
        Set Data Execution Prevention (DEP) policy to OptOut - Turn on DEP for all 32-bit applications except manually excluded. 64-bit applications have DEP always on.
#>
Function SetDEPOptOut {
    Write-Output "Setting Data Execution Prevention (DEP) policy to OptOut..."
    bcdedit /set `{current`} nx OptOut | Out-Null
}

<#
    .DESCRIPTION
        Set Data Execution Prevention (DEP) policy to OptIn - Turn on DEP only for essential 32-bit Windows executables and manually included applications. 64-bit applications have DEP always on.
#>
Function SetDEPOptIn {
    Write-Output "Setting Data Execution Prevention (DEP) policy to OptIn..."
    bcdedit /set `{current`} nx OptIn | Out-Null
}
