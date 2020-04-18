##########
# Server specific Tweaks
##########

<#
    .DESCRIPTION
        Hide Server Manager after login
#>
Function HideServerManagerOnLogin {
    Write-Output "Hiding Server Manager after login..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Show Server Manager after login
#>
Function ShowServerManagerOnLogin {
    Write-Output "Showing Server Manager after login..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Shutdown Event Tracker
#>
Function DisableShutdownTracker {
    Write-Output "Disabling Shutdown Event Tracker..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable Shutdown Event Tracker
#>
Function EnableShutdownTracker {
    Write-Output "Enabling Shutdown Event Tracker..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable password complexity and maximum age requirements
#>
Function DisablePasswordPolicy {
    Write-Output "Disabling password complexity and maximum age requirements..."
    $tmpfile = New-TemporaryFile
    secedit /export /cfg $tmpfile /quiet
    (Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
    secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $tmpfile
}

<#
    .DESCRIPTION
        Enable password complexity and maximum age requirements
#>
Function EnablePasswordPolicy {
    Write-Output "Enabling password complexity and maximum age requirements..."
    $tmpfile = New-TemporaryFile
    secedit /export /cfg $tmpfile /quiet
    (Get-Content $tmpfile).Replace("PasswordComplexity = 0", "PasswordComplexity = 1").Replace("MaximumPasswordAge = -1", "MaximumPasswordAge = 42") | Out-File $tmpfile
    secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $tmpfile
}

<#
    .DESCRIPTION
        Disable Ctrl+Alt+Del requirement before login
#>
Function DisableCtrlAltDelLogin {
    Write-Output "Disabling Ctrl+Alt+Del requirement before login..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable Ctrl+Alt+Del requirement before login
#>
Function EnableCtrlAltDelLogin {
    Write-Output "Enabling Ctrl+Alt+Del requirement before login..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Disable Internet Explorer Enhanced Security Configuration (IE ESC)
#>
Function DisableIEEnhancedSecurity {
    Write-Output "Disabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable Internet Explorer Enhanced Security Configuration (IE ESC)
#>
Function EnableIEEnhancedSecurity {
    Write-Output "Enabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable Audio
#>
Function EnableAudio {
    Write-Output "Enabling Audio..."
    Set-Service "Audiosrv" -StartupType Automatic
    Start-Service "Audiosrv" -WarningAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Audio
#>
Function DisableAudio {
    Write-Output "Disabling Audio..."
    Stop-Service "Audiosrv" -WarningAction SilentlyContinue
    Set-Service "Audiosrv" -StartupType Manual
}
