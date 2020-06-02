##########
# UI Tweaks
##########

<#
    .DESCRIPTION
        Disable Action Center (Notification Center)
#>
Function DisableActionCenter {
    Write-Output "Disabling Action Center (Notification Center)..."
    If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable Action Center (Notification Center)
#>
Function EnableActionCenter {
    Write-Output "Enabling Action Center (Notification Center)..."
    Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Lock screen
#>
Function DisableLockScreen {
    Write-Output "Disabling Lock screen..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable Lock screen
#>
Function EnableLockScreen {
    Write-Output "Enabling Lock screen..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Lock screen - Anniversary Update workaround. The GPO used in DisableLockScreen has been broken in 1607 and fixed again in 1803
#>
Function DisableLockScreenRS1 {
    Write-Output "Disabling Lock screen using scheduler workaround..."
    $service = New-Object -com Schedule.Service
    $service.Connect()
    $task = $service.NewTask(0)
    $task.Settings.DisallowStartIfOnBatteries = $false
    $trigger = $task.Triggers.Create(9)
    $trigger = $task.Triggers.Create(11)
    $trigger.StateChange = 8
    $action = $task.Actions.Create(0)
    $action.Path = "reg.exe"
    $action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
    $service.GetFolder("\").RegisterTaskDefinition("Disable LockScreen", $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
}

<#
    .DESCRIPTION
        Enable Lock screen - Anniversary Update workaround. The GPO used in DisableLockScreen has been broken in 1607 and fixed again in 1803
#>
Function EnableLockScreenRS1 {
    Write-Output "Enabling Lock screen (removing scheduler workaround)..."
    Unregister-ScheduledTask -TaskName "Disable LockScreen" -Confirm:$false -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide network options from Lock Screen
#>
Function HideNetworkFromLockScreen {
    Write-Output "Hiding network options from Lock Screen..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Show network options on lock screen
#>
Function ShowNetworkOnLockScreen {
    Write-Output "Showing network options on Lock Screen..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide shutdown options from Lock Screen
#>
Function HideShutdownFromLockScreen {
    Write-Output "Hiding shutdown options from Lock Screen..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Show shutdown options on lock screen
#>
Function ShowShutdownOnLockScreen {
    Write-Output "Showing shutdown options on Lock Screen..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable Lock screen Blur - Applicable since 1903
#>
Function DisableLockScreenBlur {
    Write-Output "Disabling Lock screen Blur..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable Lock screen Blur - Applicable since 1903
#>
Function EnableLockScreenBlur {
    Write-Output "Enabling Lock screen Blur..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Aero Shake (minimizing other windows when one is dragged by mouse and shaken)
#>
Function DisableAeroShake {
    Write-Output "Disabling Aero Shake..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable Aero Shake
#>
Function EnableAeroShake {
    Write-Output "Enabling Aero Shake..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable accessibility keys prompts (Sticky keys, Toggle keys, Filter keys)
#>
Function DisableAccessibilityKeys {
    Write-Output "Disabling accessibility keys prompts..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58"
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122"
}

<#
    .DESCRIPTION
        Enable accessibility keys prompts (Sticky keys, Toggle keys, Filter keys)
#>
Function EnableAccessibilityKeys {
    Write-Output "Enabling accessibility keys prompts..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510"
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "62"
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "126"
}

<#
    .DESCRIPTION
        Show Task Manager details - Applicable since 1607
        Although this functionality exist even in earlier versions, the Task Manager's behavior is different there and is not compatible with this tweak
#>
Function ShowTaskManagerDetails {
    Write-Output "Showing task manager details..."
    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
    $timeout = 30000
    $sleep = 100
    Do {
        Start-Sleep -Milliseconds $sleep
        $timeout -= $sleep
        $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    } Until ($preferences -or $timeout -le 0)
    Stop-Process $taskmgr
    If ($preferences) {
        $preferences.Preferences[28] = 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    }
}

<#
    .DESCRIPTION
        Hide Task Manager details - Applicable since 1607
#>
Function HideTaskManagerDetails {
    Write-Output "Hiding task manager details..."
    $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    If ($preferences) {
        $preferences.Preferences[28] = 1
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    }
}

<#
    .DESCRIPTION
        Show file operations details
#>
Function ShowFileOperationsDetails {
    Write-Output "Showing file operations details..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Hide file operations details
#>
Function HideFileOperationsDetails {
    Write-Output "Hiding file operations details..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable file delete confirmation dialog
#>
Function EnableFileDeleteConfirm {
    Write-Output "Enabling file delete confirmation dialog..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable file delete confirmation dialog
#>
Function DisableFileDeleteConfirm {
    Write-Output "Disabling file delete confirmation dialog..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide Taskbar Search icon / box
#>
Function HideTaskbarSearch {
    Write-Output "Hiding Taskbar Search icon / box..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Show Taskbar Search icon
#>
Function ShowTaskbarSearchIcon {
    Write-Output "Showing Taskbar Search icon..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Show Taskbar Search box
#>
Function ShowTaskbarSearchBox {
    Write-Output "Showing Taskbar Search box..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 2
}

<#
    .DESCRIPTION
        Hide Task View button
#>
Function HideTaskView {
    Write-Output "Hiding Task View button..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Show Task View button
#>
Function ShowTaskView {
    Write-Output "Showing Task View button..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show small icons in taskbar
#>
Function ShowSmallTaskbarIcons {
    Write-Output "Showing small icons in taskbar..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Show large icons in taskbar
#>
Function ShowLargeTaskbarIcons {
    Write-Output "Showing large icons in taskbar..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Set taskbar buttons to show labels and combine when taskbar is full
#>
Function SetTaskbarCombineWhenFull {
    Write-Output "Setting taskbar buttons to combine when taskbar is full..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Set taskbar buttons to show labels and never combine
#>
Function SetTaskbarCombineNever {
    Write-Output "Setting taskbar buttons to never combine..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 2
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Type DWord -Value 2
}

<#
    .DESCRIPTION
        Set taskbar buttons to always combine and hide labels
#>
Function SetTaskbarCombineAlways {
    Write-Output "Setting taskbar buttons to always combine, hide labels..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide Taskbar People icon
#>
Function HideTaskbarPeopleIcon {
    Write-Output "Hiding People icon..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Show Taskbar People icon
#>
Function ShowTaskbarPeopleIcon {
    Write-Output "Showing People icon..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show all tray icons
#>
Function ShowTrayIcons {
    Write-Output "Showing all tray icons..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Hide tray icons as needed
#>
Function HideTrayIcons {
    Write-Output "Hiding tray icons..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show seconds in taskbar
#>
Function ShowSecondsInTaskbar {
    Write-Output "Showing seconds in taskbar..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Hide seconds from taskbar
#>
Function HideSecondsFromTaskbar {
    Write-Output "Hiding seconds from taskbar..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable search for app in store for unknown extensions
#>
Function DisableSearchAppInStore {
    Write-Output "Disabling search for app in store for unknown extensions..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable search for app in store for unknown extensions
#>
Function EnableSearchAppInStore {
    Write-Output "Enabling search for app in store for unknown extensions..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable 'How do you want to open this file?' prompt
#>
Function DisableNewAppPrompt {
    Write-Output "Disabling 'How do you want to open this file?' prompt..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable 'How do you want to open this file?' prompt
#>
Function EnableNewAppPrompt {
    Write-Output "Enabling 'How do you want to open this file?' prompt..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide 'Recently added' list from the Start Menu
#>
Function HideRecentlyAddedApps {
    Write-Output "Hiding 'Recently added' list from the Start Menu..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Show 'Recently added' list in the Start Menu
#>
Function ShowRecentlyAddedApps {
    Write-Output "Showing 'Recently added' list in the Start Menu..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide 'Most used' apps list from the Start Menu - Applicable until 1703 (hidden by default since then)
#>
Function HideMostUsedApps {
    Write-Output "Hiding 'Most used' apps list from the Start Menu..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Show 'Most used' apps list in the Start Menu - Applicable until 1703 (GPO broken since then)
#>
Function ShowMostUsedApps {
    Write-Output "Showing 'Most used' apps list in the Start Menu..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Set Control Panel view to Small icons (Classic)
#>
Function SetControlPanelSmallIcons {
    Write-Output "Setting Control Panel view to small icons..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Set Control Panel view to Large icons (Classic)
#>
Function SetControlPanelLargeIcons {
    Write-Output "Setting Control Panel view to large icons..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Set Control Panel view to categories
#>
Function SetControlPanelCategories {
    Write-Output "Setting Control Panel view to categories..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable adding '- shortcut' to shortcut name
#>
Function DisableShortcutInName {
    Write-Output "Disabling adding '- shortcut' to shortcut name..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0,0,0,0))
}

<#
    .DESCRIPTION
        Enable adding '- shortcut' to shortcut name
#>
Function EnableShortcutInName {
    Write-Output "Enabling adding '- shortcut' to shortcut name..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide shortcut icon arrow
#>
Function HideShortcutArrow {
    Write-Output "Hiding shortcut icon arrow..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -Type String -Value "%SystemRoot%\System32\imageres.dll,-1015"
}

<#
    .DESCRIPTION
        Show shortcut icon arrow
#>
Function ShowShortcutArrow {
    Write-Output "Showing shortcut icon arrow..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
#>
Function SetVisualFXPerformance {
    Write-Output "Adjusting visual effects for performance..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Adjusts visual effects for appearance
#>
Function SetVisualFXAppearance {
    Write-Output "Adjusting visual effects for appearance..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 400
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](158,30,7,128,18,0,0,0))
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 1
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable window title bar color according to prevalent background color
#>
Function EnableTitleBarColor {
    Write-Output "Enabling window title bar color..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable window title bar color
#>
Function DisableTitleBarColor {
    Write-Output "Disabling window title bar color..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Set Dark Mode for Applications
#>
Function SetAppsDarkMode {
    Write-Output "Setting Dark Mode for Applications..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Set Light Mode for Applications
#>
Function SetAppsLightMode {
    Write-Output "Setting Light Mode for Applications..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Set Light Mode for System - Applicable since 1903
#>
Function SetSystemLightMode {
    Write-Output "Setting Light Mode for System..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Set Dark Mode for System - Applicable since 1903
#>
Function SetSystemDarkMode {
    Write-Output "Setting Dark Mode for System..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Add secondary en-US keyboard
#>
Function AddENKeyboard {
    Write-Output "Adding secondary en-US keyboard..."
    $langs = Get-WinUserLanguageList
    $langs.Add("en-US")
    Set-WinUserLanguageList $langs -Force
}

<#
    .DESCRIPTION
        Remove secondary en-US keyboard
#>
Function RemoveENKeyboard {
    Write-Output "Removing secondary en-US keyboard..."
    $langs = Get-WinUserLanguageList
    Set-WinUserLanguageList ($langs | Where-Object {$_.LanguageTag -ne "en-US"}) -Force
}

<#
    .DESCRIPTION
        Enable NumLock after startup
#>
Function EnableNumlock {
    Write-Output "Enabling NumLock after startup..."
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
    Add-Type -AssemblyName System.Windows.Forms
    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
}

<#
    .DESCRIPTION
        Disable NumLock after startup
#>
Function DisableNumlock {
    Write-Output "Disabling NumLock after startup..."
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648
    Add-Type -AssemblyName System.Windows.Forms
    If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
}

<#
    .DESCRIPTION
        Disable enhanced pointer precision
#>
Function DisableEnhPointerPrecision {
    Write-Output "Disabling enhanced pointer precision..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"
}

<#
    .DESCRIPTION
        Enable enhanced pointer precision
#>
Function EnableEnhPointerPrecision {
    Write-Output "Enabling enhanced pointer precision..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "1"
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "6"
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "10"
}

<#
    .DESCRIPTION
        Set sound scheme to No Sounds
#>
Function SetSoundSchemeNone {
    Write-Output "Setting sound scheme to No Sounds..."
    $SoundScheme = ".None"
    Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps\*\*" | ForEach-Object {
        # If scheme keys do not exist in an event, create empty ones (similar behavior to Sound control panel).
        If (!(Test-Path "$($_.PsPath)\$($SoundScheme)")) {
            New-Item -Path "$($_.PsPath)\$($SoundScheme)" | Out-Null
        }
        If (!(Test-Path "$($_.PsPath)\.Current")) {
            New-Item -Path "$($_.PsPath)\.Current" | Out-Null
        }
        # Get a regular string from any possible kind of value, i.e. resolve REG_EXPAND_SZ, copy REG_SZ or empty from non-existing.
        $Data = (Get-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
        # Replace any kind of value with a regular string (similar behavior to Sound control panel).
        Set-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -Type String -Value $Data
        # Copy data from source scheme to current.
        Set-ItemProperty -Path "$($_.PsPath)\.Current" -Name "(Default)" -Type String -Value $Data
    }
    Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Type String -Value $SoundScheme
}

<#
    .DESCRIPTION
        Set sound scheme to Windows Default
#>
Function SetSoundSchemeDefault {
    Write-Output "Setting sound scheme to Windows Default..."
    $SoundScheme = ".Default"
    Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps\*\*" | ForEach-Object {
        # If scheme keys do not exist in an event, create empty ones (similar behavior to Sound control panel).
        If (!(Test-Path "$($_.PsPath)\$($SoundScheme)")) {
            New-Item -Path "$($_.PsPath)\$($SoundScheme)" | Out-Null
        }
        If (!(Test-Path "$($_.PsPath)\.Current")) {
            New-Item -Path "$($_.PsPath)\.Current" | Out-Null
        }
        # Get a regular string from any possible kind of value, i.e. resolve REG_EXPAND_SZ, copy REG_SZ or empty from non-existing.
        $Data = (Get-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
        # Replace any kind of value with a regular string (similar behavior to Sound control panel).
        Set-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -Type String -Value $Data
        # Copy data from source scheme to current.
        Set-ItemProperty -Path "$($_.PsPath)\.Current" -Name "(Default)" -Type String -Value $Data
    }
    Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Type String -Value $SoundScheme
}

<#
    .DESCRIPTION
        Disable playing Windows Startup sound
#>
Function DisableStartupSound {
    Write-Output "Disabling Windows Startup sound..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable playing Windows Startup sound
#>
Function EnableStartupSound {
    Write-Output "Enabling Windows Startup sound..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Disable changing sound scheme
#>
Function DisableChangingSoundScheme {
    Write-Output "Disabling changing sound scheme..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoChangingSoundScheme" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable changing sound scheme
#>
Function EnableChangingSoundScheme {
    Write-Output "Enabling changing sound scheme..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoChangingSoundScheme" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable verbose startup/shutdown status messages
#>
Function EnableVerboseStatus {
    Write-Output "Enabling verbose startup/shutdown status messages..."
    If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 1
    } Else {
        Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue
    }
}

<#
    .DESCRIPTION
        Disable verbose startup/shutdown status messages
#>
Function DisableVerboseStatus {
    Write-Output "Disabling verbose startup/shutdown status messages..."
    If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
        Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue
    } Else {
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 0
    }
}

<#
    .DESCRIPTION
        Disable F1 Help key in Explorer and on the Desktop
#>
Function DisableF1HelpKey {
    Write-Output "Disabling F1 Help key..."
    If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32")) {
        New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Name "(Default)" -Type "String" -Value ""
    If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64")) {
        New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -Type "String" -Value ""
}

<#
    .DESCRIPTION
        Enable F1 Help key in Explorer and on the Desktop
#>
Function EnableF1HelpKey {
    Write-Output "Enabling F1 Help key..."
    Remove-Item "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0" -Recurse -ErrorAction SilentlyContinue
}
