##########
# Explorer UI Tweaks
##########

<#
    .DESCRIPTION
        Show full directory path in Explorer title bar
#>
Function ShowExplorerTitleFullPath {
    Write-Output "Showing full directory path in Explorer title bar..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Hide full directory path in Explorer title bar, only directory name will be shown
#>
Function HideExplorerTitleFullPath {
    Write-Output "Hiding full directory path in Explorer title bar..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show known file extensions
#>
Function ShowKnownExtensions {
    Write-Output "Showing known file extensions..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Hide known file extensions
#>
Function HideKnownExtensions {
    Write-Output "Hiding known file extensions..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Show hidden files
#>
Function ShowHiddenFiles {
    Write-Output "Showing hidden files..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Hide hidden files
#>
Function HideHiddenFiles {
    Write-Output "Hiding hidden files..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
}

<#
    .DESCRIPTION
        Show protected operating system files
#>
Function ShowSuperHiddenFiles {
    Write-Output "Showing protected operating system files..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Hide protected operating system files
#>
Function HideSuperHiddenFiles {
    Write-Output "Hiding protected operating system files..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Show empty drives (with no media)
#>
Function ShowEmptyDrives {
    Write-Output "Showing empty drives (with no media)..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Hide empty drives (with no media)
#>
Function HideEmptyDrives {
    Write-Output "Hiding empty drives (with no media)..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show folder merge conflicts
#>
Function ShowFolderMergeConflicts {
    Write-Output "Showing folder merge conflicts..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideMergeConflicts" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Hide folder merge conflicts
#>
Function HideFolderMergeConflicts {
    Write-Output "Hiding folder merge conflicts..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideMergeConflicts" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable Explorer navigation pane expanding to current folder
#>
Function EnableNavPaneExpand {
    Write-Output "Enabling navigation pane expanding to current folder..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable Explorer navigation pane expanding to current folder
#>
Function DisableNavPaneExpand {
    Write-Output "Disabling navigation pane expanding to current folder..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show all folders in Explorer navigation pane
#>
Function ShowNavPaneAllFolders {
    Write-Output "Showing all folders in Explorer navigation pane..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Hide all folders in Explorer navigation pane except the basic ones (Quick access, OneDrive, This PC, Network), some of which can be disabled using other tweaks
#>
Function HideNavPaneAllFolders {
    Write-Output "Hiding all folders in Explorer navigation pane (except the basic ones)..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Enable launching folder windows in a separate process
#>
Function EnableFldrSeparateProcess {
    Write-Output "Enabling launching folder windows in a separate process..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SeparateProcess" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable launching folder windows in a separate process
#>
Function DisableFldrSeparateProcess {
    Write-Output "Disabling launching folder windows in a separate process..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SeparateProcess" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable restoring previous folder windows at logon
#>
Function EnableRestoreFldrWindows {
    Write-Output "Enabling restoring previous folder windows at logon..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "PersistBrowsers" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Disable restoring previous folder windows at logon
#>
Function DisableRestoreFldrWindows {
    Write-Output "Disabling restoring previous folder windows at logon..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "PersistBrowsers" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show coloring of encrypted or compressed NTFS files (green for encrypted, blue for compressed)
#>
Function ShowEncCompFilesColor {
    Write-Output "Showing coloring of encrypted or compressed NTFS files..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Hide coloring of encrypted or compressed NTFS files
#>
Function HideEncCompFilesColor {
    Write-Output "Hiding coloring of encrypted or compressed NTFS files..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Sharing Wizard
#>
Function DisableSharingWizard {
    Write-Output "Disabling Sharing Wizard..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable Sharing Wizard
#>
Function EnableSharingWizard {
    Write-Output "Enabling Sharing Wizard..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide item selection checkboxes
#>
Function HideSelectCheckboxes {
    Write-Output "Hiding item selection checkboxes..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Show item selection checkboxes
#>
Function ShowSelectCheckboxes {
    Write-Output "Showing item selection checkboxes..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Hide sync provider notifications
#>
Function HideSyncNotifications {
    Write-Output "Hiding sync provider notifications..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Show sync provider notifications
#>
Function ShowSyncNotifications {
    Write-Output "Showing sync provider notifications..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Hide recently and frequently used item shortcuts in Explorer
        Note: This is only UI tweak to hide the shortcuts. In order to stop creating most recently used (MRU) items lists everywhere, use privacy tweak 'DisableRecentFiles' instead.
#>
Function HideRecentShortcuts {
    Write-Output "Hiding recent shortcuts in Explorer..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Show recently and frequently used item shortcuts in Explorer
#>
Function ShowRecentShortcuts {
    Write-Output "Showing recent shortcuts in Explorer..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Change default Explorer view to This PC
#>
Function SetExplorerThisPC {
    Write-Output "Changing default Explorer view to This PC..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Change default Explorer view to Quick Access
#>
Function SetExplorerQuickAccess {
    Write-Output "Changing default Explorer view to Quick Access..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide Quick Access from Explorer navigation pane
#>
Function HideQuickAccess {
    Write-Output "Hiding Quick Access from Explorer navigation pane..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Show Quick Access in Explorer navigation pane
#>
Function ShowQuickAccess {
    Write-Output "Showing Quick Access in Explorer navigation pane..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide Recycle Bin shortcut from desktop
#>
Function HideRecycleBinFromDesktop {
    Write-Output "Hiding Recycle Bin shortcut from desktop..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Show Recycle Bin shortcut on desktop
#>
Function ShowRecycleBinOnDesktop {
    Write-Output "Showing Recycle Bin shortcut on desktop..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show This PC shortcut on desktop
#>
Function ShowThisPCOnDesktop {
    Write-Output "Showing This PC shortcut on desktop..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Hide This PC shortcut from desktop
#>
Function HideThisPCFromDesktop {
    Write-Output "Hiding This PC shortcut from desktop..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show User Folder shortcut on desktop
#>
Function ShowUserFolderOnDesktop {
    Write-Output "Showing User Folder shortcut on desktop..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Hide User Folder shortcut from desktop
#>
Function HideUserFolderFromDesktop {
    Write-Output "Hiding User Folder shortcut from desktop..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show Control panel shortcut on desktop
#>
Function ShowControlPanelOnDesktop {
    Write-Output "Showing Control panel shortcut on desktop..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Hide Control panel shortcut from desktop
#>
Function HideControlPanelFromDesktop {
    Write-Output "Hiding Control panel shortcut from desktop..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show Network shortcut on desktop
#>
Function ShowNetworkOnDesktop {
    Write-Output "Showing Network shortcut on desktop..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" )) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"  -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" )) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Hide Network shortcut from desktop
#>
Function HideNetworkFromDesktop {
    Write-Output "Hiding Network shortcut from desktop..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
#>
Function ShowBuildNumberOnDesktop {
    Write-Output "Showing Windows build number on desktop..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Remove Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
#>
Function HideBuildNumberFromDesktop {
    Write-Output "Hiding Windows build number from desktop..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Hide Desktop icon from This PC - The icon remains in personal folders and open/save dialogs
#>
Function HideDesktopFromThisPC {
    Write-Output "Hiding Desktop icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show Desktop icon in This PC
#>
Function ShowDesktopInThisPC {
    Write-Output "Showing Desktop icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" | Out-Null
    }
}

<#
    .DESCRIPTION
        Hide Desktop icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
#>
Function HideDesktopFromExplorer {
    Write-Output "Hiding Desktop icon from Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

<#
    .DESCRIPTION
        Show Desktop icon in Explorer namespace
#>
Function ShowDesktopInExplorer {
    Write-Output "Showing Desktop icon in Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

<#
    .DESCRIPTION
        Hide Documents icon from This PC - The icon remains in personal folders and open/save dialogs
#>
Function HideDocumentsFromThisPC {
    Write-Output "Hiding Documents icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show Documents icon in This PC
#>
Function ShowDocumentsInThisPC {
    Write-Output "Showing Documents icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" | Out-Null
    }
}

<#
    .DESCRIPTION
        Hide Documents icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
#>
Function HideDocumentsFromExplorer {
    Write-Output "Hiding Documents icon from Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

<#
    .DESCRIPTION
        Show Documents icon in Explorer namespace
#>
Function ShowDocumentsInExplorer {
    Write-Output "Showing Documents icon in Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

<#
    .DESCRIPTION
        Hide Downloads icon from This PC - The icon remains in personal folders and open/save dialogs
#>
Function HideDownloadsFromThisPC {
    Write-Output "Hiding Downloads icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show Downloads icon in This PC
#>
Function ShowDownloadsInThisPC {
    Write-Output "Showing Downloads icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" | Out-Null
    }
}

<#
    .DESCRIPTION
        Hide Downloads icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
#>
Function HideDownloadsFromExplorer {
    Write-Output "Hiding Downloads icon from Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

<#
    .DESCRIPTION
        Show Downloads icon in Explorer namespace
#>
Function ShowDownloadsInExplorer {
    Write-Output "Showing Downloads icon in Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

<#
    .DESCRIPTION
        Hide Music icon from This PC - The icon remains in personal folders and open/save dialogs
#>
Function HideMusicFromThisPC {
    Write-Output "Hiding Music icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show Music icon in This PC
#>
Function ShowMusicInThisPC {
    Write-Output "Showing Music icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" | Out-Null
    }
}

<#
    .DESCRIPTION
        Hide Music icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
#>
Function HideMusicFromExplorer {
    Write-Output "Hiding Music icon from Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

<#
    .DESCRIPTION
        Show Music icon in Explorer namespace
#>
Function ShowMusicInExplorer {
    Write-Output "Showing Music icon in Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

<#
    .DESCRIPTION
        Hide Pictures icon from This PC - The icon remains in personal folders and open/save dialogs
#>
Function HidePicturesFromThisPC {
    Write-Output "Hiding Pictures icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show Pictures icon in This PC
#>
Function ShowPicturesInThisPC {
    Write-Output "Showing Pictures icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" | Out-Null
    }
}

<#
    .DESCRIPTION
        Hide Pictures icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
#>
Function HidePicturesFromExplorer {
    Write-Output "Hiding Pictures icon from Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

<#
    .DESCRIPTION
        Show Pictures icon in Explorer namespace
#>
Function ShowPicturesInExplorer {
    Write-Output "Showing Pictures icon in Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

<#
    .DESCRIPTION
        Hide Videos icon from This PC - The icon remains in personal folders and open/save dialogs
#>
Function HideVideosFromThisPC {
    Write-Output "Hiding Videos icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show Videos icon in This PC
#>
Function ShowVideosInThisPC {
    Write-Output "Showing Videos icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" | Out-Null
    }
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" | Out-Null
    }
}

<#
    .DESCRIPTION
        Hide Videos icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
#>
Function HideVideosFromExplorer {
    Write-Output "Hiding Videos icon from Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

<#
    .DESCRIPTION
        Show Videos icon in Explorer namespace
#>
Function ShowVideosInExplorer {
    Write-Output "Showing Videos icon in Explorer namespace..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

<#
    .DESCRIPTION
        Hide 3D Objects icon from This PC - The icon remains in personal folders and open/save dialogs
#>
Function Hide3DObjectsFromThisPC {
    Write-Output "Hiding 3D Objects icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show 3D Objects icon in This PC
#>
Function Show3DObjectsInThisPC {
    Write-Output "Showing 3D Objects icon in This PC..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" | Out-Null
    }
}

<#
    .DESCRIPTION
        Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
#>
Function Hide3DObjectsFromExplorer {
    Write-Output "Hiding 3D Objects icon from Explorer namespace..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
    If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

<#
    .DESCRIPTION
        Show 3D Objects icon in Explorer namespace
#>
Function Show3DObjectsInExplorer {
    Write-Output "Showing 3D Objects icon in Explorer namespace..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Hide 'Include in library' context menu item
#>
Function HideIncludeInLibraryMenu {
    Write-Output "Hiding 'Include in library' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    Remove-Item -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show 'Include in library' context menu item
#>
Function ShowIncludeInLibraryMenu {
    Write-Output "Showing 'Include in library' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    New-Item -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -Name "(Default)" -Type String -Value "{3dad6c5d-2167-4cae-9914-f99e41c12cfa}"
}

<#
    .DESCRIPTION
        Hide 'Give access to' (until 1703 'Share With') context menu item.
#>
Function HideGiveAccessToMenu {
    Write-Output "Hiding 'Give access to' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue

}

<#
    .DESCRIPTION
        Show 'Give access to' (until 1703 'Share With') context menu item.
#>
Function ShowGiveAccessToMenu {
    Write-Output "Showing 'Give access to' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    New-Item -Path "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"
    New-Item -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"
    New-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"
    New-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"
}

<#
    .DESCRIPTION
        Hide 'Share' context menu item. Applicable since 1709
#>
Function HideShareMenu {
    Write-Output "Hiding 'Share' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Show 'Share' context menu item. Applicable since 1709
#>
Function ShowShareMenu {
    Write-Output "Showing 'Share' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    New-Item -Path "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -Name "(Default)" -Type String -Value "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}"
}

<#
    .DESCRIPTION
        Disable thumbnails, show only file extension icons
#>
Function DisableThumbnails {
    Write-Output "Disabling thumbnails..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable thumbnails
#>
Function EnableThumbnails {
    Write-Output "Enabling thumbnails..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Disable creation of thumbnail cache files
#>
Function DisableThumbnailCache {
    Write-Output "Disabling creation of thumbnail cache files..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable creation of thumbnail cache files
#>
Function EnableThumbnailCache {
    Write-Output "Enabling creation of thumbnail cache files..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable creation of Thumbs.db thumbnail cache files on network folders
#>
Function DisableThumbsDBOnNetwork {
    Write-Output "Disabling creation of Thumbs.db on network folders..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable creation of Thumbs.db thumbnail cache files on network folders
#>
Function EnableThumbsDBOnNetwork {
    Write-Output "Enabling creation of Thumbs.db on network folders..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -ErrorAction SilentlyContinue
}
