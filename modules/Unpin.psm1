##########
# Unpinning
##########

<#
    .DESCRIPTION
        Unpin all Start Menu tiles
        Note: This function has no counterpart. You have to pin the tiles back manually.
#>
Function UnpinStartMenuTiles {
    Write-Output "Unpinning all Start Menu tiles..."
    If ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
        Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
            $data = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
            $data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
            Set-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data" -Type Binary -Value $data.Split(",")
        }
    } ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17134) {
        $key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
        $data = $key.Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
        Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data
        Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
    }
}

<#
    .DESCRIPTION
        Unpin all Taskbar icons
        Note: This function has no counterpart. You have to pin the icons back manually.
#>
Function UnpinTaskbarIcons {
    Write-Output "Unpinning all Taskbar icons..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue
}
