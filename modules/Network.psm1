##########
# Network Tweaks
##########

<#
    .DESCRIPTION
        Set current network profile to private (allow file sharing, device discovery, etc.)
#>
Function SetCurrentNetworkPrivate {
    Write-Output "Setting current network profile to private..."
    Set-NetConnectionProfile -NetworkCategory Private
}

<#
    .DESCRIPTION
        Set current network profile to public (deny file sharing, device discovery, etc.)
#>
Function SetCurrentNetworkPublic {
    Write-Output "Setting current network profile to public..."
    Set-NetConnectionProfile -NetworkCategory Public
}

<#
    .DESCRIPTION
        Set unknown networks profile to private (allow file sharing, device discovery, etc.)
#>
Function SetUnknownNetworksPrivate {
    Write-Output "Setting unknown networks profile to private..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Set unknown networks profile to public (deny file sharing, device discovery, etc.)
#>
Function SetUnknownNetworksPublic {
    Write-Output "Setting unknown networks profile to public..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable automatic installation of network devices
#>
Function DisableNetDevicesAutoInst {
    Write-Output "Disabling automatic installation of network devices..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable automatic installation of network devices
#>
Function EnableNetDevicesAutoInst {
    Write-Output "Enabling automatic installation of network devices..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Stop and disable Home Groups services - Not applicable since 1803. Not applicable to Server
#>
Function DisableHomeGroups {
    Write-Output "Stopping and disabling Home Groups services..."
    If (Get-Service "HomeGroupListener" -ErrorAction SilentlyContinue) {
        Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
        Set-Service "HomeGroupListener" -StartupType Disabled
    }
    If (Get-Service "HomeGroupProvider" -ErrorAction SilentlyContinue) {
        Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
        Set-Service "HomeGroupProvider" -StartupType Disabled
    }
}

<#
    .DESCRIPTION
        Enable and start Home Groups services - Not applicable since 1803. Not applicable to Server
#>
Function EnableHomeGroups {
    Write-Output "Starting and enabling Home Groups services..."
    Set-Service "HomeGroupListener" -StartupType Manual
    Set-Service "HomeGroupProvider" -StartupType Manual
    Start-Service "HomeGroupProvider" -WarningAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
#>
Function DisableSMB1 {
    Write-Output "Disabling SMB 1.0 protocol..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

<#
    .DESCRIPTION
        Enable obsolete SMB 1.0 protocol - Disabled by default since 1709
#>
Function EnableSMB1 {
    Write-Output "Enabling SMB 1.0 protocol..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}

<#
    .DESCRIPTION
        Disable SMB Server - Completely disables file and printer sharing, but leaves the system able to connect to another SMB server as a client
        Note: Do not run this if you plan to use Docker and Shared Drives (as it uses SMB internally), see https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/216
#>
Function DisableSMBServer {
    Write-Output "Disabling SMB Server..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
}

<#
    .DESCRIPTION
        Enable SMB Server
#>
Function EnableSMBServer {
    Write-Output "Enabling SMB Server..."
    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
    Enable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
}

<#
    .DESCRIPTION
        Disable NetBIOS over TCP/IP on all currently installed network interfaces
#>
Function DisableNetBIOS {
    Write-Output "Disabling NetBIOS over TCP/IP..."
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 2
}

<#
    .DESCRIPTION
        Enable NetBIOS over TCP/IP on all currently installed network interfaces
#>
Function EnableNetBIOS {
    Write-Output "Enabling NetBIOS over TCP/IP..."
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Disable Link-Local Multicast Name Resolution (LLMNR) protocol
#>
Function DisableLLMNR {
    Write-Output "Disabling Link-Local Multicast Name Resolution (LLMNR)..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable Link-Local Multicast Name Resolution (LLMNR) protocol
#>
Function EnableLLMNR {
    Write-Output "Enabling Link-Local Multicast Name Resolution (LLMNR)..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Local-Link Discovery Protocol (LLDP) for all installed network interfaces
#>
Function DisableLLDP {
    Write-Output "Disabling Local-Link Discovery Protocol (LLDP)..."
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp"
}

<#
    .DESCRIPTION
        Enable Local-Link Discovery Protocol (LLDP) for all installed network interfaces
#>
Function EnableLLDP {
    Write-Output "Enabling Local-Link Discovery Protocol (LLDP)..."
    Enable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp"
}

<#
    .DESCRIPTION
        Disable Local-Link Topology Discovery (LLTD) for all installed network interfaces
#>
Function DisableLLTD {
    Write-Output "Disabling Local-Link Topology Discovery (LLTD)..."
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio"
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr"
}

<#
    .DESCRIPTION
        Enable Local-Link Topology Discovery (LLTD) for all installed network interfaces
#>
Function EnableLLTD {
    Write-Output "Enabling Local-Link Topology Discovery (LLTD)..."
    Enable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio"
    Enable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr"
}

<#
    .DESCRIPTION
        Disable Client for Microsoft Networks for all installed network interfaces
#>
Function DisableMSNetClient {
    Write-Output "Disabling Client for Microsoft Networks..."
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient"
}

<#
    .DESCRIPTION
        Enable Client for Microsoft Networks for all installed network interfaces
#>
Function EnableMSNetClient {
    Write-Output "Enabling Client for Microsoft Networks..."
    Enable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient"
}

<#
    .DESCRIPTION
        Disable Quality of Service (QoS) packet scheduler for all installed network interfaces
#>
Function DisableQoS {
    Write-Output "Disabling Quality of Service (QoS) packet scheduler..."
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer"
}

<#
    .DESCRIPTION
        Enable Quality of Service (QoS) packet scheduler for all installed network interfaces
#>
Function EnableQoS {
    Write-Output "Enabling Quality of Service (QoS) packet scheduler..."
    Enable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer"
}

<#
    .DESCRIPTION
        Disable IPv4 stack for all installed network interfaces
#>
Function DisableIPv4 {
    Write-Output "Disabling IPv4 stack..."
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip"
}

<#
    .DESCRIPTION
        Enable IPv4 stack for all installed network interfaces
#>
Function EnableIPv4 {
    Write-Output "Enabling IPv4 stack..."
    Enable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip"
}

<#
    .DESCRIPTION
        Disable IPv6 stack for all installed network interfaces
#>
Function DisableIPv6 {
    Write-Output "Disabling IPv6 stack..."
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
}

<#
    .DESCRIPTION
        Enable IPv6 stack for all installed network interfaces
#>
Function EnableIPv6 {
    Write-Output "Enabling IPv6 stack..."
    Enable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
}

<#
    .DESCRIPTION
        Disable Network Connectivity Status Indicator active test
        Note: This may reduce the ability of OS and other components to determine internet access, however protects against a specific type of zero-click attack.
        See https://github.com/Disassembler0/Win10-Initial-Setup-Script/pull/111 for details
#>
Function DisableNCSIProbe {
    Write-Output "Disabling Network Connectivity Status Indicator (NCSI) active test..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -Type DWord -Value 1
}

<#
    .DESCRIPTION
        Enable Network Connectivity Status Indicator active test
#>
Function EnableNCSIProbe {
    Write-Output "Enabling Network Connectivity Status Indicator (NCSI) active test..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Internet Connection Sharing (e.g. mobile hotspot)
#>
Function DisableConnectionSharing {
    Write-Output "Disabling Internet Connection Sharing..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Type DWord -Value 0
}

<#
    .DESCRIPTION
        Enable Internet Connection Sharing (e.g. mobile hotspot)
#>
Function EnableConnectionSharing {
    Write-Output "Enabling Internet Connection Sharing..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -ErrorAction SilentlyContinue
}

<#
    .DESCRIPTION
        Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
#>
Function DisableRemoteAssistance {
    Write-Output "Disabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
    Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Remove-WindowsCapability -Online | Out-Null
}

<#
    .DESCRIPTION
        Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
#>
Function EnableRemoteAssistance {
    Write-Output "Enabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
    Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Add-WindowsCapability -Online | Out-Null
}

<#
    .DESCRIPTION
        Enable Remote Desktop
#>
Function EnableRemoteDesktop {
    Write-Output "Enabling Remote Desktop..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
    Enable-NetFirewallRule -Name "RemoteDesktop*"
}

<#
    .DESCRIPTION
        Disable Remote Desktop
#>
Function DisableRemoteDesktop {
    Write-Output "Disabling Remote Desktop..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
    Disable-NetFirewallRule -Name "RemoteDesktop*"
}
