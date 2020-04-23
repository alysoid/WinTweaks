##########
# WinTweak: command-line interface for Windows Tweaks
# Author: Andrea Brandi <me@andreabrandi.com>
##########

#Requires -Version 5.1

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$modulesList = @(
    'Apps',
    'Explorer',
    'Network',
    'Privacy',
    'Security',
    'Server',
    'Service',
    'Shell',
    'Unpin'
)

function GetInformation($from) {
    $data = (Get-Command $from).ScriptBlock.Ast
    $data.GetHelpContent().Description.Trim()
    $data.Extent | Select-Object File, Text | Format-List
}

function GetDescription($from) {
    $data = (Get-Command $from).ScriptBlock.Ast
    $data.GetHelpContent().Description.Trim()
}

function TweakExists($name) {
    Get-Command -Module $modulesList | Where { $_.Name -eq "$tweak" }
}

function ApplyTweaks($tweaks) {
    foreach ($tweak in $tweaks) {
        if (TweakExists $tweak) {
            Write-Host "Apply tweak: $tweak" -ForegroundColor Cyan
            Invoke-Expression $tweak
        } else {
            Write-Host "$tweak not found" -ForegroundColor Red
        }
    }
}

function SearchTweak($query, $modules = $modulesList) {
    $results = Get-Command -Module $modules | Where { $_.Name -like "*$query*" }
    $format = @{ Expression = { $_.Source }; Label = "Module" },
              @{ Expression = { $_.Name}; Label = "Tweak" },
              @{ Expression = { GetDescription -from $_ }; Label = "Description" };

    $results | Format-Table $format
}

function WinTweaks {
    [CmdletBinding()]

    param (
        [Parameter(Position = 0)]
        [string]$command = 'help',
        [parameter(Position = 1, ValueFromRemainingArguments = $true)]
        [array]$options
    )

    switch ($command) {
        { 'Help', '--help', '/?' -contains $_ } {
            Write-Host "Usage: wintweaks <command> [<options>]`n"
            Write-Host "List of available commands`n"
            Write-Host "apply       Apply one or more tweaks"
            Write-Host "help        Show help for a command"
            Write-Host "info        Display information about a tweak"
            Write-Host "list        Print a list of all available tweaks with descriptions"
            Write-Host "search      Search available tweaks with descriptions`n"
            Write-Host "Type 'wintweaks help <commands>' to get help for a specific command."

        }
        Search {
            if ($results = SearchTweak $options) {
                Write-Host "Search Results for '$options'"
                $results
            } else {
                Write-Host "No results found for '$options'"
            }
        }
        Info {
            if ([string]::IsNullOrWhiteSpace($options)) {
                wintweaks help info
            } elseif ($results = SearchTweak $options) {
                Write-Host "Information about '$options'`n"
                GetInformation $options
            } else {
                Write-Host "No information found for '$options'"
            }
        }
        List {
            switch ($options) {
                { [string]::IsNullOrWhiteSpace($_) } {
                    SearchTweak ""
                }
                { $modulesList -contains $_ } {
                    SearchTweak "" $_
                }
                { 'modules' -eq $_ } {
                    Write-Host "List of available modules`n"
                    $modulesList | ForEach-Object { Write-Host $_ }
                    Write-Host "`nType 'wintweaks list <module>' to get module's tweaks."
                }
                default {
                    Write-Host "WinTweaks: '$options' isn't a valid module. See 'wintweaks list modules' for valid entries."
                }
            }
        }
        Apply {
            switch ($options) {
                { [string]::IsNullOrWhiteSpace($_) } {
                    Write-Host "<tweaks> missed. See 'wintweaks help apply'" -ForegroundColor Red
                }
                default {
                    ApplyTweaks $options
                }
            }
        }
        default {
            Write-Host "WinTweaks: '$command' isn't a valid command. See 'wintweaks help'."
        }
    }
}
