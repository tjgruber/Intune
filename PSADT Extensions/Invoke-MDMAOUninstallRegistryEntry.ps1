function Invoke-MDMAOUninstallRegistryEntry
{
    <#
    .SYNOPSIS
        Adds, updates, or removes an app entry in the Windows Uninstall registry (system-wide).

    .DESCRIPTION
        Manages uninstall entries under:
            HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
        or, for 32-bit apps on 64-bit systems:
            HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall

        Behavior:
            - Without -Remove:
                * If the key does not exist, it is created.
                * If the key exists, its properties are updated.
            - With -Remove:
                * If the key exists, it is removed (recursively).
                * If the key does not exist, the operation is logged and skipped.

        Recommended properties exposed as parameters:
            - DisplayName
            - DisplayVersion
            - Publisher
            - InstallLocation
            - UninstallString
            - DisplayIcon

    .PARAMETER KeyName
        The registry subkey name under Uninstall.
        Example:
            HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<KeyName>

        Typically this should be a stable, unique identifier (e.g., app ID or product code).

    .PARAMETER DisplayName
        The display name shown in "Installed apps" / "Programs and Features".
        Required when not using -Remove.

    .PARAMETER DisplayVersion
        The version displayed for the app (e.g., 1.2.3.4).

    .PARAMETER Publisher
        The publisher / vendor name.

    .PARAMETER InstallLocation
        The installation directory path for the app.

    .PARAMETER UninstallString
        The command line used to uninstall the app
        (e.g., "C:\Program Files\MyApp\uninstall.exe" /uninstall).
        Required when not using -Remove.

    .PARAMETER DisplayIcon
        The path to the icon or EXE used as the display icon.

    .PARAMETER Wow6432
        If specified, write the uninstall entry under WOW6432Node for 32-bit apps
        on 64-bit Windows.

    .PARAMETER Remove
        If specified, removes the uninstall entry instead of adding/updating it.

    .EXAMPLE
        # Add or update an uninstall entry
        $InvokeMDMAOUninstallAppParams = @{
            KeyName         = 'MyApp'
            DisplayName     = 'My App'
            DisplayVersion  = '1.2.3.4'
            Publisher       = 'My Company, Inc.'
            InstallLocation = 'C:\Program Files\MyApp'
            UninstallString = '"C:\Program Files\MyApp\uninstall.exe" /uninstall'
            DisplayIcon     = 'C:\Program Files\MyApp\MyApp.exe'
        }

        Invoke-MDMAOUninstallRegistryEntry @InvokeMDMAOUninstallAppParams

    .EXAMPLE
        # Remove an existing uninstall entry
        Invoke-MDMAOUninstallRegistryEntry -KeyName 'MyApp' -Remove

    .NOTES
        Function Name  : Invoke-MDMAOUninstallRegistryEntry
        Author         : Timothy Gruber
        Version        : 1.0.0
        Created        : 2025-12-03
        Updated        : 2025-12-03

        Version History:
        1.0.0 - (2025-12-03) Initial version.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$KeyName,

        [Parameter()]
        [string]$DisplayName,

        [Parameter()]
        [string]$DisplayVersion,

        [Parameter()]
        [string]$Publisher,

        [Parameter()]
        [string]$InstallLocation,

        [Parameter()]
        [string]$UninstallString,

        [Parameter()]
        [string]$DisplayIcon,

        [Parameter()]
        [switch]$Wow6432,

        [Parameter()]
        [switch]$Remove
    )

    begin
    {
        Initialize-ADTFunction -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        $operation = if ($Remove.IsPresent)
        {
            'Remove'
        }
        else
        {
            'AddOrModify'
        }

        Write-ADTLogEntry -Message "Starting function [$($MyInvocation.MyCommand.Name)] with [Operation]: [$operation] and [KeyName]: [$KeyName]."

        # Base uninstall registry path (system-wide)
        $script:BasePath = if ($Wow6432.IsPresent)
        {
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        }
        else
        {
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        }

        $script:UninstallKeyPath = Join-Path -Path $script:BasePath -ChildPath $KeyName

        # Target name used in logging for readability
        $script:TargetName = if (-not [string]::IsNullOrWhiteSpace($DisplayName))
        {
            $DisplayName
        }
        else
        {
            $KeyName
        }

        # Validation for Add/Modify mode
        if (-not $Remove.IsPresent)
        {
            if ([string]::IsNullOrWhiteSpace($DisplayName))
            {
                $message = "DisplayName is required when not using [-Remove] for [KeyName]: [$KeyName]."
                Write-ADTLogEntry -Message $message -Severity Error
                throw $message
            }

            if ([string]::IsNullOrWhiteSpace($UninstallString))
            {
                $message = "UninstallString is required when not using [-Remove] for [KeyName]: [$KeyName]."
                Write-ADTLogEntry -Message $message -Severity Error
                throw $message
            }
        }
    }

    process
    {
        try
        {
            if ($Remove.IsPresent)
            {
                # REMOVE MODE
                if (Test-Path -Path $script:UninstallKeyPath)
                {
                    Write-ADTLogEntry -Message "Removing uninstall registry entry for [$($script:TargetName)] at path: [$($script:UninstallKeyPath)]."
                    Remove-ADTRegistryKey -Path $script:UninstallKeyPath -Recurse
                }
                else
                {
                    Write-ADTLogEntry -Message "Uninstall registry entry not found at path: [$($script:UninstallKeyPath)]. Nothing to remove." -Severity Warning
                }
            }
            else
            {
                # ADD / MODIFY MODE
                if (-not (Test-Path -Path $script:UninstallKeyPath))
                {
                    Write-ADTLogEntry -Message "Creating uninstall registry entry for [$($script:TargetName)] at path: [$($script:UninstallKeyPath)]."
                    Set-ADTRegistryKey -LiteralPath $script:UninstallKeyPath
                }
                else
                {
                    Write-ADTLogEntry -Message "Updating uninstall registry entry for [$($script:TargetName)] at path: [$($script:UninstallKeyPath)]."
                }

                $properties = @{
                    DisplayName     = $DisplayName
                    DisplayVersion  = $DisplayVersion
                    Publisher       = $Publisher
                    InstallLocation = $InstallLocation
                    UninstallString = $UninstallString
                    DisplayIcon     = $DisplayIcon
                }

                foreach ($property in $properties.GetEnumerator())
                {
                    if (-not [string]::IsNullOrWhiteSpace($property.Value))
                    {
                        Set-ADTRegistryKey -LiteralPath $script:UninstallKeyPath -Name $property.Key -Type 'String' -Value $property.Value
                        Write-ADTLogEntry -Message "Set [$($property.Key)] to: [$($property.Value)] on: [$($script:UninstallKeyPath)]."
                    }
                }
            }
        }
        catch
        {
            $message = "Failed to perform [Operation]: [$operation] on uninstall registry entry for [KeyName]: [$KeyName] with error: [$($_.Exception.Message)]."
            Write-ADTLogEntry -Message $message -Severity Error
            throw
        }
    }

    end
    {
        Write-ADTLogEntry -Message "Completed function [$($MyInvocation.MyCommand.Name)] for [Operation]: [$operation] and [KeyName]: [$KeyName]."
        Complete-ADTFunction -Cmdlet $PSCmdlet
    }
}
