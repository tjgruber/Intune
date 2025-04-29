function Invoke-MDMAOAppDetection
{
    <#
    .SYNOPSIS
        Detects all applications installed in both system and user contexts.

    .DESCRIPTION
        This function extends PSADT's Get-ADTApplication function to include user-context applications
        by scanning HKEY_USERS registry uninstall keys. The output integrates seamlessly with PSADT's
        InstalledApplication type.

    .PARAMETER Name
        The name of the application to search for.

    .PARAMETER NameMatch
        Specifies the type of match to perform on the application name. Valid values are 'Contains', 'Exact', 'Wildcard', and 'Regex'.

    .PARAMETER ProductCode
        The product code of the application to retrieve information for.

    .PARAMETER ApplicationType
        Specifies the type of application to detect. Valid values are 'All', 'MSI', and 'EXE'.

    .PARAMETER IncludeUpdatesAndHotfixes
        Include matches against updates and hotfixes in the results.

    .PARAMETER FilterScript
        A script used to filter the results as they're processed.

    .INPUTS
        None

    .OUTPUTS
        PSADT.Types.InstalledApplication[]

    .EXAMPLE
        Invoke-MDMAOAppDetection -Name "Zoom"

        Detects all installations of applications containing "Zoom" in their name.

    .EXAMPLE
        Invoke-MDMAOAppDetection -Name "Zoom" -NameMatch Exact

        Detects all installations of applications named exactly "Zoom".

    .NOTES
        Function Name  : Invoke-MDMAOAppDetection
        Author         : Timothy Gruber
        Version        : 2.0.0
        Created        : 2024-10-23
        Updated        : 2024-12-31

        Version History:
        1.0.0 - (2024-10-23) Initial version.
        2.0.0 - (2024-12-31) Updated to work with PSADT 4.0.4+.
    #>

    [CmdletBinding()]
    # TODO: Re-evaluate / come back to this later.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'PSScriptAnalyzer is not recognizing the PSADT InstalledApplication type.')]
    param
    (
        [String[]]$Name,
        [ValidateSet('Contains', 'Exact', 'Wildcard', 'Regex')]
        [String]$NameMatch = 'Contains',
        [Guid[]]$ProductCode,
        [ValidateSet('All', 'MSI', 'EXE')]
        [String]$ApplicationType = 'All',
        [Switch]$IncludeUpdatesAndHotfixes,
        [ScriptBlock]$FilterScript
    )

    begin
    {
        Initialize-ADTFunction -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        Write-ADTLogEntry -Message "Starting function [$($MyInvocation.MyCommand.Name)]"
    }

    process
    {
        try
        {
            $detectedApps = @()
            $detectedUserApps = @()

            # Use PSADT's Get-ADTApplication for system-level applications
            $systemApps = Get-ADTApplication @PSBoundParameters
            $detectedApps += $systemApps

            Write-ADTLogEntry -Message "Getting information for user-context applications..."

            # Search user uninstall registry keys for additional applications
            $userKeys = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch "_Classes" }

            foreach ($userKey in $userKeys)
            {
                $uninstallPaths = @(
                    "$($userKey.Name)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    "$($userKey.Name)\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )

                foreach ($path in $uninstallPaths)
                {
                    $userApps = @(Get-ItemProperty -Path Registry::$path -ErrorAction SilentlyContinue) | Where-Object {
                        # Apply name filtering
                        if ($Name)
                        {
                            $regAppObject = $PSItem
                            switch ($NameMatch)
                            {
                                'Contains' { foreach ($eachName in $Name) { if ($regAppObject.DisplayName -like "*$eachName*") { $true; break } } }
                                'Exact' { foreach ($eachName in $Name) { if ($regAppObject.DisplayName -eq $eachName) { $true; break } } }
                                'Wildcard' { foreach ($eachName in $Name) { if ($regAppObject.DisplayName -like $eachName) { $true; break } } }
                                'Regex' { foreach ($eachName in $Name) { if ($regAppObject.DisplayName -match $eachName) { $true; break } } }
                            }
                        }
                        else
                        {
                            $true
                        }
                    }

                    foreach ($app in $userApps)
                    {
                        # Set vars
                        $appRegProps = Get-ItemProperty -LiteralPath $app.PSPath
                        $psPropNames = $appRegProps.PSObject.Properties | Select-Object -ExpandProperty Name
                        $defUriValue = [System.Uri][System.String]::Empty
                        $installDate = [System.DateTime]::MinValue

                        # Exclude anything without any properties.
                        if (!$psPropNames)
                        {
                            continue
                        }

                        # Exclude anything without a DisplayName field.
                        if (!$psPropNames.Contains('DisplayName') -or [System.String]::IsNullOrWhiteSpace($appRegProps.DisplayName))
                        {
                            continue
                        }

                        # Determine the install date. If the key has a valid property, we use it. If not, we get the LastWriteDate for the key from the registry.
                        if (!$psPropNames.Contains('InstallDate') -or ![System.DateTime]::TryParseExact($appRegProps.InstallDate, "yyyyMMdd", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$installDate))
                        {
                            $installDate = [PSADT.Utilities.RegistryUtilities]::GetRegistryKeyLastWriteTime($item.PSPath).Date
                        }

                        # Create a PSADT InstalledApplication object for each user-context app
                        $detectedUserApps += [PSADT.Types.InstalledApplication]::new(
                            $appRegProps.PSPath,
                            $appRegProps.PSParentPath,
                            $appRegProps.PSChildName,
                            $null, # ProductCode (not typically available for user-level apps)
                            $appRegProps.DisplayName,
                            $(if ($psPropNames.Contains('DisplayVersion') -and ![System.String]::IsNullOrWhiteSpace($appRegProps.DisplayVersion)) { $appRegProps.DisplayVersion }),
                            $(if ($psPropNames.Contains('UninstallString') -and ![System.String]::IsNullOrWhiteSpace($appRegProps.UninstallString)) { $appRegProps.UninstallString }),
                            $(if ($psPropNames.Contains('QuietUninstallString') -and ![System.String]::IsNullOrWhiteSpace($appRegProps.QuietUninstallString)) { $appRegProps.QuietUninstallString }),
                            $(if ($psPropNames.Contains('InstallSource') -and ![System.String]::IsNullOrWhiteSpace($appRegProps.InstallSource)) { $appRegProps.InstallSource }),
                            $(if ($psPropNames.Contains('InstallLocation') -and ![System.String]::IsNullOrWhiteSpace($appRegProps.InstallLocation)) { $appRegProps.InstallLocation }),
                            $installDate,
                            $(if ($psPropNames.Contains('Publisher') -and ![System.String]::IsNullOrWhiteSpace($appRegProps.Publisher)) { $appRegProps.Publisher }),
                            $(if ($psPropNames.Contains('HelpLink') -and ![System.String]::IsNullOrWhiteSpace($appRegProps.HelpLink) -and [System.Uri]::TryCreate($appRegProps.HelpLink, [System.UriKind]::Absolute, [ref]$defUriValue)) { $defUriValue }),
                            $(if ($psPropNames.Contains('EstimatedSize') -and ![System.String]::IsNullOrWhiteSpace($appRegProps.EstimatedSize)) { $appRegProps.EstimatedSize }),
                            !!$(if ($psPropNames.Contains('SystemComponent')) { $appRegProps.SystemComponent }),
                            $false, # WindowsInstaller
                            ([System.Environment]::Is64BitProcess -and ($appRegProps.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node'))
                        )

                        Write-ADTLogEntry -Message "Found installed application [$($app.DisplayName)]$(if ($app.DisplayVersion) {" version [$($app.DisplayVersion)]"})."

                    }
                }
            }

            if ($detectedUserApps.Count -gt 0)
            {
                $detectedApps += $detectedUserApps
            }
            else
            {
                Write-ADTLogEntry -Message "No user-context applications detected."
            }

            # Apply FilterScript if specified
            if ($FilterScript)
            {
                $detectedApps = $detectedApps | Where-Object { . $FilterScript $_ }
            }
        }
        catch
        {
            Write-Error -ErrorRecord $_
            Invoke-ADTFunctionErrorHandler -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -ErrorRecord $_
        }

        if (-not $detectedApps)
        {
            Write-ADTLogEntry -Message "No applications detected."
        }

        return ($detectedApps | Sort-Object PSPath -Unique)

    }

    end
    {
        Complete-ADTFunction -Cmdlet $PSCmdlet
    }
}
