function Invoke-MDMAOClassicAppDetectionExt
{
    <#
    .SYNOPSIS
        Detects installed applications in both system and user contexts and (optionally) AppX/MSIX.

    .DESCRIPTION
        Extends PSADT's Get-ADTApplication:
        - Scans HKU uninstall keys for per-user apps with controllable scope.
        - Optionally detects AppX/MSIX (installed & provisioned) unless -SkipAppx is used.
        - Supports coarse app type gating via -ApplicationType (All/MSI/EXE/AppX) and fine-grained -SkipMSI/-SkipEXE.
        - Returns PSADT.Types.InstalledApplication objects. AppX/MSIX hits receive
          PSObject extended properties to carry their identity and removal metadata.

    .PARAMETER Name
        One or more names to match against DisplayName (or AppX Name/DisplayName).

    .PARAMETER NameMatch
        How to match Name. One of: Contains (default), Exact, Wildcard, Regex.

    .PARAMETER ProductCode
        One or more MSI ProductCode GUIDs to match. When specified, EXE entries are excluded
        (for both system and user contexts).

    .PARAMETER ApplicationType
        All (default) -> MSI + EXE (+ AppX unless -SkipAppx)
        MSI           -> MSI only (classic)
        EXE           -> EXE only (classic)
        AppX          -> AppX/MSIX only

        NOTE: -SkipMSI/-SkipEXE further refine classic detection; -SkipAppx disables AppX.

    .PARAMETER IncludeUpdatesAndHotfixes
        Include updates/hotfixes in results (suppressed by default for classic apps).

    .PARAMETER FilterScript
        A ScriptBlock run against each result to include/exclude (e.g. version gating).
        Where-Object style ScriptBlock for post-filtering.
        # TODO: Implement better filtering logic when time permits.

    .PARAMETER IncludeAllUsers
        [Parameter set: AllUsers] Scan all loaded user hives under HKU (excludes *_Classes,
        .DEFAULT, and well-known service SIDs). Note: unloaded profiles are not included.

    .PARAMETER IncludeLoggedOnUsers
        [Parameter set: LoggedOnUsers / Default] Scan only the logged-on user hive(s).
        Uses PSADT session vars ($CurrentLoggedOnUserSession, $UsersLoggedOn) and intersects
        with currently loaded HKU SIDs.

    .PARAMETER SkipMSI
        When set, filters out MSI (Windows Installer) results from classic detection.

    .PARAMETER SkipEXE
        When set, filters out non-MSI (EXE/other) results from classic detection.

    .PARAMETER SkipAppx
        When set, skips detection of AppX/MSIX (installed and provisioned).

    .OUTPUTS
        PSADT.Types.InstalledApplication[]

    .EXAMPLE
        Invoke-MDMAOClassicAppDetectionExt -Name 'Slack'
        Detect Slack for the currently logged-on user(s) only (default scope).

    .EXAMPLE
        Invoke-MDMAOClassicAppDetectionExt -Name 'Visual Studio Code' -IncludeAllUsers -SkipAppx
        Inventory Visual Studio Code across *all loaded* user profiles (classic only; useful for reporting).

    .EXAMPLE
        Invoke-MDMAOClassicAppDetectionExt -Name 'Google Chrome' -NameMatch Exact -ApplicationType MSI
        Exact-name match of MSI installs only.

    .EXAMPLE
        Invoke-MDMAOClassicAppDetectionExt -ProductCode '{8A69D345-D564-463C-AFF1-A69D9E530F96}'
        Detect by MSI ProductCode GUID (EXE entries are excluded automatically).

    .EXAMPLE
        # Where-Object style filter script:
        # Keep only apps matching the 7-Zip regex pattern
        $7zipFilterScript = { $_.DisplayName -match '^7-Zip\s\d{2}\.\d{2}(\s\(.+?\))?$' }
        Invoke-MDMAOClassicAppDetectionExt -FilterScript $7zipFilterScript

    .EXAMPLE
        Invoke-MDMAOClassicAppDetectionExt -ApplicationType All -SkipMSI
        Detect classic EXE + AppX (unless -SkipAppx).

    .NOTES
        Function Name  : Invoke-MDMAOClassicAppDetectionExt
        Author         : Timothy Gruber
        Version        : 3.4.1
        Created        : 2024-10-23
        Updated        : 2025-09-29

        Version History:
        1.0.0 - (2024-10-23) Initial version.
        2.0.0 - (2025-12-31) Updated to work with PSADT 4.0.4+.
        3.0.0 - (2025-08-19) Refactor & add IncludeAllUsers / IncludeLoggedOnUsers and fixes for PSADT 4.1+.
        3.1.0 - (2025-08-19) Switched to parameter sets for mutual exclusivity; expanded help.
        3.2.0 - (2025-08-20) Fixed SID and App matching, lastwritetime, and scriptfilter.
        3.3.0 - (2025-09-12) Add AppX discovery + -SkipAppx switch and AppX extended properties via WinRT PackageManager.
        3.4.0 - (2025-09-15) Implement -SkipMSI/-SkipEXE across system + per-user classic detection; gate AppX by -ApplicationType/-SkipAppx;
                             prevent passing non-PSADT params to Get-ADTApplication; honor ProductCode in per-user MSI; light update/hotfix suppression for user hive.
        3.4.1 - (2025-09-29) Fix DisplayName check for app candidates.
    #>

    [CmdletBinding(DefaultParameterSetName = 'LoggedOnUsers')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'PSScriptAnalyzer does not recognize PSADT InstalledApplication type.')]
    param
    (
        [Parameter()]
        [String[]]$Name,

        [Parameter()]
        [ValidateSet('Contains', 'Exact', 'Wildcard', 'Regex')]
        [String]$NameMatch = 'Contains',

        [Parameter()]
        [Guid[]]$ProductCode,

        [Parameter()]
        [ValidateSet('All', 'MSI', 'EXE', 'AppX')]
        [String]$ApplicationType = 'All',

        [Parameter()]
        [Switch]$IncludeUpdatesAndHotfixes,

        [Parameter()]
        [ScriptBlock]$FilterScript,

        [Parameter(ParameterSetName = 'AllUsers')]
        [Switch]$IncludeAllUsers,

        [Parameter(ParameterSetName = 'LoggedOnUsers')]
        [Switch]$IncludeLoggedOnUsers,

        [Parameter()]
        [Switch]$SkipMSI,

        [Parameter()]
        [Switch]$SkipEXE,

        [Parameter()]
        [Switch]$SkipAppx
    )

    begin
    {
        Initialize-ADTFunction -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Write-ADTLogEntry -Message "Starting function [$($MyInvocation.MyCommand.Name)] (Set: $($PSCmdlet.ParameterSetName))"

        # MARK: Helper Functions
        # Derive one-time intent flags (classic vs AppX)
        $wantMSI = ( $ApplicationType -in @('All', 'MSI') ) -and (-not $SkipMSI)
        $wantEXE = ( $ApplicationType -in @('All', 'EXE') ) -and (-not $SkipEXE)
        $wantAppx = ( $ApplicationType -in @('All', 'AppX') ) -and (-not $SkipAppx)

        # Helper to resolve which HKU SIDs to scan
        function Get-UserHiveSidsToScan
        {
            # Exclude service/.DEFAULT and *_Classes
            $sidFilter = {
                param($name)
                $leaf = ($name -split '\\')[-1]
                if ($leaf -like '*_Classes') { return $false }
                if ($leaf -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20', '.DEFAULT')) { return $false }
                return ($leaf -match '^S-1-(5-21|12-1)-[0-9\-]+$') # typical user SIDs
            }

            if ($PSCmdlet.ParameterSetName -eq 'AllUsers')
            {
                # IncludeAllUsers: every real user SID that is currently loaded
                $sids = Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction SilentlyContinue |
                    Where-Object { & $sidFilter $_.Name } |
                        ForEach-Object { ($_.Name -split '\\')[-1] } |
                            Sort-Object -Unique

                Write-ADTLogEntry -Message "Scanning user-context apps for ALL loaded users: [$($sids -join ', ')]"
                return $sids
            }
            else
            {
                # Default/LoggedOnUsers
                $sids = @()

                # Prefer PSADT's current logged-on session (has SID)
                if ($CurrentLoggedOnUserSession -and $CurrentLoggedOnUserSession.SID)
                {
                    $sids += [String]$CurrentLoggedOnUserSession.SID
                }

                # If IncludeLoggedOnUsers, use PSADT's UsersLoggedOn session variable
                if ($UsersLoggedOn)
                {
                    foreach ($acct in $UsersLoggedOn)
                    {
                        try
                        {
                            $nt = [System.Security.Principal.NTAccount]$acct.ToString()
                            $sidObj = $nt.Translate([System.Security.Principal.SecurityIdentifier])
                            if ($sidObj -and $sidObj.Value) { $sids += $sidObj.Value }
                        }
                        catch
                        {
                            Write-ADTLogEntry -Message "Failed to translate NTAccount [$acct] to SID with error: [$_]" -Severity Error
                        }
                    }
                }

                # Filter out unloaded user hives
                $loadedHku = Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction SilentlyContinue |
                    Where-Object { & $sidFilter $_.Name } |
                        ForEach-Object { ($_.Name -split '\\')[-1] }

                $sids = $sids | Where-Object { $_ -in $loadedHku } | Sort-Object -Unique
                Write-ADTLogEntry -Message "Scanning user-context apps for LOGGED-ON users only: [$($sids -join ', ')]"
                return $sids
            }
        }

        # Helper function to match names
        function Test-NameMatch
        {
            param
            (
                [Parameter(Mandatory)] [String]$Candidate,
                [String[]]$Patterns,
                [ValidateSet('Contains', 'Exact', 'Wildcard', 'Regex')] [String]$Mode = 'Contains'
            )
            if (-not $Patterns -or $Patterns.Count -eq 0) { return $true }

            foreach ($p in $Patterns)
            {
                switch ($Mode)
                {
                    'Contains' { if ($Candidate -like "*$p*") { return $true } }
                    'Exact' { if ($Candidate -ceq $p  ) { return $true } }
                    'Wildcard' { if ($Candidate -like $p  ) { return $true } }
                    'Regex' { if ($Candidate -match $p  ) { return $true } }
                }
            }
            return $false
        }
    }

    process
    {
        try
        {
            $detectedApps = @()
            $detectedUserApps = @()

            # MARK: Classic App Detection
            # Copy PSBoundParameters and strip extension-only switches before splatting downstream
            if ($wantMSI -or $wantEXE)
            {
                $baseParams = @{}
                $PSBoundParameters.GetEnumerator() | ForEach-Object { $baseParams[$_.Key] = $_.Value }
                $null = $baseParams.Remove('IncludeAllUsers')
                $null = $baseParams.Remove('IncludeLoggedOnUsers')
                $null = $baseParams.Remove('SkipAppx')
                if ($ApplicationType -eq 'AppX') { $null = $baseParams.Remove('ApplicationType') }

                # Classic (registry) apps via PSADT
                $systemApps = Get-ADTApplication @baseParams

                # Coarse app-type narrowing (AND with Skip switches)
                if ($ApplicationType -eq 'MSI')
                {
                    $systemApps = $systemApps | Where-Object { $_.WindowsInstaller }
                }
                elseif ($ApplicationType -eq 'EXE')
                {
                    $systemApps = $systemApps | Where-Object { -not $_.WindowsInstaller }
                }
                elseif ($ApplicationType -eq 'AppX')
                {
                    $systemApps = @()
                }

                if ($SkipMSI)
                {
                    $systemApps = $systemApps | Where-Object { -not $_.WindowsInstaller }
                }
                if ($SkipEXE)
                {
                    $systemApps = $systemApps | Where-Object { $_.WindowsInstaller }
                }

                $detectedApps += $systemApps
            }
            else
            {
                Write-ADTLogEntry -Message "Skipping classic system detection due to -ApplicationType/-Skip* selections."
            }

            # User-context classic apps (HKU)
            if ($wantMSI -or $wantEXE)
            {
                Write-ADTLogEntry -Message "Getting information for user-context applications..."
                $userSids = Get-UserHiveSidsToScan

                foreach ($sid in $userSids)
                {
                    $uninstallPaths = @(
                        "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                        "Registry::HKEY_USERS\$sid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                    )

                    foreach ($path in $uninstallPaths)
                    {
                        $raw = @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)

                        $userApps = $raw | Where-Object {
                            if ($Name)
                            {
                                # Must have a non-empty DisplayName before any matching
                                if (-not $PSItem.PSObject.Properties.Match('DisplayName') -or [String]::IsNullOrWhiteSpace($PSItem.DisplayName))
                                {
                                    return $false
                                }
                                Test-NameMatch -Candidate $PSItem.DisplayName -Patterns $Name -Mode $NameMatch
                            }
                            else
                            {
                                $true
                            }
                        }

                        foreach ($app in $userApps)
                        {
                            # Read full properties once
                            $appRegProps = Get-ItemProperty -LiteralPath $app.PSPath
                            $psPropNames = $appRegProps.PSObject.Properties | Select-Object -ExpandProperty Name
                            if (-not $psPropNames) { continue }

                            # Must have a non-empty DisplayName
                            if (-not ($psPropNames -contains 'DisplayName') -or [String]::IsNullOrWhiteSpace($appRegProps.DisplayName)) { continue }

                            $defUriValue = [System.Uri][System.String]::Empty
                            $installDate = [System.DateTime]::MinValue
                            $defaultGuid = [System.Guid]::Empty

                            # Determine if Windows installer and if so, get the GUID.
                            $windowsInstaller = [bool]( ($psPropNames -contains 'WindowsInstaller') -and $appRegProps.WindowsInstaller )

                            # MSI GUID if applicable
                            $appMsiGuid = $null
                            if ($windowsInstaller -and [System.Guid]::TryParse($appRegProps.PSChildName, [ref]$defaultGuid))
                            {
                                $appMsiGuid = $defaultGuid
                            }

                            # If ProductCode was supplied, only keep MSI with matching GUID
                            if ($PSBoundParameters.ContainsKey('ProductCode'))
                            {
                                if (-not $windowsInstaller) { continue }
                                if ($ProductCode -notcontains $appMsiGuid) { continue }
                            }

                            # Enforce classic type gating and Skip switches
                            if ($windowsInstaller -and -not $wantMSI) { continue }
                            if (-not $windowsInstaller -and -not $wantEXE) { continue }

                            # Install date: prefer InstallDate yyyyMMdd, else registry key last-write time
                            if ( -not ($psPropNames -contains 'InstallDate') -or
                                -not [System.DateTime]::TryParseExact($appRegProps.InstallDate, 'yyyyMMdd',
                                    [System.Globalization.CultureInfo]::InvariantCulture,
                                    [System.Globalization.DateTimeStyles]::None, [ref]$installDate) )
                            {
                                try
                                {
                                    $installDate = [PSADT.RegistryManagement.RegistryUtilities]::GetRegistryKeyLastWriteTime($app.PSPath).Date
                                }
                                catch
                                {
                                    Write-ADTLogEntry -Message "Failed to get last-write time for registry key [$($app.PSPath)] with error: [$_]" -Severity Error
                                }
                            }

                            <# [PSADT.Types.InstalledApplication] Properties:
                                1) psPath: The registry key that contains the uninstall entry.
                                2) psParentPath: The registry key for the subkey's parent.
                                3) psChildName: The registry subkey for uninstalling the application.
                                4) productCode: The product code for the application.
                                5) displayName: The display name of the application.
                                6) displayVersion: The version of the application.
                                7) uninstallString: The uninstall string used to remove the application.
                                8) quietUninstallString: The quiet uninstall string used to remove the application.
                                9) installSource: The source from which the application was installed.
                                10) installLocation: The location where the application is installed.
                                11) installDate: The date the application was installed (as a string)
                                12) publisher: The publisher of the application.
                                13) helpLink: The publisher's help link of the application.
                                14) estimatedSize: The estimated on-disk usage of the application.
                                15) systemComponent: A value indicating whether the application is a system component.
                                16) windowsInstaller: A value indicating whether the application is an MSI.
                                17) is64BitApplication: A value indicating whether the application is a 64-bit application.
                            #>
                            $detectedUserApps += [PSADT.Types.InstalledApplication]::new(
                                $appRegProps.PSPath,
                                $appRegProps.PSParentPath,
                                $appRegProps.PSChildName,
                                $appMsiGuid,
                                $appRegProps.DisplayName,
                                $(if ($psPropNames -contains 'DisplayVersion' -and $appRegProps.DisplayVersion) { $appRegProps.DisplayVersion }),
                                $(if ($psPropNames -contains 'UninstallString' -and $appRegProps.UninstallString) { $appRegProps.UninstallString }),
                                $(if ($psPropNames -contains 'QuietUninstallString' -and $appRegProps.QuietUninstallString) { $appRegProps.QuietUninstallString }),
                                $(if ($psPropNames -contains 'InstallSource' -and $appRegProps.InstallSource) { $appRegProps.InstallSource }),
                                $(if ($psPropNames -contains 'InstallLocation' -and $appRegProps.InstallLocation) { $appRegProps.InstallLocation }),
                                $installDate,
                                $(if ($psPropNames -contains 'Publisher' -and $appRegProps.Publisher) { $appRegProps.Publisher }),
                                $(if ($psPropNames -contains 'HelpLink' -and $appRegProps.HelpLink -and [System.Uri]::TryCreate($appRegProps.HelpLink, [System.UriKind]::Absolute, [ref]$defUriValue)) { $defUriValue }),
                                $(if ($psPropNames -contains 'EstimatedSize' -and $appRegProps.EstimatedSize) { $appRegProps.EstimatedSize }),
                                [bool]( ($psPropNames -contains 'SystemComponent') -and $appRegProps.SystemComponent ),
                                $windowsInstaller,
                                ( [System.Environment]::Is64BitProcess -and ($appRegProps.PSPath -notmatch '\\Wow6432Node\\') )
                            )

                            Write-ADTLogEntry -Message "Found installed application [$($appRegProps.DisplayName)]$(if ($appRegProps.DisplayVersion) { " version [$($appRegProps.DisplayVersion)]" })."
                        }
                    }
                }
            }
            else
            {
                Write-ADTLogEntry -Message "Skipping classic per-user detection due to -ApplicationType/-Skip* selections."
            }

            if ($detectedUserApps.Count -gt 0)
            {
                $detectedApps += $detectedUserApps
            }
            else
            {
                Write-ADTLogEntry -Message "No user-context applications detected."
            }

            # MARK: APPX detection
            if ($wantAppx)
            {
                $appxParams = @{
                    Name      = $Name
                    NameMatch = $NameMatch
                }
                if ($FilterScript) { $appxParams['FilterScript'] = $FilterScript }

                $appxApps = Invoke-MDMAOAppxAppDetectionExt @appxParams

                if ($appxApps.Count -gt 0)
                {
                    $detectedApps += $appxApps
                }
            }

            # MARK: App Results Filtering
            # TODO: Implement better filtering logic when time permits.
            if ($FilterScript)
            {
                $detectedApps = $detectedApps | Where-Object $FilterScript
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

        # MARK: Return Results
        # Return Results (stable order; ensure provisioned AppX are last for uninstall safety)
        return ($detectedApps | Sort-Object PSPath -Unique | Sort-Object IsProvisioned -Descending)
    }

    end
    {
        Complete-ADTFunction -Cmdlet $PSCmdlet
    }
}
