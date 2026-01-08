function Invoke-MDMAOAppxAppDetectionExt
{
    <#
    .SYNOPSIS
        Detects installed AppX applications.

    .DESCRIPTION
        Extends PSADT's Get-ADTApplication:
        - Detects AppX (installed & provisioned) applications.
        - Returns PSADT.Types.InstalledApplication objects with extended properties.

    .PARAMETER Name
        One or more names to match against AppX Name or DisplayName.

    .PARAMETER NameMatch
        How to match Name. One of: Contains (default), Exact, Wildcard, Regex.

    .PARAMETER FilterScript
        A ScriptBlock run against each result to include/exclude (e.g. version gating).
        Where-Object style ScriptBlock for post-filtering.
        # TODO: Implement better filtering logic when time permits.

    .OUTPUTS
        PSADT.Types.InstalledApplication[]

    .EXAMPLE
        # Where-Object style filter script:
        # Keep only apps matching the 7-Zip regex pattern
        $7zipFilterScript = { $_.DisplayName -match '^7-Zip\s\d{2}\.\d{2}(\s\(.+?\))?$' }
        Invoke-MDMAOAppxAppDetectionExt -FilterScript $7zipFilterScript

    .NOTES
        Function Name  : Invoke-MDMAOAppxAppDetectionExt
        Author         : Timothy Gruber
        Version        : 1.0.1
        Created        : 2025-09-15
        Updated        : 2026-01-08

        Version History:
        1.0.0 - (2024-10-23) Initial version.
        1.0.1 - (2026-01-08) Added InstallerUserCount and InstalledUserSids to logging for Appx detection.
    #>

    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'PSScriptAnalyzer does not recognize PSADT InstalledApplication type.')]
    param
    (
        [Parameter()]
        [String[]]$Name,

        [Parameter()]
        [ValidateSet('Contains', 'Exact', 'Wildcard', 'Regex')]
        [String]$NameMatch = 'Contains',

        [Parameter()]
        [ScriptBlock]$FilterScript
    )

    begin
    {
        Initialize-ADTFunction -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        Write-ADTLogEntry -Message "Starting function [$($MyInvocation.MyCommand.Name)]"

        # MARK: Helper Functions
        function Test-NameMatch
        {
            param
            (
                [Parameter(Mandatory)] [String]$Candidate,
                [String[]]$Patterns,
                [ValidateSet('Contains', 'Exact', 'Wildcard', 'Regex')] [String]$Mode = 'Contains'
            )
            if (-not $Patterns -or $Patterns.Count -eq 0)
            {
                return $true
            }

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

        # Helper: get WinRT PackageManager instance
        function Get-WinRtPackageManager
        {
            [CmdletBinding()]
            param()

            # WinRT type identity
            $tn = 'Windows.Management.Deployment.PackageManager, Windows, ContentType=WindowsRuntime'

            $t = [Type]::GetType($tn, $false)
            if (-not $t)
            {
                throw "Could not load WinRT type [$tn]. Are you on Windows 10/11 and running 64-bit PowerShell?"
            }

            return [System.Activator]::CreateInstance($t)
        }

        # Helper: get WinRT package by family + full name
        function Get-WinRtPackageByIdentity
        {
            param(
                [Parameter(Mandatory)][Object]$PackageManager,   # result from Get-WinRtPackageManager
                [Parameter(Mandatory)][String]$FamilyName,       # e.g. com.vendor.app_123abc
                [Parameter(Mandatory)][String]$FullName          # e.g. com.vendor.app_1.2.3.4_x64__123abc
            )

            try
            {
                $list = @($PackageManager.FindPackages($FamilyName))  # narrow query
                if ($list.Count -gt 0)
                {
                    foreach ($p in $list)
                    {
                        if ($p.Id -and $p.Id.FullName -eq $FullName)
                        {
                            return $p
                        }
                    }
                }
            }
            catch { Write-ADTLogEntry -Message "Failed to get WinRT package by identity for FamilyName [$FamilyName], FullName [$FullName] with error: [$_]" -Severity Warning }
            return $null
        }

        # Helper: resolve InstalledOn date (WinRT -> FS -> MinValue)
        function Resolve-AppxInstallDate
        {
            param(
                [String]$InstallLocationPath,
                [object]$WrPkg
            )

            # 1) WinRT InstalledLocation.DateCreated
            if ($WrPkg -and $WrPkg.InstalledLocation)
            {
                try
                {
                    $dc = $WrPkg.InstalledLocation.DateCreated
                    if ($dc)
                    {
                        if ($dc.PSObject.Properties.Name -contains 'UtcDateTime') { return [System.DateTime]$dc.UtcDateTime }
                        else { return ([System.DateTimeOffset]$dc).UtcDateTime }
                    }
                }
                catch { Write-ADTLogEntry -Message "Failed to get InstalledLocation.DateCreated from WinRT package with error: [$_]" -Severity Warning }
            }

            # 2) File system fallback
            if ($InstallLocationPath -and (Test-Path -LiteralPath $InstallLocationPath))
            {
                try { return (Get-Item -LiteralPath $InstallLocationPath).CreationTimeUtc } catch { Write-ADTLogEntry -Message "Failed to get CreationTimeUtc from file system with error: [$_]" -Severity Warning }
            }

            return [System.DateTime]::MinValue
        }
    }

    process
    {
        try
        {
            # MARK: AppX Detection
            $detectedAppxApps = @()
            try
            {
                # Provisioned (for new users)
                $prov = Get-AppxProvisionedPackage -Online -ErrorAction Stop
                if ($Name)
                {
                    $prov = $prov | Where-Object { Test-NameMatch -Candidate $_.DisplayName -Patterns $Name -Mode $NameMatch }
                }

                $appx = Get-AppxPackage -AllUsers -ErrorAction Stop
                if ($Name)
                {
                    $appx = $appx | Where-Object {
                        $cand = if ($_.Name) { $_.Name } else { $_.PackageFamilyName }
                        Test-NameMatch -Candidate $cand -Patterns $Name -Mode $NameMatch
                    }
                }

                # Build InstalledUserSids per family
                $familyToUsers = @{}
                foreach ($x in $appx)
                {
                    $fam = $x.PackageFamilyName
                    if (-not $fam) { continue }

                    if (-not $familyToUsers.ContainsKey($fam))
                    {
                        $familyToUsers[$fam] = [System.Collections.Generic.HashSet[String]]::new()
                    }

                    if ($x.PackageUserInformation)
                    {
                        foreach ($pui in $x.PackageUserInformation)
                        {
                            $sid = $pui.UserSecurityId.sid
                            if ($sid) { $null = $familyToUsers[$fam].Add([System.String]$sid) }
                        }
                    }
                }

                # Get packages from PackageManager (WinRT)
                $pm = $null
                try { $pm = Get-WinRtPackageManager } catch { Write-ADTLogEntry -Message "Failed to get WinRT PackageManager with error: [$_]" -Severity Warning }

                # MARK: AppxProvisionedPackage
                foreach ($p in $prov)
                {
                    $displayName = $p.DisplayName
                    $displayVer = $p.Version
                    switch ($p.Architecture)
                    {
                        0 { $arch = 'x86' }
                        5 { $arch = 'arm' }
                        9 { $arch = 'x64' }
                        11 { $arch = 'neutral' }
                        12 { $arch = 'arm64' }
                        default { $arch = "Unknown($($p.Architecture))" }
                    }
                    $is64 = $arch -iin @('x64', 'arm64', 'neutral')
                    $isArm = $arch -iin @('arm', 'arm64')
                    $psPath = "AppxProv::$($p.PackageName)"
                    $psParentPath = "AppxProv::"
                    $psChildName = $p.PackageName

                    # family: <Name>_<PublisherId>
                    $publisherId = ($p.PackageName -split '_')[-1]
                    $familyName = if ($displayName -and $publisherId) { "$displayName" + '_' + "$publisherId" } else { $null }

                    # WINRT FILL: try to fetch richer info
                    $wrPkg = $null
                    if ($pm -and $familyName)
                    {
                        $wrPkg = Get-WinRtPackageByIdentity -PackageManager $pm -FamilyName $familyName -FullName $p.PackageName
                    }
                    $publisher = $null
                    $installLocPath = $null
                    if ($wrPkg)
                    {
                        try { $publisher = $wrPkg.PublisherDisplayName } catch { Write-ADTLogEntry -Message "Failed to get PublisherDisplayName from WinRT package with error: [$_]" -Severity Warning }
                        try { if ($wrPkg.InstalledLocation) { $installLocPath = $wrPkg.InstalledLocation.Path } } catch { Write-ADTLogEntry -Message "Failed to get InstalledLocation.Path from WinRT package with error: [$_]" -Severity Warning }
                    }

                    if ($installLocPath)
                    { try { $installLoc = [System.IO.DirectoryInfo]$installLocPath } catch { Write-ADTLogEntry -Message "Failed to get InstalledLocation from WinRT package with error: [$_]" -Severity Warning } }
                    else { $installLoc = $null }
                    $installDate = Resolve-AppxInstallDate -InstallLocationPath $installLocPath -WrPkg $wrPkg

                    # Build uninstallString
                    $ps64 = "$envSystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
                    $cmd = '"{0}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Remove-AppxProvisionedPackage -Online -PackageName ''{1}'' -AllUsers -ErrorAction Stop"' -f $ps64, $p.PackageName
                    $uninstallString = $cmd
                    $quietUninstallString = $cmd

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
                    $ia = [PSADT.Types.InstalledApplication]::new(
                        $psPath,
                        $psParentPath,
                        $psChildName,
                        $null,
                        $displayName,
                        $displayVer,
                        $uninstallString,
                        $quietUninstallString,
                        $null,
                        $installLoc,
                        $installDate,
                        $publisher,
                        $null,
                        $null,
                        $false,
                        $false,
                        $is64
                    )

                    # Extended properties
                    $ia | Add-Member -NotePropertyName AppxPackageFullName -NotePropertyValue $p.PackageName
                    $ia | Add-Member -NotePropertyName PackageFamilyName -NotePropertyValue $familyName
                    $ia | Add-Member -NotePropertyName IsProvisioned -NotePropertyValue $true
                    $ia | Add-Member -NotePropertyName TargetUsers -NotePropertyValue 'AllUsers'
                    $ia | Add-Member -NotePropertyName ProcessorArchitecture -NotePropertyValue $arch
                    $ia | Add-Member -NotePropertyName RemovalMethod -NotePropertyValue 'AppxProvisionedPackage'
                    $ia | Add-Member -NotePropertyName IsArm -NotePropertyValue $isArm

                    # Roll-up: which users currently have it
                    if ($familyName -and $familyToUsers.ContainsKey($familyName))
                    {
                        $sidSet = $familyToUsers[$familyName]
                        $sids = @($sidSet) -as [String[]]
                        $count = if ($sidSet) { $sidSet.Count } else { 0 }

                        $ia | Add-Member -NotePropertyName InstalledUserSids -NotePropertyValue $sids
                        $ia | Add-Member -NotePropertyName InstalledUserCount -NotePropertyValue $count
                    }
                    else
                    {
                        $ia | Add-Member -NotePropertyName InstalledUserSids -NotePropertyValue @()
                        $ia | Add-Member -NotePropertyName InstalledUserCount -NotePropertyValue 0
                    }

                    # Log InstalledUserCount, and InstalledUserSids if InstalledUserCount greater than 0
                    if ($ia.InstalledUserCount -gt 0)
                    {
                        Write-ADTLogEntry -Message "Found AppxProvisionedPackage: [$displayName], PackageName: [$($p.PackageName)], InstalledOn(Utc): [$installDate], InstalledUserCount: [$($ia.InstalledUserCount)], InstalledUserSids: [$($ia.InstalledUserSids -join ', ')]."
                    }
                    else
                    {
                        Write-ADTLogEntry -Message "Found AppxProvisionedPackage: [$displayName], PackageName: [$($p.PackageName)], InstalledOn(Utc): [$installDate], InstalledUserCount: [$($ia.InstalledUserCount)]."
                    }

                    $detectedAppxApps += $ia
                }

                # MARK: AppxPackage
                foreach ($x in $appx)
                {
                    $displayName = if ($x.Name) { $x.Name } else { $x.PackageFamilyName }
                    $displayVer = $x.Version
                    $arch = $x.Architecture
                    $is64 = ($arch -iin @('x64', 'arm64', 'neutral'))
                    $isArm = ($arch -iin @('arm', 'arm64'))

                    $psPath = "Appx::$($x.PackageFullName)"
                    $psParentPath = "Appx::"
                    $psChildName = $x.PackageFullName

                    # Prefer Publisher from Get-AppxPackage; fall back to WinRT display name
                    $publisher = $x.Publisher
                    $installLocPath = $x.InstallLocation

                    # WINRT FILL: if missing/empty, fill from WinRT
                    $wrPkg = $null
                    if ($pm -and $x.PackageFamilyName)
                    {
                        $wrPkg = Get-WinRtPackageByIdentity -PackageManager $pm -FamilyName $x.PackageFamilyName -FullName $x.PackageFullName
                        if (-not $publisher -and $wrPkg)
                        {
                            try { $publisher = $wrPkg.PublisherDisplayName } catch { Write-ADTLogEntry -Message "Failed to get PublisherDisplayName from WinRT package with error: [$_]" -Severity Warning }
                        }
                        if ((-not $installLocPath) -and $wrPkg -and $wrPkg.InstalledLocation)
                        {
                            try { $installLocPath = $wrPkg.InstalledLocation.Path } catch { Write-ADTLogEntry -Message "Failed to get InstalledLocation.Path from WinRT package with error: [$_]" -Severity Warning }
                        }
                    }

                    $installLoc = if ($installLocPath) { [System.IO.DirectoryInfo]$installLocPath } else { $null }
                    $installDate = Resolve-AppxInstallDate -InstallLocationPath $installLocPath -WrPkg $wrPkg

                    # Build uninstallString
                    $ps64 = "$envSystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
                    $cmd = '"{0}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Remove-AppxPackage -Package ''{1}'' -AllUsers -ErrorAction Stop"' -f $ps64, $x.PackageFullName
                    $uninstallString = $cmd
                    $quietUninstallString = $cmd

                    $ia = [PSADT.Types.InstalledApplication]::new(
                        $psPath,
                        $psParentPath,
                        $psChildName,
                        $null,
                        $displayName,
                        $displayVer,
                        $uninstallString,
                        $quietUninstallString,
                        $null,
                        $installLoc,
                        $installDate,
                        $publisher,
                        $null,
                        $null,
                        $false,
                        $false,
                        $is64
                    )

                    # Extended properties
                    $ia | Add-Member -NotePropertyName AppxPackageFullName -NotePropertyValue $x.PackageFullName
                    $ia | Add-Member -NotePropertyName PackageFamilyName -NotePropertyValue $x.PackageFamilyName
                    $ia | Add-Member -NotePropertyName IsProvisioned -NotePropertyValue $false
                    $ia | Add-Member -NotePropertyName TargetUsers -NotePropertyValue 'AllUsers'
                    $ia | Add-Member -NotePropertyName ProcessorArchitecture -NotePropertyValue $arch
                    $ia | Add-Member -NotePropertyName RemovalMethod -NotePropertyValue 'AppxPackage'
                    $ia | Add-Member -NotePropertyName IsArm -NotePropertyValue $isArm

                    # Roll-up
                    if ($x.PackageFamilyName -and $familyToUsers.ContainsKey($x.PackageFamilyName))
                    {
                        $sidSet = $familyToUsers[$x.PackageFamilyName]
                        $sids = @($sidSet) -as [String[]]
                        $count = if ($sidSet) { $sidSet.Count } else { 0 }

                        $ia | Add-Member -NotePropertyName InstalledUserSids -NotePropertyValue $sids
                        $ia | Add-Member -NotePropertyName InstalledUserCount -NotePropertyValue $count
                    }
                    else
                    {
                        $ia | Add-Member -NotePropertyName InstalledUserSids -NotePropertyValue @()
                        $ia | Add-Member -NotePropertyName InstalledUserCount -NotePropertyValue 0
                    }

                    # Log InstalledUserCount, and InstalledUserSids if InstalledUserCount greater than 0
                    if ($ia.InstalledUserCount -gt 0)
                    {
                        Write-ADTLogEntry -Message "Found AppxPackage: [$displayName], PackageFullName: [$($x.PackageFullName)], InstalledOn(Utc): [$installDate], InstalledUserCount: [$($ia.InstalledUserCount)], InstalledUserSids: [$($ia.InstalledUserSids -join ', ')]."
                    }
                    else
                    {
                        Write-ADTLogEntry -Message "Found AppxPackage: [$displayName], PackageFullName: [$($x.PackageFullName)], InstalledOn(Utc): [$installDate], InstalledUserCount: [$($ia.InstalledUserCount)]."
                    }

                    $detectedAppxApps += $ia
                }
            }
            catch
            {
                Write-ADTLogEntry -Message "AppX detection failed with error: [$_]" -Severity Error
            }

            # MARK: Results Filtering
            # TODO: Implement better filtering logic when time permits.
            if ($FilterScript)
            {
                $detectedAppxApps = $detectedAppxApps | Where-Object $FilterScript
            }

        }
        catch
        {
            Write-Error -ErrorRecord $_
            Invoke-ADTFunctionErrorHandler -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -ErrorRecord $_
        }

        if (-not $detectedAppxApps)
        {
            Write-ADTLogEntry -Message "No AppX applications detected."
        }

        # MARK: Return Results
        # Lastly sort by IsProvisioned to prevent potential uninstallation issues when piped to uninstall
        return ($detectedAppxApps | Sort-Object PSPath -Unique | Sort-Object IsProvisioned -Descending)
    }

    end
    {
        Complete-ADTFunction -Cmdlet $PSCmdlet
    }
}
