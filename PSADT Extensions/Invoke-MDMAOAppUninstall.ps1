function Invoke-MDMAOAppUninstall
{
    <#
    .SYNOPSIS
        Uninstalls one or more applications intelligently based on context (user/system, MSI/EXE).

    .DESCRIPTION
        - Automatically detects whether an app was installed in the user or system context.
        - Supports uninstalling MSI or EXE-based applications.
        - Prefers QuietUninstallString when available, falls back to UninstallString.
        - Handles user-context uninstalls via Start-ADTProcessAsUser.
        - Supports passing additional parameters for user-context and system-context EXE uninstalls.
        - Allows customized expected success exit codes.
        - Supports selective uninstall targeting: UserContext only, SystemContext only, or both.

    .PARAMETER Apps
        One or more InstalledApplication objects to uninstall (supports pipeline input).

    .PARAMETER UninstallApps
        Specifies whether to uninstall:
          - UserAndSystemContextApps (default)
          - UserContextAppsOnly
          - SystemContextAppsOnly

    .PARAMETER UserContextEXEUninstallParameters
        Optional string of additional arguments to use during EXE uninstalls in user context.

    .PARAMETER AdditionalSystemContextEXEUninstallParameters
        Optional string of additional arguments to use during EXE uninstalls in system context.

    .PARAMETER SuccessExitCodes
        One or more integer exit codes considered successful.
        Default = 0. Example: @(0, 19, 20) for Chrome.

    .EXAMPLE
        Invoke-MDMAOAppUninstall -Apps $apps

    .EXAMPLE
        $apps | Invoke-MDMAOAppUninstall -UserContextEXEUninstallParameters '--silent' -AdditionalSystemContextEXEUninstallParameters '--quiet'

    .NOTES
        Function Name  : Invoke-MDMAOAppUninstall
        Author         : Timothy Gruber
        Version        : 1.2.0
        Created        : 2025-04-27
        Updated        : 2025-04-29

        Version History:
        1.0.0 - (2025-04-27) Initial version.
        1.1.0 - (2025-04-27) Refactored with USER-CONTEXT MSI UNINSTALL, skipApp handling, and StdOut/Err logging for user/system exe uninstalls.
        1.2.0 - (2025-08-15) Fix user context detection.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSADT.Types.InstalledApplication[]]$Apps,

        [Parameter()]
        [ValidateSet('UserAndSystemContextApps', 'UserContextAppsOnly', 'SystemContextAppsOnly')]
        [String]$UninstallApps = 'UserAndSystemContextApps',

        [Parameter()]
        [String]$UserContextEXEUninstallParameters,

        [Parameter()]
        [String]$AdditionalSystemContextEXEUninstallParameters,

        [Parameter()]
        [Int[]]$SuccessExitCodes = @(0)
    )

    begin
    {
        Initialize-ADTFunction -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        Write-ADTLogEntry -Message "Starting function [$($MyInvocation.MyCommand.Name)]"
    }

    process
    {
        foreach ($app in $Apps)
        {
            $isUserContext = ($app.PSPath -imatch 'HKEY_(?:USERS|CURRENT_USER)\b')
            $appDisplayName = $app.DisplayName

            Write-ADTLogEntry -Message "Processing [$appDisplayName] for uninstallation in [$UninstallApps] mode."

            $skipApp = $false

            switch ($UninstallApps)
            {
                'SystemContextAppsOnly'
                {
                    if ($isUserContext)
                    {
                        Write-ADTLogEntry -Message "Skipping user-context app [$appDisplayName]."
                        $skipApp = $true
                    }
                }
                'UserContextAppsOnly'
                {
                    if (-not $isUserContext)
                    {
                        Write-ADTLogEntry -Message "Skipping system-context app [$appDisplayName]."
                        $skipApp = $true
                    }
                }
                default
                {
                    # No action needed for UserAndSystemContextApps
                }
            }

            if ($skipApp)
            {
                continue
            }

            # Prefer QuietUninstallString if available
            $uninstallString = $app.QuietUninstallString
            if (-not $uninstallString)
            {
                Write-ADTLogEntry -Message "QuietUninstallString not found. Checking UninstallString."
                $uninstallString = $app.UninstallString
            }

            if (-not $uninstallString)
            {
                Write-ADTLogEntry -Message "No uninstall string found for [$appDisplayName]. Skipping." -Severity Error
                continue
            }
            else
            {
                Write-ADTLogEntry -Message "Uninstall string found: [$uninstallString]"
            }

            # Determine uninstall executable
            $uninstallPath = (($uninstallString -split ' --| -| /')[0]).Trim('"').Trim()

            # Final check
            if ($uninstallPath -notmatch "MsiExec.exe" -and -not (Test-Path $uninstallPath))
            {
                Write-ADTLogEntry -Message "Uninstall path not found: [$uninstallPath]. Skipping." -Severity Error
                continue
            }

            # SYSTEM-CONTEXT MSI UNINSTALL
            if (-not $isUserContext -and $uninstallString -match 'Msiexec.exe')
            {
                Write-ADTLogEntry -Message "Uninstalling system-context MSI app: [$appDisplayName]"
                $app | Uninstall-ADTApplication -AdditionalArgumentList '/qn /norestart' -ErrorAction SilentlyContinue
                continue
            }

            # USER-CONTEXT MSI UNINSTALL
            if ($isUserContext -and $uninstallString -match 'Msiexec.exe')
            {
                Write-ADTLogEntry -Message "Uninstalling user-context MSI app: [$appDisplayName]"

                $msiArgs = $uninstallString -replace '(?i)^.*?msiexec(?:\.exe)?', ''
                $msiArgs = $msiArgs.TrimStart(' ', '"', "'")

                $userMSIUninstallSplat = @{
                    FilePath         = 'Msiexec.exe'
                    ArgumentList     = $msiArgs
                    CreateNoWindow   = $true
                    SuccessExitCodes = $SuccessExitCodes
                    PassThru         = $true
                    ErrorAction      = 'SilentlyContinue'
                }

                $userMSIUninstallResult = Start-ADTProcessAsUser @userMSIUninstallSplat

                if ($userMSIUninstallResult.StdOut.Length -gt 1)
                {
                    Write-ADTLogEntry -Message "User-context MSI uninstall output: [$($userMSIUninstallResult.StdOut)]"
                }
                if ($userMSIUninstallResult.StdErr.Length -gt 1)
                {
                    Write-ADTLogEntry -Message "User-context MSI uninstall error: [$($userMSIUninstallResult.StdErr)]" -Severity Error
                }

                continue
            }

            # USER-CONTEXT EXE UNINSTALL
            if ($isUserContext)
            {
                Write-ADTLogEntry -Message "Uninstalling user-context EXE app: [$appDisplayName]"

                $userLevelUninstallSplat = @{
                    CreateNoWindow   = $true
                    SuccessExitCodes = $SuccessExitCodes
                    PassThru         = $true
                    ErrorAction      = 'SilentlyContinue'
                }

                if ($app.QuietUninstallString)
                {
                    $userLevelUninstallSplat['FilePath'] = $uninstallPath
                    # Extract additional arguments
                    $uninstallArguments = $uninstallString -replace [Regex]::Escape($uninstallPath), ''
                    $uninstallArguments = $uninstallArguments.TrimStart(' ', '"', "'")
                    $userLevelUninstallSplat['ArgumentList'] = $uninstallArguments
                }
                else
                {
                    $userLevelUninstallSplat['FilePath'] = $uninstallPath
                }

                if ($PSBoundParameters.ContainsKey('UserContextEXEUninstallParameters'))
                {
                    Write-ADTLogEntry -Message "Using the following specified user-context EXE uninstall parameters: [$UserContextEXEUninstallParameters]"
                    $userLevelUninstallSplat['ArgumentList'] = $UserContextEXEUninstallParameters
                }

                $userLevelUninstallResult = Start-ADTProcessAsUser @userLevelUninstallSplat

                if ($userLevelUninstallResult.StdOut.Length -gt 1)
                {
                    Write-ADTLogEntry -Message "User-context EXE uninstall output: [$($userLevelUninstallResult.StdOut)]"
                }
                if ($userLevelUninstallResult.StdErr.Length -gt 1)
                {
                    Write-ADTLogEntry -Message "User-context EXE uninstall error: [$($userLevelUninstallResult.StdErr)]" -Severity Error
                }

                continue
            }

            # SYSTEM-CONTEXT EXE UNINSTALL
            Write-ADTLogEntry -Message "Uninstalling system-context EXE app: [$appDisplayName]"

            $systemLevelUninstallSplat = @{
                SuccessExitCodes = $SuccessExitCodes
                ErrorAction      = 'SilentlyContinue'
            }

            if ($PSBoundParameters.ContainsKey('AdditionalSystemContextEXEUninstallParameters'))
            {
                Write-ADTLogEntry -Message "Using the following additional system-context EXE uninstall parameters: [$AdditionalSystemContextEXEUninstallParameters]"
                $systemLevelUninstallSplat['AdditionalArgumentList'] = $AdditionalSystemContextEXEUninstallParameters
            }

            $app | Uninstall-ADTApplication @systemLevelUninstallSplat

        }
    }

    end
    {
        Complete-ADTFunction -Cmdlet $PSCmdlet
    }
}
