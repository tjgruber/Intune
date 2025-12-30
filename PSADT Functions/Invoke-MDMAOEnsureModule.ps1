function Invoke-MDMAOEnsureModule
{
    <#
    .SYNOPSIS
        Ensures that a specified PowerShell module is available and imported.

    .DESCRIPTION
        This function guarantees that a given PowerShell module:
            - Exists locally at or above a specified minimum version, and
            - Is imported into the current session.

        Behavior:
            1. Attempts to locate an installed version via Get-Module -ListAvailable.
            2. If found:
                - Verifies that it meets the MinimumVersion (if specified).
                - Imports that specific version into the current session.
            2. Optionally, if -LocalModulePath is specified:
                - Attempts to validate and import the module from a local manifest
                  path or directory (e.g., a bundled module under PSADT SupportFiles).
            3. If still not found or too old (and -ImportOnly is NOT specified):
                - Ensures:
                    * TLS 1.2 is enabled.
                    * PowerShellGet cmdlets (Install-Module) are available.
                    * NuGet package provider is installed.
                    * The target repository (default: PSGallery) exists and is Trusted.
                - Installs the module with Install-Module.
                - Imports the newly installed module into the current session.
            4. If -ImportOnly is specified:
                - The function will NOT attempt to install anything from a remote repository.
                - If the module does not exist or does not meet MinimumVersion (including
                  the local path if provided), the function logs an error and throws.

        Any unrecoverable error is logged via Write-ADTLogEntry and re-thrown so
        that calling code (e.g., deployment/automation workflows) can treat it
        as a hard failure.

    .PARAMETER ModuleName
        The name of the PowerShell module to ensure (e.g. "Az.Accounts").

    .PARAMETER MinimumVersion
        The minimum acceptable module version. If the locally available version
        is lower than this, an installation attempt will be made (unless -ImportOnly
        is specified, in which case the function throws).

    .PARAMETER LocalModulePath
        Optional local source path for the module.
        This can be:
            - A full path to a module manifest (.psd1), OR
            - A directory path that contains the module manifest named
              "<ModuleName>.psd1".

        Examples:
            - "C:\Temp\Modules\Az.Accounts.2.12.5\Az.Accounts.psd1"
            - "C:\Temp\Modules\Az.Accounts.2.12.5"

        If specified, this local source is attempted after checking existing
        installed modules, and before attempting any repository install.
        When -ImportOnly is also specified, the function will not hit any
        repositories and will only use existing modules or this local path.

    .PARAMETER RepositoryName
        The name of the PowerShell repository to use for installation when
        the module is not found or does not meet MinimumVersion.
        Default is "PSGallery".

    .PARAMETER Scope
        The installation scope for Install-Module and Install-PackageProvider.
        Valid values: "CurrentUser", "AllUsers".
        Default is "CurrentUser".

        NOTE:
            - When running under SYSTEM (e.g., Intune/PSADT), "CurrentUser"
              maps to the SYSTEM profile, which is typically sufficient.
            - Use "AllUsers" if you want modules/providers available to all users.

    .PARAMETER ImportOnly
        If specified, the function will ONLY attempt to locate and import an
        existing module (installed or via -LocalModulePath). No repository
        installation will be attempted. If the module is missing or too old,
        the function logs an error and throws.

    .EXAMPLE
        # Ensure Az.Accounts is available at least at version 2.12.5
        Invoke-MDMAOEnsureModule -ModuleName 'Az.Accounts' -MinimumVersion '2.12.5'

    .EXAMPLE
        # Ensure Az.Storage is available, using default PSGallery and CurrentUser scope
        Invoke-MDMAOEnsureModule -ModuleName 'Az.Storage' -MinimumVersion '5.9.0'

    .EXAMPLE
        # Prefer a bundled local Az.Accounts module first, then fall back to PSGallery
        $localAzAccountsPath = Join-Path $dirSupportFiles 'Modules\az.accounts.2.12.5'
        Invoke-MDMAOEnsureModule -ModuleName 'Az.Accounts' -MinimumVersion '2.12.5' -LocalModulePath $localAzAccountsPath

    .EXAMPLE
        # Only use existing/local PnP.PowerShell, never hit PSGallery
        Invoke-MDMAOEnsureModule -ModuleName 'PnP.PowerShell' -MinimumVersion '2.5.0' -LocalModulePath 'C:\Temp\PnpModule' -ImportOnly

    .NOTES
        Function Name  : Invoke-MDMAOEnsureModule
        Author         : Timothy Gruber
        Version        : 1.0.0
        Created        : 2025-12-09
        Updated        : 2025-12-09

        Version History:
        1.0.0 - (2025-12-09) Initial version.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$ModuleName,

        [Parameter()]
        [Version]$MinimumVersion,

        [Parameter()]
        [string]$LocalModulePath,

        [Parameter()]
        [string]$RepositoryName = 'PSGallery',

        [Parameter()]
        [ValidateSet('AllUsers', 'CurrentUser')]
        [string]$Scope = 'AllUsers',

        [Parameter()]
        [switch]$ImportOnly
    )

    begin
    {
        Initialize-ADTFunction -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        Write-ADTLogEntry -Message "Starting function [$($MyInvocation.MyCommand.Name)] for [ModuleName]: [$ModuleName], [MinimumVersion]: [$MinimumVersion], [LocalModulePath]: [$LocalModulePath], [RepositoryName]: [$RepositoryName], [Scope]: [$Scope], [ImportOnly]: [$($ImportOnly.IsPresent)]."

        # Try to ensure TLS 1.2 is enabled for outbound calls (PSGallery/NuGet/etc.)
        try
        {
            $currentProtocols = [System.Net.ServicePointManager]::SecurityProtocol
            $tls12 = [System.Net.SecurityProtocolType]::Tls12

            if (($currentProtocols -band $tls12) -eq 0)
            {
                [System.Net.ServicePointManager]::SecurityProtocol = $currentProtocols -bor $tls12
                Write-ADTLogEntry -Message "Enabled TLS 1.2 for outbound PowerShell web requests."
            }
        }
        catch
        {
            $message = "Failed to enforce TLS 1.2 for outbound web requests with error: [$($_.Exception.Message)]. Continuing without modification."
            Write-ADTLogEntry -Message $message -Severity Warning
        }
    }

    process
    {
        try
        {
            #-----------------------------------------------------------------
            # Step 1: Try to locate an existing installed module
            #-----------------------------------------------------------------
            $existingModule = Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

            if ($existingModule)
            {
                Write-ADTLogEntry -Message "Found existing module [$ModuleName] version [$($existingModule.Version)]."

                if ($MinimumVersion -and ($existingModule.Version -lt $MinimumVersion))
                {
                    $message = "Existing module [$ModuleName] version [$($existingModule.Version)] is lower than required [MinimumVersion]: [$MinimumVersion]."
                    Write-ADTLogEntry -Message $message -Severity Warning
                }
                else
                {
                    # Either no MinimumVersion was specified or the existing module meets it
                    Write-ADTLogEntry -Message "Importing existing module [$ModuleName] version [$($existingModule.Version)]."
                    Import-Module -Name $existingModule.Name -RequiredVersion $existingModule.Version -Force -ErrorAction Stop

                    $imported = Get-Module -Name $ModuleName | Select-Object -First 1
                    Write-ADTLogEntry -Message "Successfully imported module [$ModuleName] version [$($imported.Version)]."
                    return
                }
            }

            #-----------------------------------------------------------------
            # Step 2: Try to use a local module path if provided
            #-----------------------------------------------------------------
            if ($LocalModulePath)
            {
                try
                {
                    $resolvedLocalPath = $null
                    try
                    {
                        $resolvedLocalPath = (Resolve-Path -Path $LocalModulePath -ErrorAction Stop | Select-Object -First 1).Path
                        Write-ADTLogEntry -Message "Resolved [LocalModulePath] for module [$ModuleName] to: [$resolvedLocalPath]."
                    }
                    catch
                    {
                        $message = "Failed to resolve [LocalModulePath]: [$LocalModulePath] for module [$ModuleName] with error: [$($_.Exception.Message)]."
                        Write-ADTLogEntry -Message $message -Severity Warning
                    }

                    if ($resolvedLocalPath)
                    {
                        $manifestPath = $null

                        if (Test-Path -Path $resolvedLocalPath -PathType Leaf)
                        {
                            # Treat as direct manifest path
                            $manifestPath = $resolvedLocalPath
                        }
                        elseif (Test-Path -Path $resolvedLocalPath -PathType Container)
                        {
                            # Assume "<dir>\<ModuleName>.psd1"
                            $candidateManifest = Join-Path -Path $resolvedLocalPath -ChildPath ("{0}.psd1" -f $ModuleName)

                            if (Test-Path -Path $candidateManifest -PathType Leaf)
                            {
                                $manifestPath = $candidateManifest
                            }
                            else
                            {
                                Write-ADTLogEntry -Message "Local module directory for [$ModuleName] at path: [$resolvedLocalPath] does not contain manifest file: [$candidateManifest]." -Severity Warning
                            }
                        }

                        if ($manifestPath -and (Test-Path -Path $manifestPath -PathType Leaf))
                        {
                            Write-ADTLogEntry -Message "Found local module manifest for [$ModuleName] at path: [$manifestPath]. Validating with Test-ModuleManifest."
                            $manifestInfo = $null

                            try
                            {
                                $manifestInfo = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
                                Write-ADTLogEntry -Message "Local module manifest for [$ModuleName] reports version: [$($manifestInfo.Version)]."
                            }
                            catch
                            {
                                $message = "Failed to validate local module manifest for [$ModuleName] at path: [$manifestPath] with error: [$($_.Exception.Message)]."
                                Write-ADTLogEntry -Message $message -Severity Warning
                            }

                            if ($manifestInfo)
                            {
                                if ($MinimumVersion -and ($manifestInfo.Version -lt $MinimumVersion))
                                {
                                    $message = "Local module manifest for [$ModuleName] version [$($manifestInfo.Version)] is lower than required [MinimumVersion]: [$MinimumVersion]."
                                    Write-ADTLogEntry -Message $message -Severity Warning
                                }
                                else
                                {
                                    Write-ADTLogEntry -Message "Importing module [$ModuleName] from local manifest path: [$manifestPath] with version [$($manifestInfo.Version)]."
                                    Import-Module -Name $manifestPath -Force -ErrorAction Stop

                                    $importedLocal = Get-Module -Name $ModuleName | Select-Object -First 1
                                    Write-ADTLogEntry -Message "Successfully imported module [$ModuleName] from local path with version [$($importedLocal.Version)]."
                                    return
                                }
                            }
                        }
                        else
                        {
                            Write-ADTLogEntry -Message "Local module path for [$ModuleName] is not a valid manifest or directory containing a manifest: [$resolvedLocalPath]." -Severity Warning
                        }
                    }
                }
                catch
                {
                    $message = "Unexpected error while processing [LocalModulePath] for module [$ModuleName] with error: [$($_.Exception.Message)]."
                    Write-ADTLogEntry -Message $message -Severity Warning
                }
            }

            # If getting here and ImportOnly is specified, MUST stop.
            if ($ImportOnly.IsPresent)
            {
                $message = "Module [$ModuleName] could not be located or did not meet [MinimumVersion]: [$MinimumVersion] using existing modules or [LocalModulePath]: [$LocalModulePath], and [-ImportOnly] is specified. Cannot continue."
                Write-ADTLogEntry -Message $message -Severity Error
                throw $message
            }

            #-----------------------------------------------------------------
            # Step 3: At this point, need to INSTALL from repository
            #         (ImportOnly is NOT set)
            #-----------------------------------------------------------------

            # Ensure PowerShellGet is available (Install-Module)
            if (-not (Get-Command -Name Install-Module -ErrorAction SilentlyContinue))
            {
                $message = "PowerShellGet (Install-Module) is not available on this system. Cannot install module [$ModuleName]."
                Write-ADTLogEntry -Message $message -Severity Error
                throw $message
            }

            # Ensure NuGet package provider is available (and at or above a required version)
            try
            {
                # Define the minimum NuGet provider version you require
                $requiredNugetVersion = [Version]'2.8.5.201'

                # Check for already-installed providers and avoid any implicit bootstrapping/prompting.
                $nugetProvider = Get-PackageProvider -Name 'NuGet' -ListAvailable -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1

                if ($nugetProvider)
                {
                    $currentNugetVersion = [Version]$nugetProvider.Version
                    if ($currentNugetVersion -lt $requiredNugetVersion)
                    {
                        Write-ADTLogEntry -Message "NuGet package provider version [$currentNugetVersion] is lower than required version [$requiredNugetVersion]. Updating provider silently."

                        $null = Install-PackageProvider -Name 'NuGet' -MinimumVersion $requiredNugetVersion.ToString() -Scope $Scope -Force -ForceBootstrap -Confirm:$false -ErrorAction Stop

                        $nugetProvider = Get-PackageProvider -Name 'NuGet' -ListAvailable -ErrorAction Stop | Sort-Object Version -Descending | Select-Object -First 1

                        Write-ADTLogEntry -Message "Successfully updated NuGet package provider to version: [$($nugetProvider.Version)]."
                    }
                    else
                    {
                        Write-ADTLogEntry -Message "NuGet package provider already present with sufficient version: [$currentNugetVersion]."
                    }
                }
                else
                {
                    Write-ADTLogEntry -Message "NuGet package provider not found. Installing NuGet provider silently."

                    $null = Install-PackageProvider -Name 'NuGet' -MinimumVersion $requiredNugetVersion.ToString() -Scope $Scope -Force -ForceBootstrap -Confirm:$false -ErrorAction Stop

                    $nugetProvider = Get-PackageProvider -Name 'NuGet' -ListAvailable -ErrorAction Stop | Sort-Object Version -Descending | Select-Object -First 1

                    Write-ADTLogEntry -Message "Successfully installed NuGet package provider version: [$($nugetProvider.Version)]."
                }
            }
            catch
            {
                $message = "Failed to ensure NuGet package provider required for module [$ModuleName] with error: [$($_.Exception.Message)]."
                Write-ADTLogEntry -Message $message -Severity Error
                throw $message
            }

            # Ensure repository exists and is Trusted
            try
            {
                $repository = Get-PSRepository -Name $RepositoryName -ErrorAction SilentlyContinue

                if (-not $repository)
                {
                    if ($RepositoryName -eq 'PSGallery')
                    {
                        Write-ADTLogEntry -Message "Repository [$RepositoryName] not registered. Registering PSGallery as a trusted repository."
                        Register-PSRepository -Name 'PSGallery' -SourceLocation 'https://www.powershellgallery.com/api/v2' -InstallationPolicy Trusted -ErrorAction Stop
                        $repository = Get-PSRepository -Name 'PSGallery' -ErrorAction Stop
                    }
                    else
                    {
                        $message = "Repository [$RepositoryName] is not registered and automatic registration is only implemented for [PSGallery]. Please register the repository before calling this function."
                        Write-ADTLogEntry -Message $message -Severity Error
                        throw $message
                    }
                }
                elseif ($repository.InstallationPolicy -ne 'Trusted')
                {
                    Write-ADTLogEntry -Message "Setting repository [$RepositoryName] InstallationPolicy to [Trusted]."
                    Set-PSRepository -Name $RepositoryName -InstallationPolicy Trusted -ErrorAction Stop
                }
            }
            catch
            {
                $message = "Failed to configure repository [$RepositoryName] for module [$ModuleName] with error: [$($_.Exception.Message)]."
                Write-ADTLogEntry -Message $message -Severity Error
                throw $message
            }

            # Build Install-Module parameters
            $installParams = @{
                Name          = $ModuleName
                Repository    = $RepositoryName
                Scope         = $Scope
                Force         = $true
                AllowClobber  = $true
                ErrorAction   = 'Stop'
                WarningAction = 'SilentlyContinue'
            }

            if ($MinimumVersion)
            {
                $installParams['MinimumVersion'] = $MinimumVersion.ToString()
            }

            Write-ADTLogEntry -Message "Installing module [$ModuleName] from repository [$RepositoryName] with [Scope]: [$Scope] and [MinimumVersion]: [$MinimumVersion]."
            Install-Module @installParams

            # Import after successful install
            Write-ADTLogEntry -Message "Importing module [$ModuleName] after installation."
            Import-Module -Name $ModuleName -Force -ErrorAction Stop

            $importedModule = Get-Module -Name $ModuleName | Select-Object -First 1

            if (-not $importedModule)
            {
                $message = "Module [$ModuleName] was installed but could not be imported."
                Write-ADTLogEntry -Message $message -Severity Error
                throw $message
            }

            if ($MinimumVersion -and ($importedModule.Version -lt $MinimumVersion))
            {
                $message = "Imported module [$ModuleName] version [$($importedModule.Version)] is lower than required [MinimumVersion]: [$MinimumVersion]."
                Write-ADTLogEntry -Message $message -Severity Error
                throw $message
            }

            Write-ADTLogEntry -Message "Successfully installed and imported module [$ModuleName] version [$($importedModule.Version)]."
        }
        catch
        {
            $message = "Failed to ensure module [$ModuleName] with error: [$($_.Exception.Message)]."
            Write-ADTLogEntry -Message $message -Severity Error
            throw
        }
    }

    end
    {
        Write-ADTLogEntry -Message "Completed function [$($MyInvocation.MyCommand.Name)] for [ModuleName]: [$ModuleName]."
        Complete-ADTFunction -Cmdlet $PSCmdlet
    }
}
