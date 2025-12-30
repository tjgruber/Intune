function Get-MDMAOSecureUserInput
{
    <#
    .SYNOPSIS
        Displays a masked input dialog in the logged-on user session and returns
        the value to the SYSTEM context as a SecureString.

    .DESCRIPTION
        Launches a small helper PowerShell process in the interactive
        (logged-on) user session via Start-ADTProcessAsUser. The helper shows
        a WinForms dialog for collecting sensitive input (for example,
        BitLocker startup PINs or arbitrary secrets) with:

            - Masked textbox input
            - Optional numeric-only enforcement
            - Optional confirmation textbox (second masked field)
            - Minimum and maximum length validation
            - Optional regex validation via ValidationPattern/ValidationMessage
            - A modern-looking dialog (Segoe UI, EnableVisualStyles, with icon)
            - Customizable input/confirm label text and button text

        The helper process:

            - Converts the entered value to a SecureString
            - Derives an AES key from a per-run, random 256-bit key string
            - Uses ConvertFrom-SecureString -Key to produce an encrypted blob
            - Writes only the encrypted blob to a temporary file accessible
              by both the user and SYSTEM

        The calling (SYSTEM) side:

            - Generates the per-run AES key (never written to disk)
            - Resolves the temporary file path
            - Optionally resolves the icon resource to use for the dialog
            - Passes the key, temp file path, and validation metadata into the
              helper script via token replacement
            - Waits for the helper process to exit
            - Reads the encrypted blob from the temp file
            - Deletes the temp file
            - Decrypts the blob back into a SecureString and returns it

        No plain-text input is written to disk or logged, and only high-level
        events (start, success, cancellation, and errors) are written to the
        PSADT log.

        This function is intended to be called from SYSTEM context (for example,
        during Intune/MDT/ConfigMgr/MDMAO deployments) when user input is
        required but must not be exposed in logs or plain-text files.

    .PARAMETER Title
        Title for the dialog window.

    .PARAMETER Message
        Message/instructions shown at the top of the dialog. This is rendered
        as a wrapped, multi-line label.

    .PARAMETER MinimumLength
        Minimum number of characters required. Defaults to 1. If a value less
        than 1 is provided, it is coerced to 1.

    .PARAMETER MaximumLength
        Maximum number of characters allowed. Defaults to 256.
        If a value smaller than MinimumLength is provided, it is coerced
        to equal MinimumLength.

    .PARAMETER NumericOnly
        When specified, only digits 0-9 are allowed. Any non-numeric input
        will be rejected with an inline error message.

    .PARAMETER RequireConfirmation
        When specified, displays a second masked textbox ("Confirm") and
        requires both values to match before the dialog can close successfully.

    .PARAMETER ValidationPattern
        Optional PowerShell regular expression pattern that the input must
        match. If provided, the input is additionally validated with -notmatch.

        Example:
            '^[A-Z]{3}-\d{4}-[A-Z]{3}$'

        This is useful for enforcing arbitrary secret formats or token schemas.

    .PARAMETER ValidationMessage
        Optional custom error message shown when ValidationPattern is provided
        and the input does not match it. If not provided, a generic message is
        shown:

            "Input does not match the required format."

    .PARAMETER TempPath
        Optional directory path used to store the encrypted temporary blob
        created by the helper process.

        Requirements:
            - Must be accessible by both the SYSTEM account and the logged-on
              user session.
            - The directory will be created if it does not exist.

        If not specified, the default is:
            $env:SystemRoot\Tracing

        A unique file name is generated per invocation within this directory.

    .PARAMETER IconResource
        Optional icon resource to use for the dialog window.

        - If a full/relative path is provided (contains '\' or ':'), that path
          is passed directly to the helper script.
        - If only a file name is provided (for example, 'manage-bde.exe' or
          'imageres.dll'), it is resolved under:
              $env:SystemRoot\System32\<IconResource>

        If omitted or empty, the default is:
            $env:SystemRoot\System32\manage-bde.exe

        If the resolved file does not exist or cannot be loaded as an icon,
        the dialog falls back to the default WinForms icon.

    .PARAMETER HeaderText
        Optional header text displayed at the top of the dialog window.
        Defaults to: ""

    .PARAMETER InputLabelText
        Optional label text for the first input field.
        Defaults to: "Input:"

        Example: "New PIN:"

    .PARAMETER ConfirmLabelText
        Optional label text for the confirmation field when RequireConfirmation
        is specified.
        Defaults to: "Confirm:"

        Example: "Re-type PIN:"

    .PARAMETER OkButtonText
        Optional text for the primary button.
        Defaults to: "OK"

        Example: "Set PIN"

    .PARAMETER CancelButtonText
        Optional text for the cancel button.
        Defaults to: "Cancel"

    .OUTPUTS
        [SecureString]

        Returns:
            - A SecureString containing the user's input on success.
            - $null if the dialog is cancelled or if the helper fails to
              produce a valid encrypted value.

    .EXAMPLE
        # Simple PIN with numeric-only rules, confirmation, and BitLocker-style labels
        $GetMDMAOSecureUserInputParams = @{
            Title             = "BitLocker Startup PIN"
            HeaderText        = "Set BitLocker startup PIN"
            Message           = "Choose a PIN for BitLocker pre-boot authentication."
            MinimumLength     = 6
            MaximumLength     = 20
            NumericOnly       = $true
            RequireConfirmation = $true
            IconResource      = 'manage-bde.exe'
            InputLabelText    = 'New PIN:'
            ConfirmLabelText  = 'Re-type PIN:'
            OkButtonText      = 'Set PIN'
        }

        $pin = Get-MDMAOSecureUserInput @GetMDMAOSecureUserInputParams

        if ($pin)
        {
            Add-BitLockerKeyProtector `
                -MountPoint $env:SystemDrive `
                -Pin        $pin `
                -TpmAndPinProtector | Out-Null
        }

    .EXAMPLE
        # Arbitrary secret with regex enforcement, custom temp directory, and DLL icon
        $secret = Get-MDMAOSecureUserInput `
            -Title "Enter Secret Token" `
            -HeaderText "Set BitLocker startup PIN" `
            -Message "Enter the token provided by IT (format: ABC-1234-XYZ)." `
            -MinimumLength 5 `
            -MaximumLength 64 `
            -ValidationPattern '^[A-Z]{3}-\d{4}-[A-Z]{3}$' `
            -ValidationMessage "Token must match the format ABC-1234-XYZ." `
            -TempPath 'C:\ProgramData\MDMAO\SecureInput' `
            -IconResource 'shell32.dll'

        if ($secret)
        {
            # Use $secret (SecureString) as needed
        }

    .NOTES
        Function Name  : Get-MDMAOSecureUserInput
        Author         : Timothy Gruber
        Version        : 1.0.0
        Created        : 2025-12-05
        Updated        : 2025-12-08

        Version History:
        1.0.0 - (2025-12-05) Initial version
    #>

    [CmdletBinding()]
    [OutputType([SecureString])]
    param
    (
        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [int]$MinimumLength = 1,

        [Parameter()]
        [int]$MaximumLength = 256,

        [Parameter()]
        [switch]$NumericOnly,

        [Parameter()]
        [switch]$RequireConfirmation,

        [Parameter()]
        [string]$ValidationPattern,

        [Parameter()]
        [string]$ValidationMessage,

        [Parameter()]
        [string]$TempPath,

        [Parameter()]
        [string]$IconResource,

        [Parameter()]
        [string]$HeaderText,

        [Parameter()]
        [string]$InputLabelText,

        [Parameter()]
        [string]$ConfirmLabelText,

        [Parameter()]
        [string]$OkButtonText,

        [Parameter()]
        [string]$CancelButtonText
    )

    begin
    {
        Initialize-ADTFunction -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        Write-ADTLogEntry -Message "Starting function [$($MyInvocation.MyCommand.Name)] with [Title]: [$Title]."

        if ($MinimumLength -lt 1)
        {
            $MinimumLength = 1
        }

        if ($MaximumLength -lt $MinimumLength)
        {
            $MaximumLength = $MinimumLength
        }

        # Defaults for labels/buttons if not provided
        if ([string]::IsNullOrWhiteSpace($InputLabelText))
        {
            $InputLabelText = 'Input:'
        }

        if ([string]::IsNullOrWhiteSpace($ConfirmLabelText))
        {
            $ConfirmLabelText = 'Confirm:'
        }

        if ([string]::IsNullOrWhiteSpace($OkButtonText))
        {
            $OkButtonText = 'OK'
        }

        if ([string]::IsNullOrWhiteSpace($CancelButtonText))
        {
            $CancelButtonText = 'Cancel'
        }

        if ([string]::IsNullOrWhiteSpace($HeaderText))
        {
            $HeaderText = ''
        }

        # Per-run 256-bit AES key used for encryption/decryption of the secret.
        # Generated at runtime and never written to disk.
        $script:KeyBytes = New-Object 'System.Byte[]' 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($script:KeyBytes)
        $script:KeyString = [string]::Join(',', $script:KeyBytes)

        # Resolve temp directory (accessible by both SYSTEM and user session)
        $baseTempPath = if (-not [string]::IsNullOrWhiteSpace($TempPath))
        {
            $TempPath
        }
        else
        {
            Join-Path -Path $env:SystemRoot -ChildPath 'Tracing'
        }

        try
        {
            if (-not (Test-Path -Path $baseTempPath))
            {
                New-Item -Path $baseTempPath -ItemType Directory -Force | Out-Null
                Write-ADTLogEntry -Message "Created temp directory for secure input at: [$baseTempPath]."
            }
        }
        catch
        {
            $message = "Failed to create or verify temp directory for secure input at: [$baseTempPath] with error: [$_]"
            Write-ADTLogEntry -Message $message -Severity Error
            throw $message
        }

        # Temp file location accessible by both user and SYSTEM
        $script:PinTempPath = Join-Path -Path $baseTempPath -ChildPath ("MDMAO_{0}.tmp" -f ([Guid]::NewGuid().ToString("N")))

        # Safely encode the validation pattern and message for use inside the helper script
        $script:ValidationPatternBase64 = if ([string]::IsNullOrWhiteSpace($ValidationPattern))
        {
            ''
        }
        else
        {
            [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ValidationPattern))
        }

        $script:ValidationMessageBase64 = if ([string]::IsNullOrWhiteSpace($ValidationMessage))
        {
            ''
        }
        else
        {
            [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ValidationMessage))
        }

        # Resolve icon path (SYSTEM side) and escape for single-quoted literal.
        # If IconResource is just a file name, assume %SystemRoot%\System32\<IconResource>.
        # If it looks like a path (contains '\' or ':'), pass it through as-is.
        $resolvedIconPath = $null

        if (-not [string]::IsNullOrWhiteSpace($IconResource))
        {
            if ($IconResource -like '*\*' -or $IconResource -like '*:*')
            {
                $resolvedIconPath = $IconResource
            }
            else
            {
                $system32Path = Join-Path -Path $env:SystemRoot -ChildPath 'System32'
                $resolvedIconPath = Join-Path -Path $system32Path -ChildPath $IconResource
            }
        }
        else
        {
            # Default: manage-bde.exe in System32
            $system32Path = Join-Path -Path $env:SystemRoot -ChildPath 'System32'
            $resolvedIconPath = Join-Path -Path $system32Path -ChildPath 'manage-bde.exe'
        }

        $script:IconPathResolved = $resolvedIconPath
        $script:IconPathEscaped = $script:IconPathResolved -replace "'", "''"

        # Pre-escaped values for single-quoted literals in the helper script
        $script:TitleEscaped = $Title -replace "'", "''"
        $script:MessageEscaped = $Message -replace "'", "''"
        $script:HeaderTextEscaped = $HeaderText -replace "'", "''"
        $script:InputLabelEscaped = $InputLabelText -replace "'", "''"
        $script:ConfirmLabelEscaped = $ConfirmLabelText -replace "'", "''"
        $script:OkButtonTextEscaped = $OkButtonText -replace "'", "''"
        $script:CancelButtonTextEscaped = $CancelButtonText -replace "'", "''"
    }

    process
    {
        try
        {
            # Template for the helper script. All __TOKENS__ are replaced before encoding.
            $helperTemplate = @'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

$Title               = '__TITLE__'
$Message             = '__MESSAGE__'
$MinimumLength       = __MINLEN__
$MaximumLength       = __MAXLEN__
$NumericOnly         = __NUMERICFLAG__
$RequireConfirmation = __CONFIRMFLAG__

$validationPatternBase64 = '__VALPATTERN__'
$validationMessageBase64 = '__VALMSG__'
$pinTempPath             = '__PINPATH__'
$keyString               = '__KEYSTRING__'
$iconPath                = '__ICONPATH__'

$HeaderText              = '__HEADERTEXT__'
$InputLabelText          = '__INPUTLABEL__'
$ConfirmLabelText        = '__CONFIRMLABEL__'
$OkButtonText            = '__OKTEXT__'
$CancelButtonText        = '__CANCELTEXT__'

$validationPattern = $null
$validationMessage = $null

if (-not [string]::IsNullOrWhiteSpace($validationPatternBase64))
{
    $validationPattern = [System.Text.Encoding]::Unicode.GetString(
        [System.Convert]::FromBase64String($validationPatternBase64)
    )
}

if (-not [string]::IsNullOrWhiteSpace($validationMessageBase64))
{
    $validationMessage = [System.Text.Encoding]::Unicode.GetString(
        [System.Convert]::FromBase64String($validationMessageBase64)
    )
}

$form           = New-Object System.Windows.Forms.Form
$labelHeader    = New-Object System.Windows.Forms.Label
$labelInfo      = New-Object System.Windows.Forms.Label
$labelInput     = New-Object System.Windows.Forms.Label
$labelConfirm   = New-Object System.Windows.Forms.Label
$textboxInput   = New-Object System.Windows.Forms.TextBox
$textboxConfirm = New-Object System.Windows.Forms.TextBox
$statusLabel    = New-Object System.Windows.Forms.Label
$buttonOk       = New-Object System.Windows.Forms.Button
$buttonCancel   = New-Object System.Windows.Forms.Button
$baseFont       = New-Object System.Drawing.Font('Segoe UI', 9)
$form.Font      = $baseFont

$charactersLabel = if ($NumericOnly) { 'numbers' } else { 'characters' }

$form.Text            = $Title
$form.StartPosition   = 'CenterScreen'
$form.Size            = New-Object System.Drawing.Size(480, 260)
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox     = $false
$form.MinimizeBox     = $false
$form.TopMost         = $true
$form.ShowInTaskbar   = $false

# Try to use the provided icon resource (if any)
if (-not [string]::IsNullOrWhiteSpace($iconPath))
{
    try
    {
        if ([System.IO.File]::Exists($iconPath))
        {
            $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($iconPath)
        }
    }
    catch { }
}

# Optional header label
$labelHeader.AutoSize    = $true
$labelHeader.MaximumSize = New-Object System.Drawing.Size(440, 0)
$labelHeader.Font        = New-Object System.Drawing.Font('Calibri Light', 13.8)
$labelHeader.ForeColor   = [System.Drawing.Color]::MediumBlue

# Multi-line message label with wrapping
$labelInfo.AutoSize    = $true
$labelInfo.MaximumSize = New-Object System.Drawing.Size(440, 0)
$labelInfo.Text        = $Message

$labelInput.AutoSize = $true
$labelInput.Text     = $InputLabelText

$labelConfirm.AutoSize = $true
$labelConfirm.Text     = $ConfirmLabelText

# ---- two simple layouts: with header / without header ----
if ([string]::IsNullOrWhiteSpace($HeaderText))
{
    # No header: original compact layout
    $labelHeader.Visible  = $false

    $labelInfo.Location   = New-Object System.Drawing.Point(15, 15)

    $labelInput.Location  = New-Object System.Drawing.Point(15, 80)
    $textboxInput.Location              = New-Object System.Drawing.Point(140, 77)
    $textboxInput.Width                 = 280
    $textboxInput.UseSystemPasswordChar = $true
    $textboxInput.MaxLength             = $MaximumLength

    $confirmTop = 115
    $statusTop  = 145
    $buttonsTop = 180

    $form.Height = 260
}
else
{
    # With header: push everything down a bit
    $labelHeader.Text     = $HeaderText
    $labelHeader.Visible  = $true
    $labelHeader.Location = New-Object System.Drawing.Point(15, 15)

    $labelInfo.Location   = New-Object System.Drawing.Point(15, 55)

    $labelInput.Location  = New-Object System.Drawing.Point(15, 110)
    $textboxInput.Location              = New-Object System.Drawing.Point(140, 107)
    $textboxInput.Width                 = 280
    $textboxInput.UseSystemPasswordChar = $true
    $textboxInput.MaxLength             = $MaximumLength

    $confirmTop = 145
    $statusTop  = 175
    $buttonsTop = 210

    $form.Height = 285
}

$labelConfirm.Location = New-Object System.Drawing.Point(15, $confirmTop)
$textboxConfirm.Location              = New-Object System.Drawing.Point(140, ($confirmTop - 3))
$textboxConfirm.Width                 = 280
$textboxConfirm.UseSystemPasswordChar = $true
$textboxConfirm.MaxLength             = $MaximumLength

if (-not $RequireConfirmation)
{
    $labelConfirm.Visible   = $false
    $textboxConfirm.Visible = $false
}

$statusLabel.AutoSize  = $true
$statusLabel.Location  = New-Object System.Drawing.Point(15, $statusTop)
$statusLabel.ForeColor = [System.Drawing.Color]::Red

$buttonOk.Text         = $OkButtonText
$buttonOk.Width        = 85
$buttonOk.Location     = New-Object System.Drawing.Point(245, $buttonsTop)
$buttonOk.DialogResult = [System.Windows.Forms.DialogResult]::OK

$buttonCancel.Text         = $CancelButtonText
$buttonCancel.Width        = 85
$buttonCancel.Location     = New-Object System.Drawing.Point(340, $buttonsTop)
$buttonCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

$form.AcceptButton = $buttonOk
$form.CancelButton = $buttonCancel

$buttonOk.Add_Click({
    $inputText   = $textboxInput.Text
    $confirmText = $textboxConfirm.Text

    if ([string]::IsNullOrWhiteSpace($inputText))
    {
        $statusLabel.Text  = 'Input cannot be empty.'
        $form.DialogResult = [System.Windows.Forms.DialogResult]::None
        return
    }

    if ($inputText.Length -lt $MinimumLength -or $inputText.Length -gt $MaximumLength)
    {
        $statusLabel.Text  = "Input must be $MinimumLength-$MaximumLength $charactersLabel long."
        $form.DialogResult = [System.Windows.Forms.DialogResult]::None
        return
    }

    if ($NumericOnly -and ($inputText -notmatch '^\d+$'))
    {
        $statusLabel.Text  = 'Only numeric digits (0-9) are allowed.'
        $form.DialogResult = [System.Windows.Forms.DialogResult]::None
        return
    }

    if ($RequireConfirmation -and ($inputText -ne $confirmText))
    {
        $statusLabel.Text  = 'Input values do not match.'
        $form.DialogResult = [System.Windows.Forms.DialogResult]::None
        return
    }

    if ($validationPattern -and ($inputText -notmatch $validationPattern))
    {
        if ([string]::IsNullOrWhiteSpace($validationMessage))
        {
            $statusLabel.Text = 'Input does not match the required format.'
        }
        else
        {
            $statusLabel.Text = $validationMessage
        }

        $form.DialogResult = [System.Windows.Forms.DialogResult]::None
        return
    }
})

$form.Controls.Add($labelHeader)
$form.Controls.Add($labelInfo)
$form.Controls.Add($labelInput)
$form.Controls.Add($textboxInput)
$form.Controls.Add($labelConfirm)
$form.Controls.Add($textboxConfirm)
$form.Controls.Add($statusLabel)
$form.Controls.Add($buttonOk)
$form.Controls.Add($buttonCancel)

$dialogResult = $form.ShowDialog()

if ($dialogResult -ne [System.Windows.Forms.DialogResult]::OK)
{
    # User cancelled
    [Environment]::ExitCode = 1
    return
}

# Convert to SecureString and encrypt with per-run AES key
$secure    = ConvertTo-SecureString -String $textboxInput.Text -AsPlainText -Force
$keyBytes  = $keyString.Split(',') | ForEach-Object { [byte]$_ }
$encrypted = ConvertFrom-SecureString -SecureString $secure -Key $keyBytes

# Write encrypted blob to temp file
Set-Content -Path $pinTempPath -Value $encrypted -Encoding ASCII -Force

[Environment]::ExitCode = 0
'@

            # Apply token replacements
            $helperScript = $helperTemplate
            $helperScript = $helperScript.Replace('__TITLE__', $script:TitleEscaped)
            $helperScript = $helperScript.Replace('__MESSAGE__', $script:MessageEscaped)
            $helperScript = $helperScript.Replace('__MINLEN__', $MinimumLength.ToString())
            $helperScript = $helperScript.Replace('__MAXLEN__', $MaximumLength.ToString())

            $numericFlagLiteral = if ($NumericOnly.IsPresent) { '$true' } else { '$false' }
            $confirmFlagLiteral = if ($RequireConfirmation.IsPresent) { '$true' } else { '$false' }

            $helperScript = $helperScript.Replace('__NUMERICFLAG__', $numericFlagLiteral)
            $helperScript = $helperScript.Replace('__CONFIRMFLAG__', $confirmFlagLiteral)
            $helperScript = $helperScript.Replace('__PINPATH__', $script:PinTempPath)
            $helperScript = $helperScript.Replace('__KEYSTRING__', $script:KeyString)
            $helperScript = $helperScript.Replace('__VALPATTERN__', $script:ValidationPatternBase64)
            $helperScript = $helperScript.Replace('__VALMSG__', $script:ValidationMessageBase64)
            $helperScript = $helperScript.Replace('__ICONPATH__', $script:IconPathEscaped)

            $helperScript = $helperScript.Replace('__INPUTLABEL__', $script:InputLabelEscaped)
            $helperScript = $helperScript.Replace('__CONFIRMLABEL__', $script:ConfirmLabelEscaped)
            $helperScript = $helperScript.Replace('__OKTEXT__', $script:OkButtonTextEscaped)
            $helperScript = $helperScript.Replace('__CANCELTEXT__', $script:CancelButtonTextEscaped)
            $helperScript = $helperScript.Replace('__HEADERTEXT__', $script:HeaderTextEscaped)

            # Encode helper script to base64 for -EncodedCommand
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($helperScript)
            $encodedCommand = [Convert]::ToBase64String($bytes)

            $startParams = @{
                FilePath                 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
                ArgumentList             = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
                SecureArgumentList       = $true
                UseHighestAvailableToken = $true
                WindowStyle              = 'Hidden'
                WaitForChildProcesses    = $true
                PassThru                 = $true
                ErrorAction              = 'SilentlyContinue'
            }

            Write-ADTLogEntry -Message "Launching secure user input helper in logged-on user session from [$($MyInvocation.MyCommand.Name)]."

            $helperResult = Start-ADTProcessAsUser @startParams

            if (-not $helperResult -or $helperResult.ExitCode -ne 0)
            {
                Write-ADTLogEntry -Message "Secure user input helper exited with [ExitCode]: [$($helperResult.ExitCode)]. Treating as cancellation." -Severity Warning
                return $null
            }

            if (-not (Test-Path -Path $script:PinTempPath))
            {
                Write-ADTLogEntry -Message "Secure input helper completed but no temp file was found at: [$($script:PinTempPath)]." -Severity Warning
                return $null
            }

            # Read and decrypt the AES blob to a SecureString
            $encryptedValue = Get-Content -Path $script:PinTempPath -ErrorAction Stop
            Remove-Item -Path $script:PinTempPath -Force -ErrorAction SilentlyContinue

            if ([string]::IsNullOrWhiteSpace($encryptedValue))
            {
                Write-ADTLogEntry -Message "Encrypted temp file at: [$($script:PinTempPath)] was empty. Treating as cancellation." -Severity Warning
                return $null
            }

            $secureResult = ConvertTo-SecureString -String $encryptedValue -Key $script:KeyBytes

            return $secureResult
        }
        catch
        {
            $message = "Failed to collect secure user input in [$($MyInvocation.MyCommand.Name)] with error: [$_]"
            Write-ADTLogEntry -Message $message -Severity Error
            throw
        }
    }

    end
    {
        Write-ADTLogEntry -Message "Completed function [$($MyInvocation.MyCommand.Name)] with [Title]: [$Title]."
        Complete-ADTFunction -Cmdlet $PSCmdlet
    }
}
