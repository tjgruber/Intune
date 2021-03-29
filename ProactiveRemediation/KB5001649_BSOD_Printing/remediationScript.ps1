<# remediationScript.ps1

.SYNOPSIS
    Installs the defined (KB5001649) MSU.
.DESCRIPTION
    Downloads and installs the defined (KB5001649) MSU
    Update the download URL (kbMSUDownloadURL), KB number (kbMSU), and outFile variable definitions appropriately.
.LINK
    https://TimothyGruber.com

#>

# MS Update download url
    $kbMSUDownloadURL = 'http://download.windowsupdate.com/d/msdownload/update/software/updt/2021/03/windows10.0-kb5001649-x64_aca549448414a5ad559c742c39e9342468a23eb5.msu'

# KB
    $kbMSU = 'KB5001649'

# Test the download
    $downloadTestPass = $false
    Write-Output "Testing $kbMSU MSU URL"
    $kbDownloadTest = Invoke-WebRequest -Uri $kbMSUDownloadURL -Method Head -UseBasicParsing -ErrorAction SilentlyContinue -ErrorVariable DLTESTERR
    if ($kbDownloadTest.Headers.'Content-Length' -gt 120000) {
        # Download test passed
        Write-Output "The $kbMSU MSU URL test passed"
        $downloadTestPass = $true
    } else {
        # Download test failed
        Write-Output "ERROR: The $kbMSU MSU download url [$kbMSUDownloadURL] test failed. [$DLTESTERR]"
        Exit 1
    }

# Download MSU to temp folder
    if ($downloadTestPass -eq $true) {
        $outFile = 'windows10.0-kb5001649-x64_aca549448414a5ad559c742c39e9342468a23eb5.msu'
        Write-Output "Creating temp folder location if not already exist at [$env:TEMP\$($kbMSU)MSU]"
        $newDir = New-Item -Path "$env:TEMP\$($kbMSU)MSU" -ItemType Directory -Force
        $outFilePath = "$env:TEMP\$($kbMSU)MSU\$outFile"

        Write-Output "Downloading $kbMSU MSU to [$outFilePath]"
        (New-Object System.Net.WebClient).DownloadFile($kbMSUDownloadURL, $outFilePath)

        Write-Output "Verifying file download success"
        if (-not (Test-Path -Path $outFilePath)) {
            Write-Output "ERROR - There was a problem downloading the $kbMSU MSU!"
            Exit 1
        } else {
            Write-Output "$kbMSU MSU downloaded successfully to [$outFilePath]"
        }
    }

# Silently execute the MSU
    Write-Output "Executing the $kbMSU MSU from [$outFilePath]"
    Start-Process -FilePath "$env:SystemRoot\System32\wusa.exe" -ArgumentList "$outFilePath /quiet /promptrestart" -WindowStyle Hidden -Wait
    Write-Output "Finished executing the $kbMSU MSU from [$outFilePath]"

# Clean up the temp folder and downloaded file
    Write-Output "Cleaning up temp folder and $kbMSU MSU file"
    Remove-Item -Path $newDir -Recurse -Force
    Write-Output "Remediation completed"
    Exit 0
