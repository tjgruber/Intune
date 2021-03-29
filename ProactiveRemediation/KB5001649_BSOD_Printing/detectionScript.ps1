<# detectionScript.ps1

.SYNOPSIS
    Detects if MS patches causing printing and BSOD issues are installed, if the patch fix is installed, and exits appropriately.
.DESCRIPTION
    Detects the presense of app or desired setting. Remediation will be triggered when the script both returns a 1 value exit code and writes a string value to STDOUT.
	This detects if the patches with issues are installed, or if the patch fix is installed. The script exits appropriately for remediation to occur if needed.
    Update the download URL (kbMSUDownloadURL), KB number (kbMSU), and outFile variable definitions appropriately.
	Customize "Script Logic" section to detect appropriately to your needs.
.LINK
    https://TimothyGruber.com

#>

<#########################################
## BEGIN SCRIPT LOGIC
#########################################>

# Patches with issues:
	$patchesWithIssues = "KB5000802|KB5000808|KB5000809|KB5000822"

# Patch fix:
	$patchFix = "KB5001649"

# Check if device has any of the patches with issues installed:
	$issuePatchesInstalled = Get-HotFix | Where-Object -Property HotFixID -Match $patchesWithIssues

# Check if device has patch fix installed:
	$fixPatchInstalled = Get-HotFix | Where-Object -Property HotFixID -EQ $patchFix

# If device has patch fix installed, exit with success. No action needed. Otherwise, if problem patches are found, exit with error, patch is still needed.
	if ($fixPatchInstalled.HotFixID) {

		# MS Patch fix (KB5001649) is detected as installed, nothing to do
			Write-Output -InputObject "SUCCESS : Microsoft patch KB5001649 is installed"
			Exit 0

	} else {

		# MS Patch fix (KB5001649) is NOT detected. Check if patch fix should be installed:
			if ($issuePatchesInstalled.HotFixID) {

				# MS problem patch is detected, therefore the patch fix (KB5001649) should be installed.
					Write-Output -InputObject "WARNING : Microsoft patch KB5001649 NOT detected on device!"
					Exit 1

			} else {
				# MS problem patch is NOT detected, therefore the patch fix (KB5001649) is not required.
					Write-Output -InputObject "NOT APPLICABLE : The patches with issues (KB5000802/808/809/822) are not detected. The MS patch fix (KB5001649) is not required!"
					Exit 0
			}

	}

<#########################################
## END SCRIPT LOGIC
#########################################>
