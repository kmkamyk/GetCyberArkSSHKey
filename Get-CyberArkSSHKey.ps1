---

### Skrypt: Get-CyberArkSSHKey.ps1 (w języku angielskim)

```powershell
<#
.SYNOPSIS
    Retrieves an SSH private key from a CyberArk Vault using the REST API.
    This script handles Windows Integrated Authentication and Multi-Factor Authentication (MFA).

.DESCRIPTION
    The script follows these steps:
    1. Authenticates to the CyberArk API using the current Windows user's credentials.
    2. If MFA is required, it prompts the user for a one-time password.
    3. Searches for a target account's ID based on its safe and properties.
    4. Retrieves the SSH private key for the found account.
    5. Saves the key to a local file.
    6. Logs out of the API session.

.NOTES
    Author: AI Generated Example
    Version: 1.0
    Requires: PowerShell 5.1 or later.
#>

# =================================================================================
# === CONFIGURATION - Adjust these variables for your environment ===
# =================================================================================

# Base URI for your CyberArk PVWA instance's API
$baseURI = "https://cyberark.yourdomain.com/PasswordVault"

# The name of the safe where the target account is stored
$safeName = "Your-Target-SafeName"

# Properties to uniquely identify the target account
# Use a combination that best fits your account configuration
$accountAddress = "target.server.address" # e.g., IP address or FQDN
$accountUsername = "ssh_username"          # e.g., root, ec2-user

# The local file path where the retrieved SSH key will be saved
$sshKeyOutputPath = "C:\Temp\id_rsa_from_cyberark.pem"

# The reason for retrieving the credential (often required by CyberArk policy)
$retrievalReason = "Administrative access for ticket JIRA-1234"

# =================================================================================
# === SCRIPT LOGIC (Usually does not require modification) ===
# =================================================================================

# Initialize session token
$sessionToken = $null

try {
    # Step 1: Windows Integrated Authentication (Logon, Stage 1)
    Write-Host "[INFO] Step 1: Attempting logon using Windows credentials..."
    $logonURI = "$baseURI/api/auth/Cyberark/Logon"
    
    $logonResponse = Invoke-RestMethod -Method Post -Uri $logonURI -UseDefaultCredentials
    # In older APIs, the token might be in a nested property like $logonResponse.CyberArkLogonResult
    $cyberarkLogonToken = $logonResponse
    
    Write-Host "[SUCCESS] Successfully obtained a temporary logon token."

    # Step 2: Handle Multi-Factor Authentication (MFA/2FA)
    # In modern API versions, a successful first step returns available MFA mechanisms if required.
    # This example assumes a simple OTP flow and may need adaptation.
    
    Write-Host "[INFO] Step 2: Awaiting second factor authentication (MFA)..."
    $mfaCode = Read-Host -Prompt "[INPUT] Please enter your authentication code (e.g., from an authenticator app)"
    
    $mfaURI = "$baseURI/api/auth/Cyberark/AdvanceAuthentication"
    $mfaBody = @{
        "authenticationAction" = "OobChallenge" # This value may vary based on your config
        "answer" = $mfaCode
    } | ConvertTo-Json
    
    $mfaHeaders = @{
        "Authorization" = $cyberarkLogonToken
    }

    # Send the MFA response to get the final session token
    $sessionToken = Invoke-RestMethod -Method Post -Uri $mfaURI -Headers $mfaHeaders -Body $mfaBody -ContentType "Application/json"
    
    if (-not $sessionToken) {
        throw "Failed to obtain the final session token after the MFA step."
    }
    Write-Host "[SUCCESS] MFA completed successfully."

    # Prepare the authorization header for subsequent requests
    $authHeader = @{
        # Newer APIs (v10+) typically use a Bearer token
        "Authorization" = "Bearer $sessionToken" 
    }

    # Step 3: Find the Account ID
    Write-Host "[INFO] Step 3: Searching for account '$accountUsername@$accountAddress' in safe '$safeName'..."
    $searchQuery = "safe=$($safeName)&userName=$($accountUsername)&address=$($accountAddress)"
    $accountsURI = "$baseURI/api/accounts?$searchQuery"
    
    $foundAccounts = Invoke-RestMethod -Method Get -Uri $accountsURI -Headers $authHeader
    
    if ($foundAccounts.count -eq 0) {
        throw "No matching account found in safe '$safeName'."
    }
    if ($foundAccounts.count -gt 1) {
        Write-Warning "Found more than one matching account. Using the first one in the list."
    }
    
    $accountId = $foundAccounts.value[0].id
    Write-Host "[SUCCESS] Found account. ID: $accountId"

    # Step 4: Retrieve the SSH Key (treated as the account's "password")
    Write-Host "[INFO] Step 4: Retrieving SSH key for account ID: $accountId..."
    $retrieveURI = "$baseURI/api/accounts/$accountId/password/retrieve"
    
    $retrieveBody = @{
        "reason" = $retrievalReason
    } | ConvertTo-Json
    
    # Call the API to retrieve the key content
    $sshPrivateKey = Invoke-RestMethod -Method Post -Uri $retrieveURI -Headers $authHeader -Body $retrieveBody -ContentType "Application/json"
    
    if (-not $sshPrivateKey) {
        throw "Failed to retrieve the SSH key. The server response was empty."
    }
    Write-Host "[SUCCESS] SSH key retrieved successfully."

    # Step 5: Save the Key to a File
    Write-Host "[INFO] Step 5: Saving key to file: $sshKeyOutputPath"
    # Ensure the target directory exists
    $outputDir = Split-Path -Parent -Path $sshKeyOutputPath
    if (-not (Test-Path -Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
    }
    
    # Write the key content to the file
    $sshPrivateKey | Out-File -FilePath $sshKeyOutputPath -Encoding ascii
    
    # Optional: Set secure file permissions (for Windows)
    try {
        $acl = Get-Acl $sshKeyOutputPath
        $acl.SetAccessRuleProtection($true, $false) # Remove inherited permissions
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl -Path $sshKeyOutputPath -AclObject $acl
        Write-Host "[INFO] Set file permissions on key file (current user only)."
    } catch {
        Write-Warning "Could not set file permissions on the key file: $($_.Exception.Message)"
    }

    Write-Host "[COMPLETE] SSH key has been saved to: $sshKeyOutputPath"

} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    # Display the full API error response if available
    if ($_.Exception.Response) {
        $errorResponse = $_.Exception.Response.GetResponseStream()
        $streamReader = New-Object System.IO.StreamReader($errorResponse)
        $errorBody = $streamReader.ReadToEnd()
        Write-Error "Server Response: $errorBody"
    }
} finally {
    # Step 6: Logoff - ALWAYS run this, even if errors occurred
    if ($sessionToken) {
        Write-Host "[INFO] Step 6: Logging off API session..."
        $logoffURI = "$baseURI/api/auth/Logoff"
        try {
            Invoke-RestMethod -Method Post -Uri $logoffURI -Headers $authHeader | Out-Null
            Write-Host "[SUCCESS] Session logged off successfully."
        } catch {
            Write-Warning "An error occurred during logoff. The token may have already expired."
        }
    }
}