<#
.SYNOPSIS
    Retrieves an SSH private key from a CyberArk Vault using the REST API and optionally converts it to PPK format.

.DESCRIPTION
    The script follows these steps:
    1. Authenticates to the CyberArk API using the current Windows user's credentials.
    2. If MFA is required, it prompts the user for a one-time password.
    3. Searches for a target account's ID based on its safe and properties.
    4. Retrieves the SSH private key (in PEM format) for the found account.
    5. Saves the key to a local PEM file.
    6. If enabled, it uses puttygen.exe to convert the PEM key to PPK format.
    7. Logs out of the API session.

.NOTES
    Author: AI Generated Example
    Version: 1.1
    Requires: PowerShell 5.1 or later. For PPK conversion, PuTTY (puttygen.exe) must be installed.
#>

# =================================================================================
# === CONFIGURATION - Adjust these variables for your environment ===
# =================================================================================

# Base URI for your CyberArk PVWA instance's API
$baseURI = "https://cyberark.yourdomain.com/PasswordVault"

# The name of the safe where the target account is stored
$safeName = "Your-Target-SafeName"

# Properties to uniquely identify the target account
$accountAddress = "target.server.address" # e.g., IP address or FQDN
$accountUsername = "ssh_username"          # e.g., root, ec2-user

# The local file path where the retrieved PEM SSH key will be saved
$sshKeyOutputPathPEM = "C:\Temp\id_rsa_from_cyberark.pem"

# The reason for retrieving the credential (often required by CyberArk policy)
$retrievalReason = "Administrative access for ticket JIRA-1234"

# --- PPK Conversion Settings ---

# Set to $true to automatically convert the PEM key to PPK format
$convertToPPK = $true

# Full path to puttygen.exe. This is required if $convertToPPK is $true.
# Usually located in "C:\Program Files\PuTTY\puttygen.exe"
$puttygenPath = "C:\Program Files\PuTTY\puttygen.exe"

# The local file path where the converted PPK key will be saved.
# This path is generated automatically based on the PEM path.
$sshKeyOutputPathPPK = $sshKeyOutputPathPEM.Replace(".pem", ".ppk")

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
    $cyberarkLogonToken = $logonResponse
    Write-Host "[SUCCESS] Successfully obtained a temporary logon token."

    # Step 2: Handle Multi-Factor Authentication (MFA/2FA)
    Write-Host "[INFO] Step 2: Awaiting second factor authentication (MFA)..."
    $mfaCode = Read-Host -Prompt "[INPUT] Please enter your authentication code"
    $mfaURI = "$baseURI/api/auth/Cyberark/AdvanceAuthentication"
    $mfaBody = @{ "authenticationAction" = "OobChallenge"; "answer" = $mfaCode } | ConvertTo-Json
    $mfaHeaders = @{ "Authorization" = $cyberarkLogonToken }
    $sessionToken = Invoke-RestMethod -Method Post -Uri $mfaURI -Headers $mfaHeaders -Body $mfaBody -ContentType "Application/json"
    if (-not $sessionToken) { throw "Failed to obtain the final session token after the MFA step." }
    Write-Host "[SUCCESS] MFA completed successfully."

    $authHeader = @{ "Authorization" = "Bearer $sessionToken" }

    # Step 3: Find the Account ID
    Write-Host "[INFO] Step 3: Searching for account '$accountUsername@$accountAddress' in safe '$safeName'..."
    $searchQuery = "safe=$($safeName)&userName=$($accountUsername)&address=$($accountAddress)"
    $accountsURI = "$baseURI/api/accounts?$searchQuery"
    $foundAccounts = Invoke-RestMethod -Method Get -Uri $accountsURI -Headers $authHeader
    if ($foundAccounts.count -eq 0) { throw "No matching account found in safe '$safeName'." }
    if ($foundAccounts.count -gt 1) { Write-Warning "Found more than one matching account. Using the first one." }
    $accountId = $foundAccounts.value[0].id
    Write-Host "[SUCCESS] Found account. ID: $accountId"

    # Step 4: Retrieve the SSH Key
    Write-Host "[INFO] Step 4: Retrieving SSH key for account ID: $accountId..."
    $retrieveURI = "$baseURI/api/accounts/$accountId/password/retrieve"
    $retrieveBody = @{ "reason" = $retrievalReason } | ConvertTo-Json
    $sshPrivateKey = Invoke-RestMethod -Method Post -Uri $retrieveURI -Headers $authHeader -Body $retrieveBody -ContentType "Application/json"
    if (-not $sshPrivateKey) { throw "Failed to retrieve the SSH key. The server response was empty." }
    Write-Host "[SUCCESS] SSH key retrieved successfully."

    # Step 5: Save the Key to a PEM File
    Write-Host "[INFO] Step 5: Saving PEM key to file: $sshKeyOutputPathPEM"
    $outputDir = Split-Path -Parent -Path $sshKeyOutputPathPEM
    if (-not (Test-Path -Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
    $sshPrivateKey | Out-File -FilePath $sshKeyOutputPathPEM -Encoding ascii
    Write-Host "[SUCCESS] PEM key saved."

    # Step 6: Convert PEM to PPK (if enabled)
    if ($convertToPPK) {
        Write-Host "[INFO] Step 6: Converting PEM key to PPK format..."
        if (-not (Test-Path -Path $puttygenPath)) {
            throw "PuTTYgen not found at the specified path: $puttygenPath. Cannot convert key."
        }
        
        # Command line arguments for puttygen to perform a non-interactive conversion
        $puttygenArgs = "'$sshKeyOutputPathPEM' -o '$sshKeyOutputPathPPK' --new-passphrase ''"
        
        Start-Process -FilePath $puttygenPath -ArgumentList $puttygenArgs -Wait -NoNewWindow
        
        if (Test-Path -Path $sshKeyOutputPathPPK) {
            Write-Host "[SUCCESS] Key successfully converted and saved to: $sshKeyOutputPathPPK"
        } else {
            throw "Failed to convert the key to PPK format. Check PuTTYgen logs or permissions."
        }
    }

    Write-Host "[COMPLETE] Operation finished."

} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $errorResponse = $_.Exception.Response.GetResponseStream()
        $streamReader = New-Object System.IO.StreamReader($errorResponse)
        $errorBody = $streamReader.ReadToEnd()
        Write-Error "Server Response: $errorBody"
    }
} finally {
    # Step 7: Logoff
    if ($sessionToken) {
        Write-Host "[INFO] Step 7: Logging off API session..."
        $logoffURI = "$baseURI/api/auth/Logoff"
        try {
            Invoke-RestMethod -Method Post -Uri $logoffURI -Headers $authHeader | Out-Null
            Write-Host "[SUCCESS] Session logged off successfully."
        } catch {
            Write-Warning "An error occurred during logoff. The token may have already expired."
        }
    }
}