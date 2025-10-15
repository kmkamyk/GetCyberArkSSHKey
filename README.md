# CyberArk SSH Key Retrieval PowerShell Script

A PowerShell script to securely fetch an SSH private key from a CyberArk Vault using the REST API. It handles Windows Integrated Authentication and prompts for a Multi-Factor Authentication (MFA/2FA) code.

## Description

This script automates the process of retrieving SSH private keys stored in the CyberArk Privileged Access Management (PAM) solution. It is designed to be run by a user on a domain-joined Windows machine, using their current Windows session for the initial authentication step.

The script retrieves the key in its original format (typically PEM) and saves it to a local file.

## Features

-   **Windows Integrated Authentication**: Leverages the current user's Windows credentials for the initial login to CyberArk (SSO).
-   **MFA/2FA Support**: Prompts the user to enter a one-time password (OTP) to complete the multi-factor authentication process.
-   **Account Discovery**: Searches for the target account within a specified safe using properties like username and address.
-   **Secure Retrieval**: Downloads the SSH private key associated with the account.
-   **File Output**: Saves the retrieved key to a local file.
-   **Automatic Session Logout**: Ensures the API session is properly terminated after the operation is complete or if an error occurs.

## Prerequisites

1.  **PowerShell**: PowerShell 5.1 or newer.
2.  **Network Access**: Connectivity from the machine running the script to the CyberArk PVWA (Password Vault Web Access) API endpoint.
3.  **CyberArk Permissions**: The user running the script must have:
    -   Permissions to authenticate to the CyberArk API.
    -   Permissions to view and retrieve credentials from the specified safe and target account.
4.  **CyberArk Configuration**: The CyberArk environment must be configured to allow:
    -   REST API access.
    -   Windows Integrated Authentication via the API.
    -   MFA/2FA for API sessions.

## Configuration

Before running the script, you must edit the `Get-CyberArkSSHKey.ps1` file and update the variables in the **CONFIGURATION** section.

```powershell
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

# The local file path where the retrieved SSH key will be saved
$sshKeyOutputPath = "C:\Temp\id_rsa_from_cyberark.pem"

# The reason for retrieving the credential (often required by CyberArk policy)
$retrievalReason = "Administrative access for ticket JIRA-1234"
```
## Usage

1.  Clone this repository or download the `Get-CyberArkSSHKey.ps1` script.
2.  Open the script in a code editor (like VS Code).
3.  Modify the variables in the **CONFIGURATION** section to match your environment.
4.  Open a PowerShell terminal and navigate to the directory where you saved the script.
5.  Run the script:
    ```powershell
    .\Get-CyberArkSSHKey.ps1
    ```
6.  When prompted, enter your MFA/2FA code from your authenticator app.
7.  If successful, the script will create the SSH key file at the path specified in `$sshKeyOutputPath`.

## Disclaimer

-   **Template Script**: This script is a template and may require modifications to work with your specific CyberArk version, API endpoints, or authentication flow. Always consult the API documentation for your CyberArk version.
-   **Security**: Storing private keys on a disk is a security risk. For production or automated use cases, consider loading the key directly into memory for use with an SSH client and clearing it immediately after the session ends, instead of saving it to a file.
-   **No Warranty**: This script is provided as-is, without any warranty. Use it at your own risk.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
