# PDI - Password Directive Implementation

**A Python-based automated tool for adhering to DG Workstation Password and Account Policy**

- **Overview**

The Password Directive Implementation (PDI) tool is a Python script designed to enforce specific password policy settings on Windows systems based on guidelines provided by the Director General of C-DAC: Centre for Development of Advanced Computing. The tool primarily utilizes PowerShell commands to check and modify Group Policy settings and implement additional user management tasks.

- **Guidelines Implemented**

1. **Password Complexity**
  1. Passwords must be at least 15 characters long.
  2. Passwords must contain a mix of uppercase, lowercase, numbers, and special characters.

1. **Periodic Changes**
  1. Passwords should expire every six (6) months.

1. **Account Lockout**
  1. Enable automatic account lockout mechanisms after five (5) unsuccessful login attempts.

- **Tool Functionalities**

1. **Group Policy Checks**

1. The tool checks the following Group Policy settings:
  1. Maximum password age (180 days) [Local Computer Policy Configuration \> Policies \> Windows Settings \> Security Settings \> Account Policies \> Password Policy \> Maximum password age]
  2. Password complexity requirements (Enabled) [Local Computer Policy Configuration \> Policies \> Windows Settings \> Security Settings \> Account Policies \> Password Policy \> Password must meet complexity requirements]
  3. Relaxation of minimum password length limits (Enabled) [Local Computer Policy Configuration \> Policies \> Windows Settings \> Security Settings \> Account Policies \> Password Policy \> Relaxation of minimum password length limits]
  4. Minimum password length (15 characters) [Local Computer Policy Configuration \> Policies \> Windows Settings \> Security Settings \> Account Policies \> Password Policy \> Minimum password length]
  5. Account lockout threshold (5 invalid attempts) [Local Computer Policy Configuration \> Policies \> Windows Settings \> Security Settings \> Account Policies \> Account Lockout Policy \> Account lockout threshold]

1. **Group Policy Modifications**

1. The tool makes recommended changes to the Group Policy settings using PowerShell commands and scripts.

1. **User Management**

1. The tool creates a user named "systemadmin" with predefined settings (password, description, etc.).
2. Sets additional parameters for the user:

  1. **PasswordNeverExpires:** Prevents the user's password from expiring.
  2. **UserMayNotChangePassword:** Disables the user's ability to change their password.
  3. **AccountNeverExpires:** Prevents the user's account from expiring.

1. Make the user member of these groups:

  1. **Administrators:** For giving the newly created user admin rights.
  2. **Users:** For enable login features for this account in future use.

1. Updates existing users' settings for all users except "Guest", "DefaultAccount", "Administrator", "WDAGUtilityAccount", and the automatically created user, sets the following parameters:

  1. **PasswordNeverExpires:** Disables the automatic password expiration.
  2. **ForcePasswordChange:** Requires the user to change their password at their next logon.

- **Workflow**

1. **Initialization**
  1. **Importing Modules**
    1. Import necessary modules and libraries (`os`, `sys`, `time`, `ctypes`, `datetime`, `subprocess`).
    2. Define ANSII colour codes for console output.
  2. **Configuration**
    1. Set `debug_mode` and `command_prefix` variables for debugging purposes.
    2. Initialize variables for password policy checks and new user creation.
2. **Group Policy Checks**
  1. Function: `check_MinMaxPassAge()`
    1. Use PowerShell command to check the maximum and minimum password age.
    2. Update global variables (`check_MaxPassAge` and `check_MinPassAge`) based on policy compliance.
  2. Function: `check_PassComplex_MinPassLength_Badlock()`
    1. Use PowerShell command to export security policy settings to a file.
    2. Parse the file and update global variables for password complexity, minimum password length, and account lockout threshold.
  3. Function: `check_gpo()`
    1. Call the above functions to check various Group Policy settings.
    2. Print the results in coloured output for easy readability.
3. **Group Policy Modifications**
  1. Function: `RelaxMinimumPasswordLengthLimits()`
    1. Use PowerShell command to create a registry entry to relax minimum password length limits.
  2. Function: `others_policy_implementation()`
    1. Generate a PowerShell script to parse and modify security policy settings.
    2. Execute the script to update Group Policy settings.
  3. Function: `update_GPO()`
    1. Call the above functions to implement recommended changes in Group Policy settings.
    2. User Management
  4. Function: `create_AdminUser()`
    1. Generate a PowerShell script to create a new user with predefined settings.
    2. Execute the script to create the user and add it to the "Administrators" and "Users" groups.
  5. Function: `update_users()`
    1. Use PowerShell commands to get a list of local users (excluding system accounts).
    2. Iterate through users and update password settings.
4. **Console Output**
  1. Display coloured console output indicating system information, administrative rights, Group Policy checks, and script execution status.
5. **Script Execution**
  1. Check for Windows system detection and administrator rights.
  2. If conditions are met, execute the Group Policy checks, modifications, user creation, and update functions.
  3. Display the result of each operation and prompt the user to press Enter to close the console.

- **Error Handling**

1. The tool includes error handling for possible failures during the execution of PowerShell commands.
2. Possible Error Codes:

    1. **Error Code 1:** Failed to create user account.
    2. **Error Code 2:** Failed to update settings for existing users.

- **Usage**

1. Ensure the script is executed with administrative privileges.
2. Run the script on a Windows system that not in an Active Directory Domain.

- **Future Scope**
  1. The tool can be extended to include the following functionalities:
    1. **Cross-Platform Support:** Extend support for other operating systems.
    2. **Customization:** Allow users to customize default user name password and details.
    3. **Reboot:** Add support to reboot the system with user concern on complication of the tool execution.

- **Requirements**

1. The tool requires PowerShell to be installed on the Windows system.
2. The Windows system should be configured as a standalone workstation, not as a part of a domain controller.
3. Administrative privileges are necessary for successful execution.
4. Professional version of windows required as Group Policy doesn't available on Windows Home Editions.
5. For directly execution the python script Python version 3.7 or Higher is required.
