# -*- coding: utf-8 -*-
import os
import sys
import time
import ctypes
import datetime
import subprocess


red = "\u001b[38;5;160m"
light_red = "\u001b[38;5;208m"
green = "\033[0;32m"
yellow = "\u001b[38;5;184m"
nocolor = "\033[0m"
cyan = "\033[36m"
ascii_col = "\033[0;92m"
log_col = "\u001b[38;5;110m"


debug_mode = False
command_prefix = ""
# Suppress powershell errors when debug mode is False
if not debug_mode:
    command_prefix = "$ErrorActionPreference = 'SilentlyContinue';"

# Maximum password age
check_MaxPassAge = "N/A"
# Minimum password length
check_MinPassAge = "N/A"
# Password must meet complexity requirements
check_PassComplexity = "N/A"
# Relax minimum password length limits
check_MinPassLength = "N/A"

# Account lockout threshold
check_BadLock = "N/A"

# New User Name
name = "sysadmin"
# New User Full Name
fname = "Sys Admin"
# New User Password
password = "Demo Password" #Please Change with your password before execution of the code
# New User Description
des = "System Administrator Account CDAC Kolakta"

def check_MinMaxPassAge():
    global check_MaxPassAge, check_MinPassAge
    command = command_prefix+'net accounts'
    result = subprocess.run( ["powershell", command], shell=True, stdout=subprocess.PIPE)
    output = result.stdout.decode("utf-8")
    for line in output.split('\n'):
        try:
            if "Maximum password age (days): " in line:
                max_password_age =  int(line.split(":")[1].strip())
                if max_password_age == 180:
                    check_MaxPassAge = True
                else:
                    check_MaxPassAge = False
        except:
            pass
        try:
            if "Minimum password length: " in line:
                min_password_len =  int(line.split(":")[1].strip())
                if min_password_len >= 15 :
                    check_MinPassAge = True
                else:
                    check_MinPassAge = False
        except:
            pass

def check_PassComplex_MinPassLength_Badlock():
    global check_PassComplexity, check_MinPassLength, check_BadLock
    command = command_prefix+"secedit /export /areas securitypolicy /cfg 'C:\\secpol.cfg' > $null; (Get-Content 'C:\\secpol.cfg') | Select-String 'PasswordComplexity', 'RelaxMinimumPasswordLengthLimits', 'ClearTextPassword','LockoutDuration','LockoutBadCount','ResetLockoutCount'"
    result = subprocess.run(["powershell", command], shell=True, capture_output=True)
    output = result.stdout.decode("utf-8").strip()
    for line in output.split('\n'):
        if "PasswordComplexity" in line:
            try:
                password_complexity = int(line.split("=")[1].strip())
                if password_complexity == 1:
                    check_PassComplexity = True
                else:
                    check_PassComplexity = False
            except:
                check_PassComplexity = False
        if "RelaxMinimumPasswordLengthLimits" in line:
            try:
                password_complexity = int(line.split(",")[1].strip())
                if password_complexity == 1:
                    check_MinPassLength = True
                else:
                    check_MinPassLength = False
            except:
                check_MinPassLength = False
        elif "LockoutBadCount" in line:
            try:
                LockoutBadCount = int(line.split("=")[1].strip())
                if LockoutBadCount == 5:
                    check_BadLock = True
                else:
                    check_BadLock = False
            except:
                check_BadLock = False
    if check_MinPassLength == "N/A":
        check_MinPassLength = False
    if os.path.exists("C:\\secpol.cfg"):
        os.remove("C:\\secpol.cfg")


def check_gpo():
    try:
        check_MinMaxPassAge()
        check_PassComplex_MinPassLength_Badlock()
        if check_MaxPassAge:
            print(green, end="")
            print ("[√] Maximum password age meet requirement (180 Days)")
        else:
            print(light_red, end="")
            print('[×] Maximum password age doesn\'t meet requirement (180 Days)')
        
        if check_PassComplexity:
            print(green, end="")
            print ("[√] Password complexity requirement is Enabled")
        else:
            print(light_red, end="")
            print('[×] Password complexity requirement is Disables')
        
        if check_MinPassLength:
            print(green, end="")
            print ("[√] Relax minimum password length limits Enabled")
        else:
            print(light_red, end="")
            print('[×] Relax minimum password length limits Disabled / Not Configured')

        if check_MinPassAge:
            print(green, end="")
            print ("[√] Relax minimum password length limits Enabled")
        else:
            print(light_red, end="")
            print('[×] Relax minimum password length limits Disabled / Not Configured')

        if check_BadLock:
            print(green, end="")
            print ("[√] Account lockout threshold is meet requirement (5 invalid attempt's)")
        else:
            print(light_red, end="")
            print('[×] Account lockout threshold does\'t meet requirement (5 invalid attempt\'s)')

    except Exception as e:
        if debug_mode is False:
            print('Failure to check GPO Policy\'s')
        else:
            print(e)

# Relax minimum password length limits
def RelaxMinimumPasswordLengthLimits():
    command = command_prefix+'New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" -Name "RelaxMinimumPasswordLengthLimits" -PropertyType DWord -Value 1 -Force'
    result = subprocess.run( ["powershell", command], shell=True, stdout=subprocess.PIPE)
    # output = result.stdout.decode("utf-8")

def others_policy_implementation() :
    # Generate the PowerShell script
    ps_script_content = f"""
    Function Parse-SecPol($CfgFile) {{
        secedit /export /cfg "$CfgFile" | out-null
        $obj = New-Object psobject
        $index = 0
        $contents = Get-Content $CfgFile -raw
        [regex]::Matches($contents,"(?<=\[)(.*)(?=\])") | %{{
            $title = $_
            [regex]::Matches($contents,"(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | %{{

                $section = new-object psobject
                $_.value -split "\\r\\n" | ?{{$_ -ne ""}} | %{{
                    $value = [regex]::Match($_,"(?<=\=).*").value
                    $name = [regex]::Match($_,".*(?=\=)").value
                    $section | add-member -MemberType NoteProperty -Name $name.tostring().trim() -Value $value.tostring().trim() -ErrorAction SilentlyContinue | out-null
                }}
                $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
            }}
            $index += 1
        }}
        return $obj
    }}

    Function Set-SecPol($Object, $CfgFile){{
    $SecPool.psobject.Properties.GetEnumerator() | %{{

            "[$($_.Name)]"
            $_.Value | %{{
                $_.psobject.Properties.GetEnumerator() | %{{

                    "$($_.Name)=$($_.Value)"
                }}
            }}
        }} | out-file $CfgFile -ErrorAction Stop
        secedit /configure /db c:\\windows\\security\\local.sdb /cfg "$CfgFile" /areas SECURITYPOLICY
    }}

    $SecPool = Parse-SecPol -CfgFile C:\\Test.cgf
    $SecPool.'System Access'.PasswordComplexity = 1
    $SecPool.'System Access'.MinimumPasswordLength = 15
    $SecPool.'System Access'.MaximumPasswordAge = 180
    $SecPool.'System Access'.LockoutBadCount = 5

    Set-SecPol -Object $SecPool -CfgFile C:\\Test.cfg
    Remove-Item C:\\Test.cfg
    """

    # Save the PowerShell script to a file
    ps_script_path = 'C:\\netadmin.ps1'
    with open(ps_script_path, 'w') as ps_script_file:
        ps_script_file.write(ps_script_content)

    # Run the PowerShell script using subprocess
    subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-File', ps_script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    
    if os.path.exists(ps_script_path):
        os.remove(ps_script_path)

def update_GPO ():
    # Relax minimum password length limits
    RelaxMinimumPasswordLengthLimits()
    others_policy_implementation()

def create_AdminUser():
    # Generate the PowerShell script
    ps_script_content =f""" 
    $username = "{name}"
    $password = ConvertTo-SecureString "{password}" -AsPlainText -Force
    $fullname = "{fname}"
    $description = "{des}"
    $existingUser = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    if ($existingUser -eq $null) {{
        # Create the user account
        New-LocalUser -Name "$username" -Password $password -FullName "$fullname" -Description "$description" -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires

        # Add the user to the Administrators group
        Add-LocalGroupMember -Group "Administrators" -Member $Username

        Add-LocalGroupMember -Group "Users" -Member $Username
    }}
    """
    # Save the PowerShell script to a file
    ps_script_path = 'C:\\netadmin2.ps1'
    with open(ps_script_path, 'w') as ps_script_file:
        ps_script_file.write(ps_script_content)

    # Run the PowerShell script using subprocess
    subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-File', ps_script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

    if os.path.exists(ps_script_path):
        os.remove(ps_script_path)

def update_users():
    # PowerShell command to get local users excluding specified names
    get_users_command = fr"Get-LocalUser | Where-Object {{ $_.Name -notin @('Guest', 'DefaultAccount', 'Administrator', 'WDAGUtilityAccount', '{name}') }} | ForEach-Object {{ $_.Name }}"

    # Run the PowerShell command and capture the output
    get_users_process = subprocess.Popen(["powershell", "-Command", get_users_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    get_users_output, get_users_error = get_users_process.communicate()

    if get_users_process.returncode == 0:
        # Split the output into a list of user names
        user_names = get_users_output.strip().split('\n')

        # Iterate through each user and update password settings
        for user_name in user_names:
            # PowerShell command to set the password expiration for the current user
            set_password_command = fr'Set-LocalUser -Name "{user_name}" -PasswordNeverExpires $false'
            subprocess.run(["powershell", "-Command", set_password_command])

            # Command to update logonpasswordchg for the current user
            update_logon_command = f'net user "{user_name}" /logonpasswordchg:yes'
            subprocess.run(update_logon_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)


if __name__ == "__main__" :
    os.system("")
    print('PDI - Password Directive Implementation')
    print('Developed by CDAC Kolkata ICTS Team')
    print()
    # for windows
    if sys.platform == "win32":
        print(green, end="")
        print("[√] Windows system detected")
        print(yellow, end='')
        print('[!] Checking for Administrator rights')
        if ctypes.windll.shell32.IsUserAnAdmin() == False:
            print(red, end='')
            print('[×] Administrator rights not found')
            print(light_red)
            print('[*] Please run this script as Administrator')
        else:
            print(green, end='')
            print('[√] Administrator rights found')
            print(yellow, end="")
            print('[!] Checking Group Policy\'s')
            check_gpo()
            print(yellow, end="")
            print('[!] Making Recommended Changes in Group Policy\'s')
            update_GPO()
            try:
                create_AdminUser()
            except:
                print(light_red, end='')
                print('[Optional] Error Code 1')
            try:
                update_users()
            except:
                print(light_red, end='')
                print('[Optional] Error Code 2')
            print(green, end="")
            print('[√] Operations Completed Successfully')
            print(cyan, end='')
            input("\nPress Enter to close the console...")
            print(nocolor)
