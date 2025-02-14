import os
import psutil
import shutil
import time
import winreg as reg

# Scareware signatures (Example of malicious executables)
MALICIOUS_FILES = [
    "scareware.exe",
    "fake_alert.exe",
    "malicious_installer.exe",
    "popup_adware.exe"
]

# List of common scareware processes or system alterations (example)
SUSPICIOUS_PROCESSES = [
    "scareware_process",   # Example process names
    "fake_alert_process",
    "popup_adware_process"
]

# Check if any malicious processes are running
def check_for_scareware_processes():
    print("Checking for running malicious processes...")
    for process in psutil.process_iter(['pid', 'name']):
        try:
            if process.info['name'].lower() in SUSPICIOUS_PROCESSES:
                print(f"Malicious process found: {process.info['name']} (PID: {process.info['pid']})")
                terminate_process(process.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

# Terminate the suspicious process
def terminate_process(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()
        print(f"Terminated process with PID: {pid}")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        print(f"Failed to terminate process with PID: {pid}")

# Scan the system for malicious files (in common directories)
def scan_for_malicious_files():
    print("Scanning for malicious files...")
    directories_to_scan = [
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\Users\\Public\\Downloads",
        "C:\\Users\\<User>\\AppData"  # Change <User> to your system username
    ]
    
    for directory in directories_to_scan:
        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.lower() in MALICIOUS_FILES:
                        file_path = os.path.join(root, file)
                        print(f"Found malicious file: {file_path}")
                        remove_file(file_path)

# Remove a file from the system
def remove_file(file_path):
    try:
        os.remove(file_path)
        print(f"Removed malicious file: {file_path}")
    except Exception as e:
        print(f"Error removing file {file_path}: {str(e)}")

# Check for registry modifications (startup items, scheduled tasks, etc.)
def check_for_scareware_registry_entries():
    print("Checking for registry modifications related to scareware...")
    registry_keys = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    ]
    
    for key in registry_keys:
        try:
            reg_key = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_READ)
            for i in range(0, reg.QueryInfoKey(reg_key)[1]):
                name, value, _ = reg.EnumValue(reg_key, i)
                if any(malicious in value.lower() for malicious in MALICIOUS_FILES):
                    print(f"Found malicious registry entry: {name} -> {value}")
                    remove_registry_entry(reg_key, name)
        except FileNotFoundError:
            continue

# Remove a registry entry
def remove_registry_entry(reg_key, name):
    try:
        reg.DeleteValue(reg_key, name)
        print(f"Removed registry entry: {name}")
    except Exception as e:
        print(f"Error removing registry entry {name}: {str(e)}")

# Main function to diagnose and clean scareware
def main():
    print("Starting scareware detection and cleanup...")
    
    # Step 1: Check for malicious processes
    check_for_scareware_processes()
    
    # Step 2: Scan system directories for malicious files
    scan_for_malicious_files()
    
    # Step 3: Check registry for suspicious entries
    check_for_scareware_registry_entries()
    
    print("Scareware diagnostic and cleanup complete!")

if __name__ == "__main__":
    main()
