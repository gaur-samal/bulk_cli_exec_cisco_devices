#!/usr/bin/env python3

#### __author__ = "Gaur Samal" ####
#### __email__ = "gsamal@cisco.com" ####

import subprocess
import csv
import sys
import os
import getpass

backup_file_name = "interface_backup.txt"
#username = "sdaadmin"
#password = "cisco@123"
device_ips = []
all_device_ips = set()
failed_device_ips = set()
processed_device_ips = set()
unreachable_device_ips = set()
auth_fail_device_ips = set()
backup_files_created = set()
count = 0
count_device_fail = 0
count_device_unreachable=0
count_device_fail_auth=0
modified_interfaces = 0
failed_interfaces = 0
modified_interfaces_count = {}
failed_interfaces_count = {}

def is_pingable(device_ip):
    try:
        subprocess.run(['ping', '-c', '1', device_ip], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False
    
def check_authentication(device_ip, username, password):
    try:
        subprocess.run([
            "sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
            f"{username}@{device_ip}", "exit"
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def backup_running_config(device_ip, username, password):
    try:
        subprocess.run([
            "sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
            f"{username}@{device_ip}", "term len 0"
        ], check=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        output_bytes = subprocess.check_output([
            "sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
            f"{username}@{device_ip}", f"show running-config"
        ], stderr=subprocess.DEVNULL)
        output = output_bytes.decode('utf-8')
        return True, output_bytes
    except subprocess.CalledProcessError:
        return False, None

def backup_interface_config(device_ip, port_name, username, password):
    global count, count_device_fail
    global count_device_unreachable
    print(f"Connecting to {device_ip}")
    if not is_pingable(device_ip):
        print(f"The device with IP {device_ip} is not reachable.")
        unreachable_device_ips.add(device_ip)
        count_device_unreachable=len(unreachable_device_ips)
        return False, None
    all_device_ips.add(device_ip)
    count = len(all_device_ips)
    if not check_authentication(device_ip, username, password):
        print(f"Authentication failed for device {device_ip}. Please check your username and password.")
        failed_device_ips.add(device_ip)
        #print(f"{failed_device_ips}")
        count_device_fail=len(failed_device_ips)
        #print(f"{count_device_fail}")
        return False, None
    print(f"Backing up interface config for port: {port_name}")

    try:
        subprocess.run([
            "sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
            f"{username}@{device_ip}", "term len 0"
        ], check=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        output_bytes = subprocess.check_output([
            "sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
            f"{username}@{device_ip}", f"show running-config interface {port_name}"
        ], stderr=subprocess.DEVNULL)
        output = output_bytes.decode('utf-8')
        #print(f"{output}")
        if output:
            native_vlan_lines = [line for line in output.split("\n") if 'switchport trunk native vlan' in line]
            if native_vlan_lines:
                vlan_id = ''.join(filter(str.isdigit, native_vlan_lines[0]))
                print(f"Native Vlan is {vlan_id}")
                with open(backup_file_name, "a") as backup_file:
                    backup_file.write(output)
                return True, vlan_id
            else:
                print("Native VLAN line not found in the output.")
                return False, None
        else:
            print(f"Error backing up interface config for port {port_name}")
            return False, None

    except subprocess.CalledProcessError:
        print("Error: SSH connection failed")
        failed_device_ips.add(device_ip)
        #print(f"{failed_device_ips}")
        count_device_fail=len(failed_device_ips)
        #print(f"{count_device_fail}")
        return False, None

    return True

def modify_global_config(device_ip, action, config, username, password):
    global count_device_fail
    command = f"term len 0\nconf t\n"
    if action == "1":
        if config is None:
            return
        command += config + "\n"   
    elif action == "2":
        if config is None:
            return
        # Split the config into lines and prepend "no" to each line
        config_lines = config.split('\n')
        for line in config_lines:
            command += "no " + line + "\n"
    command += "end\n"
    command += "exit\n"
    try:
        process_bytes = subprocess.check_output([
            "sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
            f"{username}@{device_ip}"
        ], input=bytes(command, 'utf-8'), stderr=subprocess.DEVNULL)
        process = process_bytes.decode('utf-8')
        execution_log_name = f"exec_log.txt"
        with open(execution_log_name, 'a') as log:
            log.write("=======================================================\n")
            log.write(f"Execution Logs for {device_ip}\n")
            log.write(process)
            log.write("=======================================================\n")
        if "Invalid input detected" in process:
            print("Command execution failed: wrong CLI")
            failed_device_ips.add(device_ip)
            count_device_fail=len(failed_device_ips)
        else:
            print(f"Global config modified for Device {device_ip}")
    except subprocess.CalledProcessError:
        print(f"Error: An error occurred while modifying global config for port {device_ip}")


def modify_interface_config(device_ip, port_name, action, vlan_id, config, username, password):
    global modified_interfaces, failed_interfaces
    command = f"term len 0\nconf t\ninterface {port_name}\n"
    config = config.replace('vlanid', vlan_id)
    if action == "1":
        if config is None:
            return
        command += config + "\n"   
    elif action == "2":
        if config is None:
            return
        # Split the config into lines and prepend "no" to each line
        config_lines = config.split('\n')
        for line in config_lines:
            command += "no " + line + "\n"
    print(f"Modifying interface config for port {port_name}")
    command += "end\n"
    command += "exit\n"
    try:
        subprocess.run([
            "sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
            f"{username}@{device_ip}"
        ], input=bytes(command, 'utf-8'), stderr=subprocess.DEVNULL, check=True)
        modified_interfaces += 1
        modified_interfaces_count[port_name] = modified_interfaces_count.get(port_name, 0) + 1
        print(f"Interface config modified for port {port_name}")
    except subprocess.CalledProcessError:
        failed_interfaces += 1
        failed_interfaces_count[port_name] = failed_interfaces_count.get(port_name, 0) + 1
        print(f"Error: An error occurred while modifying interface config for port {port_name}")

def process_csv(csv_file, action, config, username, password):
    global failed_interfaces
    vlanid_contains = 'vlanid' in config.lower()
    itt_vlan_id = None
    vlanid_option = None
    if vlanid_contains:
        vlanid_option, itt_vlan_id = get_vlan_id()
    with open(csv_file, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)
        for row in reader:
            device_ip, port_name = row
            print("=======================================================")
            if device_ip not in failed_device_ips and device_ip not in unreachable_device_ips:
                backup_success, vlan_id = backup_interface_config(device_ip, port_name, username, password)
                if backup_success:
                    if vlanid_option:
                        vlan_id = itt_vlan_id
                    modify_interface_config(device_ip, port_name, action, vlan_id, config, username, password)
                else:
                    print(f"Skipping modification of interface config due to backup failure for port {port_name}")
                    failed_interfaces += 1
                    failed_interfaces_count[port_name] = failed_interfaces_count.get(port_name, 0) + 1
            else:
                print(f"This device {device_ip} would not be tried as it failed authentication or SSH connectivity atleast once")

def process_failed_devices(csv_file, action, config, username, password):
    global failed_device_ips
    global failed_interfaces
    vlanid_contains = 'vlanid' in config.lower()
    itt_vlan_id = None
    vlanid_option = None
    if vlanid_contains:
        vlanid_option, itt_vlan_id = get_vlan_id()
    with open(csv_file, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)
        
        for row in reader:
            device_ip, port_name = row
            if (device_ip in failed_device_ips or device_ip in unreachable_device_ips) and device_ip not in processed_device_ips:
                print("=======================================================")
                backup_success, vlan_id = backup_interface_config(device_ip, port_name, username, password)
                if backup_success:
                    if vlanid_option:
                        vlan_id = itt_vlan_id
                    modify_interface_config(device_ip, port_name, action, vlan_id, config, username, password)
                else:
                    print(f"Skipping modification of interface config due to backup failure for port {port_name}")
                    failed_interfaces += 1
                    failed_interfaces_count[port_name] = failed_interfaces_count.get(port_name, 0) + 1
                    processed_device_ips.add(device_ip)
            else:
                if device_ip in all_device_ips:
                    continue
                else:
                    print("=======================================================")
                    print(f"This device {device_ip} would not be tried as it failed authentication or SSH connectivity atleast once")

def proccess_global(csv_file, action, config, username, password):
    global count_device_unreachable, count, count_device_fail_auth
    try:
        with open(csv_file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)
            for row in reader:
                device_ip = row[0]
                print("=======================================================")
                print(f"Processing device with IP: {device_ip}")
                all_device_ips.add(device_ip)
                count = len(all_device_ips)
                if is_pingable(device_ip) and check_authentication(device_ip, username, password):
                    print("Device is reachable and authentication successful. Backing up running config...")
                    if device_ip not in backup_files_created:
                        backup_success, config_output = backup_running_config(device_ip, username, password)
                        if backup_success:
                            backup_files_created.add(device_ip)
                            config_file_name = f"{device_ip}_running_config.txt"
                            with open(config_file_name, 'wb') as config_file:
                                config_file.write(config_output)
                            print(f"Running config backed up successfully for device {device_ip}")
                            run_cnf_bckup_path = os.path.join(os.getcwd(), config_file_name)
                            print("Backup file created at:", run_cnf_bckup_path)
                            backup_files_created.add(device_ip)
                        else:
                            print(f"backup failed for device {device_ip}")
                    else:
                        print(f"Backup file already created for device {device_ip}. Skipping backup.")
                    modify_global_config(device_ip, action, config, username, password)
                elif not is_pingable(device_ip):
                    unreachable_device_ips.add(device_ip)
                    count_device_unreachable=len(unreachable_device_ips)
                    print(f"Skipping device {device_ip} because device is unreachable")
                elif not check_authentication(device_ip, username, password):
                    auth_fail_device_ips.add(device_ip)
                    count_device_fail_auth=len(auth_fail_device_ips)
                    print(f"Skipping device {device_ip} because of CLI_AUTH_ERROR")
                else:
                    print(f"Not able to verify reachability or authentication status of device:{device_ip} ")
    except FileNotFoundError:
        print("CSV file not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def retry_failed_devices(csv_file, action, config, username, password):
    while True:
        retry_option = input("\nDo you want to retry the operation for failed devices? (yes/no): ").lower()
        if retry_option == "yes":
            process_failed_devices(csv_file, action, config, username, password)
            break
        elif retry_option == "no":
            print("Exiting...")
            break 
        else:
            print("Please enter 'yes' or 'no'.")

def get_action():
    while True:
        action = input("\nEnter the action (1 to add config, 2 to remove config): ")
        if action in ['1', '2']:
            return action
        else:
            print("Invalid action. Please enter 1 or 2.")

def get_config(action):
    print("Enter the configuration to", "add" if action == "1" else "remove","(press Enter twice to finish):")
    print("Use 'vlanid' to indicate where the VLAN ID should be inserted.")
    print("Config: ")
    config_lines = []
    while True:
        line = input()
        if line == "":
            break
        config_lines.append(line)
    
    config = '\n'.join(config_lines)
    return config

def get_vlan_id():
    while True:
        option = input("\nDo you want to use the existing VLAN ID from the interface configuration? (yes/no): ").lower()
        if option == 'yes':
            print("Using existing VLANID from interface configuration !!!")
            return False, None
        else:
            while True:
                itt_vlan_id = input("Enter the new VLAN ID: ")
                if itt_vlan_id.isdigit():
                    return True, itt_vlan_id

                else:
                    print("VLAN ID must be a number.")


def csv_has_port_names(csv_file):
    try:
        with open(csv_file, 'r', newline='') as csvfile:
            reader = csv.reader(csvfile)
            headers = next(reader)  # Read the first row (header)
            return "Port name" in headers
    except FileNotFoundError:
        print(f"File '{csv_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error occurred while reading CSV file: {e}")
        return False

def interface_modification(csv_file, action, config, username, password):
    process_csv(csv_file, action, config, username, password)
    retry_failed_devices(csv_file, action, config, username, password)
    print("\n=======================================================")
    print("Summary of device login attempted and ports configured:")
    print("=======================================================\n")
    print(f"Unique device IP addresses login attempted: {count}")
    for ip in all_device_ips:
        print(ip)
    print(f"Modified interfaces: {modified_interfaces}")
    print(f"Failed logins due to reachability: {count_device_unreachable}")
    for ip in unreachable_device_ips:
        print(ip)
    print(f"Failed logins: {count_device_fail}")
    for ip in failed_device_ips:
        print(ip)
    print(f"Failed interfaces: {failed_interfaces}")
    print("\n=======================================================")
    print("Summary of input/backup files and option provided:")
    print("=======================================================\n")
    print(f"CSV file: {csv_file}")
    print(f"Action: {action}")
    backup_file_path = os.path.join(os.getcwd(), backup_file_name)
    print("Backup file created at:", backup_file_path)

def global_modification(csv_file, action, config, username, password):
    proccess_global(csv_file, action, config, username, password)
    print("\n=======================================================")
    print(f"Summary of device login attempted: {count} ")
    print("=======================================================\n")
    for ip in all_device_ips:
        print(ip)
    print("\n=======================================================")
    print(f"Summary of device login failed due to reachability: {count_device_unreachable} ")
    print("=======================================================\n")
    for ip in unreachable_device_ips:
        print(ip)
    print("\n=======================================================")
    print(f"Summary of device login failed due to CLI_AUTH_ERROR:{count_device_fail_auth} ")
    print("=======================================================\n")
    for ip in auth_fail_device_ips:
        print(ip)
    print("=======================================================\n")
    print(f"Summary of device login failed due to wrong CLI: {count_device_fail}")
    print("=======================================================\n")
    for ip in failed_device_ips:
        print(ip)
    print("=======================================================\n")

def confirm_interface_modification():
    while True:
        confirmation = input("Do you want to perform interface level modifications? (yes/no): ").lower()
        if confirmation in ["yes", "no"]:
            return confirmation == "yes"
        else:
            print("Please enter 'yes' or 'no'.")

def confirm_global_modification():
    while True:
        confirmation = input("Do you want to perform global level modifications? (yes/no): ").lower()
        if confirmation in ["yes", "no"]:
            return confirmation == "yes"
        else:
            print("Please enter 'yes' or 'no'.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 dot1x.py <interface_csv_file> OR \n")
        print("Usage: ./dot1x.py <interface_csv_file>")
        sys.exit(1)
    csv_file = sys.argv[1]
    action = get_action()
    print("Enter the device credentials: ( Please note, use the credential which is used by DNAC for managing devices, the credential should be same for all the devices mentioned in csv file)")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    config = get_config(action)
    if csv_has_port_names(csv_file):
        print("Interface names detected in csv file...")
        if confirm_interface_modification():
            interface_modification(csv_file, action, config, username, password)
        else:
            print("Interface level modifications aborted !!")
            sys.exit()
    else:
        print("No port names found in the CSV file. Skipping interface level modifications.")
        if confirm_global_modification():
            global_modification(csv_file, action, config, username, password)
        else:
            print("global config modify aborted !!")
            sys.exit()


if __name__ == "__main__":
    main()