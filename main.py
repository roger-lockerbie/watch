# WATCH - Wazuh Analysis for Threats and Cybersecurity on Hypervisors
#
# Demo code for integrating IBM Storage Defender Data Protect with Wazuh to clone VM's inject a Wazuh agent
# and running threat detection (IoC's, YARA etc) and reporting results back to Defebder
# scanner.py
# main.py
# main.py

import yaml
import time
import getpass
import os
from cohesity_client import CohesityClient
from vmware_client import VMwareClient
from scanner import execute_malware_scan
from colorama import init, Fore, Style


def main():
    init(autoreset=True)

    # Load configuration
    print(Fore.CYAN + "Loading configuration...")
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)

    passwords_provided(config)

    cohesity_client = CohesityClient(config)
    vmware_client = VMwareClient(config)


    vm_name = input(Fore.CYAN + "Enter the name of the VM to scan: ")

    # Get available snapshots
    try:
        vm_id, snapshots = cohesity_client.get_vm_id_and_snapshots(vm_name)
    except Exception as e:
        print(Fore.RED + str(e))
        return

    # Display snapshots
    print(Fore.GREEN + f"\nAvailable snapshots for VM '{vm_name}':")
    for idx, snap in enumerate(snapshots):
        snap_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(snap['runStartTimeUsecs'] / 1e6))
        print(Fore.MAGENTA + "[{}] {}".format(idx + 1, snap_time_str))

    # Get user selection
    snapshot_selection = input(Fore.CYAN + "\nEnter the number corresponding to the snapshot to use: ")
    try:
        snapshot_index = int(snapshot_selection) - 1
        if snapshot_index < 0 or snapshot_index >= len(snapshots):
            raise ValueError
    except ValueError:
        print(Fore.RED + "Invalid selection.")
        return

    selected_snapshot = snapshots[snapshot_index]
    snapshot_time_usecs = selected_snapshot['runStartTimeUsecs']

    # Convert snapshot time for naming (not strictly needed now)
    timestamp = time.strftime('%Y%m%d%H%M%S', time.localtime(snapshot_time_usecs / 1e6))

    # Gracefully shut down production VM
    print(Fore.YELLOW + f"Gracefully shutting down production VM: {vm_name}")
    prod_vm = vmware_client.get_vm_by_name(vm_name)
    vmware_client.graceful_shutdown_vm(prod_vm)

    # Clone the VM from the chosen snapshot
    print(Fore.GREEN + "Cloning VM from Cohesity snapshot...")
    clone_task_id = cohesity_client.clone_vm(vm_name, selected_snapshot=selected_snapshot)

    print(Fore.GREEN + "Waiting for clone to complete...")
    status = cohesity_client.wait_for_clone_complete(clone_task_id)
    if status not in ['kSuccess', 'kWarning']:
        print(Fore.RED + f"Clone task ended with status: {status}")
        # Power on production VM again before exit
        vmware_client.power_on_vm(prod_vm)
        return

    # After clone completes, the cloned VM should be named prefix+vm_name
    cloned_vm_name = config['vmware']['prefix'] + vm_name
    cloned_vm = vmware_client.get_vm_by_name(cloned_vm_name)
    vmware_client.power_on_vm(cloned_vm)
    ip_address = vmware_client.get_vm_ip(cloned_vm)
    print(Fore.GREEN + f"Cloned VM IP Address: {ip_address}")

    # Determine OS type
    os_type = cloned_vm.guest.guestFamily
    print(Fore.GREEN + f"Detected OS Type: {os_type}")

    # Execute Malware Scan
    print(Fore.YELLOW + "Starting malware scan...")
    ssh_credentials = config['ssh']
    winrm_credentials = config['winrm']
    wazuh_config = config['wazuh']

  ###  findings = execute_malware_scan(ip_address, os_type, ssh_credentials, winrm_credentials, wazuh_config)
  ###  print(Fore.GREEN + "Scan complete.")

    # Process Scan Results
 ###   if findings != 'No threats detected':
 ###       print(Fore.RED + "Threats detected! Sending alert to Cohesity.")
 ###       cohesity_client.create_alert(cloned_vm_name, findings)
 ###   else:
 ###       print(Fore.GREEN + "No threats detected.")
#debug
    time.sleep(5)
    # Cleanup: Tear down the clone
    print(Fore.YELLOW + f"Tearing down cloned VM: {cloned_vm_name}")
    cohesity_client.destroy_clone(clone_task_id)

    print(Fore.YELLOW + f"Restarting production VM: {vm_name}")
    vmware_client.power_on_vm(prod_vm)

    vmware_client.disconnect()
    print(Fore.GREEN + "Process completed." + Style.RESET_ALL)


def passwords_provided(config):
    # Read passwords from environment variables
    # Cohesity
    config['cohesity']['password'] = os.getenv('COHESITY_PASSWORD')
    # VMware
    config['vmware']['password'] = os.getenv('VMWARE_PASSWORD')
    # SSH
    config['ssh']['password'] = os.getenv('SSH_PASSWORD')
    # WinRM
    config['winrm']['password'] = os.getenv('WINRM_PASSWORD')
    # Wazuh
    config['wazuh']['api_password'] = os.getenv('WAZUH_API_PASSWORD')
    config['wazuh']['registration_password'] = os.getenv('WAZUH_REGISTRATION_PASSWORD')

    # Check that all passwords are provided
    if not config['cohesity']['password']:
        config['cohesity']['password'] = getpass.getpass('Enter Cohesity password: ')
    if not config['vmware']['password']:
        config['vmware']['password'] = getpass.getpass('Enter VMware password: ')
    if not config['ssh']['password']:
        config['ssh']['password'] = getpass.getpass('Enter SSH password: ')
    if not config['winrm']['password']:
        config['winrm']['password'] = getpass.getpass('Enter WinRM password: ')
    if not config['wazuh']['api_password']:
        config['wazuh']['api_password'] = getpass.getpass('Enter Wazuh API password: ')
    if not config['wazuh']['registration_password']:
        config['wazuh']['registration_password'] = getpass.getpass('Enter Wazuh registration password: ')
    # Ensure that all passwords are now provided
    missing_credentials = []
    if not config['cohesity']['password']:
        missing_credentials.append('Cohesity password')
    if not config['vmware']['password']:
        missing_credentials.append('VMware password')
    if not config['ssh']['password']:
        missing_credentials.append('SSH password')
    if not config['winrm']['password']:
        missing_credentials.append('WinRM password')
    if not config['wazuh']['api_password']:
        missing_credentials.append('Wazuh API password')
    if not config['wazuh']['registration_password']:
        missing_credentials.append('Wazuh registration password')
    if missing_credentials:
        print(Fore.RED + "Error: The following passwords were not provided:")
        for cred in missing_credentials:
            print(Fore.RED + f" - {cred}")
        raise Exception("Please provide these passwords and try again.")


if __name__ == "__main__":
    main()
