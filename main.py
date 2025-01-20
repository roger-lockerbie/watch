#!/usr/bin/env python3
# main.py

import argparse
import getpass
import logging
import os
import sys
import time

import yaml
from colorama import init, Fore

from cohesity_client import CohesityClient
from scanner import execute_malware_scan
from vmware_client import VMwareClient


def setup_logging(config, debug=False):
    """Setup logging based on config and debug flag."""
    log_dir = config.get('logging', {}).get('log_dir', '.')
    log_file = config.get('logging', {}).get('log_file', 'watch.log')
    log_path = os.path.join(log_dir, log_file)

    log_level = logging.DEBUG if debug else logging.INFO

    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)

    # Configure logging
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler(sys.stdout)  # Ensures that logs are also printed to the console
        ]
    )

    # Suppress paramiko and other noisy logs unless in debug mode
    if not debug:
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
    else:
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
        logging.getLogger("requests").setLevel(logging.DEBUG)


def main():
    init(autoreset=True)

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="WATCH - Wazuh Analysis for Threats and Cybersecurity on Hypervisors"
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging.'
    )
    args = parser.parse_args()

    # Load configuration
    try:
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(Fore.RED + "Error: config.yaml not found.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(Fore.RED + f"Error parsing config.yaml: {e}")
        sys.exit(1)

    # Setup logging
    setup_logging(config, debug=args.debug)
    logging.info("Loading configuration...")

    # Handle passwords
    try:
        passwords_provided(config)
    except Exception as e:
        logging.error(e)
        sys.exit(1)

    # Initialize clients
    try:
        cohesity_client = CohesityClient(config)
        vmware_client = VMwareClient(config)
    except Exception as e:
        logging.error(f"Initialization Error: {e}")
        sys.exit(1)

    # Get VM name from user
    vm_name = input(Fore.CYAN + "Enter the name of the VM to scan: ")
    logging.info(f"Selected VM for scanning: {vm_name}")

    # Get available snapshots
    try:
        vm_id, snapshots = cohesity_client.get_vm_id_and_snapshots(vm_name)
    except Exception as e:
        logging.error(str(e))
        return

    # Display snapshots
    logging.info(f"Available snapshots for VM '{vm_name}':")
    for idx, snap in enumerate(snapshots):
        snap_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(snap['runStartTimeUsecs'] / 1e6))
        logging.info(Fore.MAGENTA + f"[{idx + 1}] {snap_time_str}")

    # Get user selection
    snapshot_selection = input(Fore.CYAN + "\nEnter the number corresponding to the snapshot to use: ")
    try:
        snapshot_index = int(snapshot_selection) - 1
        if snapshot_index < 0 or snapshot_index >= len(snapshots):
            raise ValueError
    except ValueError:
        logging.error("Invalid snapshot selection.")
        return

    selected_snapshot = snapshots[snapshot_index]
    snapshot_time_usecs = selected_snapshot['runStartTimeUsecs']
    logging.debug(f"Selected snapshot timestamp: {snapshot_time_usecs}")

    # Convert snapshot time for naming
    timestamp = time.strftime('%Y%m%d', time.localtime(snapshot_time_usecs / 1e6))

    # Gracefully shut down production VM
    logging.info(f"Gracefully shutting down production VM: {vm_name}")
    try:
        prod_vm = vmware_client.get_vm_by_name(vm_name)
        vmware_client.graceful_shutdown_vm(prod_vm)
    except Exception as e:
        logging.error(f"Error shutting down VM: {e}")
        return

    # Clone the VM from the chosen snapshot
    logging.info("Cloning VM from Cohesity snapshot...")
    try:
        clone_task_id = cohesity_client.clone_vm(vm_name, selected_snapshot=selected_snapshot, suffix=timestamp)
    except Exception as e:
        logging.error(f"Error initiating clone: {e}")
        # Attempt to power on the production VM again before exiting
        try:
            vmware_client.power_on_vm(prod_vm)
            logging.info(f"Restarted production VM: {vm_name}")
        except Exception as ex:
            logging.error(f"Error restarting production VM: {ex}")
        return

    # Wait for clone completion
    logging.info("Waiting for clone to complete...")
    try:
        status = cohesity_client.wait_for_clone_complete(clone_task_id)
        logging.info(f"Clone task completed with status: {status}")
    except Exception as e:
        logging.error(f"Clone task failed: {e}")
        # Attempt to power on the production VM again before exiting
        try:
            vmware_client.power_on_vm(prod_vm)
            logging.info(f"Restarted production VM: {vm_name}")
        except Exception as ex:
            logging.error(f"Error restarting production VM: {ex}")
        return

    if status not in ['kSuccess', 'kWarning']:
        logging.error(f"Clone task ended with status: {status}")
        # Power on production VM again before exit
        try:
            vmware_client.power_on_vm(prod_vm)
            logging.info(f"Restarted production VM: {vm_name}")
        except Exception as ex:
            logging.error(f"Error restarting production VM: {ex}")
        return

    # After clone completes, the cloned VM should be named prefix+vm_name+timestamp
    cloned_vm_name = config['vmware']['prefix'] + vm_name + timestamp
    try:
        cloned_vm = vmware_client.get_vm_by_name(cloned_vm_name)
        # already done by clone task
        #    vmware_client.power_on_vm(cloned_vm)
        ip_address = vmware_client.get_vm_ip(cloned_vm)
        logging.info(f"Cloned VM IP Address: {ip_address}")
    except Exception as e:
        logging.error(f"Error handling cloned VM: {e}")
        # Attempt to power on the production VM again before exiting
        try:
            vmware_client.power_on_vm(prod_vm)
            logging.info(f"Restarted production VM: {vm_name}")
        except Exception as ex:
            logging.error(f"Error restarting production VM: {ex}")
        return

    # Determine OS type
    try:
        for attempt in range(10):
            os_type = cloned_vm.guest.guestFamily
            if os_type is not None:
                logging.info(f"Detected OS Type: {os_type}")
                break
            logging.warning(f"VMware Tools not ready yet, retrying... (Attempt {attempt + 1}/10)")
            time.sleep(6)
        else:
            logging.error("Failed to detect OS type after multiple attempts.")
            raise Exception("Unable to detect OS type: VMware Tools may not be running.")
    except Exception as e:
        logging.error(f"Error determining OS type: {e}")
        # Attempt to power on the production VM again before exiting
        try:
            vmware_client.power_on_vm(prod_vm)
            logging.info(f"Restarted production VM: {vm_name}")
        except Exception as ex:
            logging.error(f"Error restarting production VM: {ex}")
        return

    # Execute Malware Scan
    logging.info("Starting malware scan...")
    ssh_credentials = config['ssh']
    winrm_credentials = config['winrm']
    wazuh_config = config['wazuh']

    try:
        findings = execute_malware_scan(ip_address, os_type, ssh_credentials, winrm_credentials, wazuh_config,
                                        cloned_vm_name)
        logging.info("Scan complete.")
    except Exception as e:
        logging.error(f"Error during malware scan: {e}")
        logging.info("Scan Failed.")

    # Cleanup: Tear down the clone
    user_input = input(
        Fore.CYAN + f"Do you wish to tear down the cloned VM '{cloned_vm_name}'? (Y/N): ").strip().lower()
    if user_input == 'y':
        logging.info(f"Tearing down cloned VM: {cloned_vm_name}")
        try:
            cohesity_client.destroy_clone(cloned_vm_name)
        except Exception as e:
            logging.error(f"Error destroying clone: {e}")

        # Restart production VM
        logging.info(f"Restarting production VM: {vm_name}")
        try:
            vmware_client.power_on_vm(prod_vm)
        except Exception as e:
            logging.error(f"Error restarting production VM: {e}")
    else:
        logging.info(
            "Clone tear down skipped, you will be responsible for tearing down in UI when you are ready. Production VM will not be restarted.")

    vmware_client.disconnect()
    logging.info("Process completed.")


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
        logging.error("The following passwords were not provided:")
        for cred in missing_credentials:
            logging.error(f" - {cred}")
        raise Exception("Please provide these passwords and try again.")


if __name__ == "__main__":
    main()
