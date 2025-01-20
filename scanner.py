# scanner.py

import paramiko
import time
import requests
import json
import winrm
import logging


class SSHClient:
    def __init__(self, ip_address, username, password, port=22):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.port = port
        self.ssh = None
        self.connect()

    def connect(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connected = False
        while not connected:
            try:
                self.ssh.connect(hostname=self.ip_address,
                                 port=self.port,
                                 username=self.username,
                                 password=self.password)
                connected = True
                logging.info(f"SSH connection established to {self.ip_address}")
            except Exception as e:
                logging.error(f"SSH connection failed: {e}")
                time.sleep(5)

    def execute_command(self, command):
        stdin, stdout, stderr = self.ssh.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode()
        errors = stderr.read().decode()
        if exit_status != 0:
            logging.error(f"Error executing command '{command}': {errors}")
        return output, errors, exit_status

    def close(self):
        self.ssh.close()
        logging.info(f"SSH connection to {self.ip_address} closed")


def execute_malware_scan(ip_address, os_type, ssh_credentials, winrm_credentials, wazuh_config, cloned_vm_name):
    if 'windows' in os_type.lower():
        # Windows VM
        execute_windows_scan(ip_address, winrm_credentials, wazuh_config, cloned_vm_name)
    else:
        # Assume Linux VM
        execute_linux_scan(ip_address, ssh_credentials, wazuh_config, cloned_vm_name)


def execute_windows_scan(ip_address, winrm_credentials, wazuh_config, cloned_vm_name, ):
    # Establish WinRM session
    session = winrm.Session(
        target=f"http://{ip_address}:{winrm_credentials['port']}/wsman",
        auth=(winrm_credentials['username'], winrm_credentials['password']),
        transport='basic',
        server_cert_validation='ignore'
    )
    logging.info(f"Established WinRM session to {ip_address}")

    # Install Wazuh agent using the provided commands with dynamic WAZUH_MANAGER
    wazuh_manager = wazuh_config["manager_address"]
    wazuh_agent_version = "4.9.2-1"

    install_commands = [
        # Download Wazuh agent MSI installer
        f"Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-{wazuh_agent_version}.msi -OutFile $env:tmp\\wazuh-agent.msi",
        # Install Wazuh agent
        f"msiexec.exe /i $env:tmp\\wazuh-agent.msi /q WAZUH_MANAGER='{wazuh_manager}' WAZUH_AGENT_NAME='{cloned_vm_name}'",
        # Start Wazuh agent service
        "NET START WazuhSvc"
    ]

    for cmd in install_commands:
        # TODO: The winrm basic auth, + elevating privileges makes this all a bit loose, any remote execution on windows should be tightened significantly for any non-demo/production use of this code
        response = session.run_ps(f'Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted; {cmd}')
        if response.status_code != 0:
            logging.error(f"Command failed: {cmd}\n{response.std_err.decode()}")
        else:
            logging.debug(f"Command succeeded: {cmd}\n{response.std_out.decode()}")

    # Wait for agent to register and send data
    logging.info("Waiting for Wazuh agent to register and send data...")
    agent_id = None
    for _ in range(24):  # Wait up to 4 minutes
        agent_id = get_wazuh_agent_id(wazuh_config, cloned_vm_name)
        if agent_id:
            logging.debug(f"Wazuh agent registered with ID: {agent_id}")
            break
        time.sleep(10)
    if not agent_id:
        raise Exception("Wazuh agent failed to register")


def execute_linux_scan(ip_address, ssh_credentials, wazuh_config, cloned_vm_name, ):
    ssh_client = SSHClient(ip_address, ssh_credentials['username'],
                           ssh_credentials['password'],
                           ssh_credentials['port'])

    # Determine Linux distribution type using /etc/os-release
    distro_type = detect_linux_distro_os_release(ssh_client)
    logging.info(f"Detected Linux distribution type: {distro_type}")

    if distro_type == 'debian':
        install_commands = [
            # Download Wazuh agent DEB package
            'wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb -O /tmp/wazuh-agent.deb',
            # Install Wazuh agent
            f"sudo WAZUH_MANAGER='{wazuh_config['manager_address']}' WAZUH_AGENT_NAME='{cloned_vm_name}' dpkg -i /tmp/wazuh-agent.deb",
            # Reload systemd daemon
            'sudo systemctl daemon-reload',
            # Enable Wazuh agent to start on boot
            'sudo systemctl enable wazuh-agent',
            # Start Wazuh agent
            'sudo systemctl start wazuh-agent'
        ]
    elif distro_type == 'rpm':
        install_commands = [
            # Download Wazuh agent RPM package
            'curl -o /tmp/wazuh-agent-4.9.2-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.2-1.x86_64.rpm',
            # Install Wazuh agent
            f"sudo WAZUH_MANAGER='{wazuh_config['manager_address']}' WAZUH_AGENT_NAME='{cloned_vm_name}' rpm -ihv /tmp/wazuh-agent-4.9.2-1.x86_64.rpm",
            # Reload systemd daemon
            'sudo systemctl daemon-reload',
            # Enable Wazuh agent to start on boot
            'sudo systemctl enable wazuh-agent',
            # Start Wazuh agent
            'sudo systemctl start wazuh-agent'
        ]
    else:
        logging.error("Unsupported Linux distribution")
        ssh_client.close()
        raise Exception("Unsupported Linux distribution")

    # Execute installation commands
    for cmd in install_commands:
        output, errors, exit_status = ssh_client.execute_command(cmd)
        if exit_status == 0:
            logging.debug(f"Executed command on Linux VM: {cmd}\nOutput: {output}")
        else:
            logging.error(f"Failed to execute command on Linux VM: {cmd}\nError: {errors}")

    # Wait for agent to register and send data
    logging.info(f"Waiting for Wazuh agent to register and send data...")
    agent_id = None
    for _ in range(24):  # Wait up to 4 minutes
        agent_id = get_wazuh_agent_id(wazuh_config, cloned_vm_name)
        if agent_id:
            logging.debug(f"Wazuh agent registered with ID: {agent_id}")
            break
        time.sleep(10)
    if not agent_id:
        ssh_client.close()
        raise Exception("Wazuh agent failed to register")

    ssh_client.close()


def detect_linux_distro_os_release(ssh_client):
    try:
        output, errors, exit_status = ssh_client.execute_command('cat /etc/os-release')
        if exit_status != 0:
            logging.error("Failed to read /etc/os-release")
            return 'unknown'

        distro_info = {}
        for line in output.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                distro_info[key.strip()] = value.strip().strip('"')

        distro_id = distro_info.get('ID', '').lower()
        distro_id_like = distro_info.get('ID_LIKE', '').lower()

        # Define known Debian and RPM-based IDs
        debian_ids = ['debian', 'ubuntu', 'linuxmint', 'raspbian']
        rpm_ids = ['rhel', 'centos', 'fedora', 'rocky', 'almalinux', 'opensuse', 'suse']

        if distro_id in debian_ids or any(id_like in distro_id_like for id_like in debian_ids):
            return 'debian'
        elif distro_id in rpm_ids or any(id_like in distro_id_like for id_like in rpm_ids):
            return 'rpm'
        else:
            return 'unknown'
    except Exception as e:
        logging.error(f"Error detecting Linux distro via /etc/os-release: {e}")
        return 'unknown'


def get_wazuh_token(wazuh_config):
    """
    Obtain an authorization token from the Wazuh API using Basic Authentication.
    """
    url = f"https://{wazuh_config['manager_address']}:55000/security/user/authenticate"
    username = wazuh_config.get("api_user", "")
    password = wazuh_config.get("api_password", "")

    if not username or not password:
        logging.error("API user or password not provided in configuration.")
        return None

    try:
        response = requests.post(url, auth=(username, password), verify=False)
        response.raise_for_status()
        token = response.json()['data']['token']
        logging.debug("Successfully obtained Wazuh API token.")
        return token
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred while obtaining token: {http_err} - {response.text}")
    except Exception as e:
        logging.error(f"Error obtaining Wazuh API token: {e}")
    return None


def get_wazuh_agent_id(wazuh_config, agent_name):
    token = get_wazuh_token(wazuh_config)
    headers = {
        'Authorization': f'Bearer {token}'
    }

    url = f'https://{wazuh_config["manager_address"]}:55000/agents?name={agent_name}'
    logging.debug(f"Requesting Wazuh agent ID from URL: {url}")
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        agents = response.json().get('data', {}).get('affected_items', [])
        if agents:
            logging.debug(f"Found Wazuh agent ID: {agents[0]['id']}")
            return agents[0]['id']
        else:
            return None
    except Exception as e:
        logging.error(f"Error fetching Wazuh agent ID: {e}")
        return None


# No longer used as there are no facilities for custom alert bodies back in Defender
def get_wazuh_alerts(wazuh_config, agent_id):
    token = get_wazuh_token(wazuh_config)
    url = f'https://{wazuh_config["manager_address"]}:55000/alerts?agent_ids={agent_id}'
    headers = {
        'Authorization': f'Bearer {token}'
    }

    logging.debug(f"Requesting Wazuh alerts from URL: {url}")
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        alerts = response.json().get('data', {}).get('affected_items', [])
        logging.debug(f"Retrieved {len(alerts)} alerts from Wazuh")
        return alerts
    except Exception as e:
        logging.error(f"Error fetching Wazuh alerts: {e}")
        return []


def parse_wazuh_alerts(alerts):
    findings = ''
    for alert in alerts:
        findings += json.dumps(alert, indent=2) + '\n'
    return findings or 'No threats detected'
