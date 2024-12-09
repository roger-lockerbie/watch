# scanner.py

import paramiko
import time
import requests
import json
import winrm


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
            except Exception:
                time.sleep(5)

    def execute_command(self, command):
        stdin, stdout, stderr = self.ssh.exec_command(command)
        output = stdout.read().decode()
        errors = stderr.read().decode()
        return output + errors

    def close(self):
        self.ssh.close()


def execute_malware_scan(ip_address, os_type, ssh_credentials, winrm_credentials, wazuh_config):
    if 'windows' in os_type.lower():
        # Windows VM
        findings = execute_windows_scan(ip_address, winrm_credentials, wazuh_config)
    else:
        # Assume Linux VM
        findings = execute_linux_scan(ip_address, ssh_credentials, wazuh_config)
    return findings


def execute_windows_scan(ip_address, winrm_credentials, wazuh_config):
    # Establish WinRM session
    session = winrm.Session(
        target=ip_address,
        auth=(winrm_credentials['username'], winrm_credentials['password']),
        transport='ntlm',
        server_cert_validation='ignore'
    )

    # Install Wazuh agent
    install_commands = [
        # Download Wazuh agent MSI installer
        'Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.4.0-1.msi -OutFile C:\\wazuh-agent.msi',
        # Install Wazuh agent
        f'msiexec /i C:\\wazuh-agent.msi /quiet /norestart ADDLOCAL="Agent,Tools" MANAGER="{wazuh_config["manager_address"]}" AUTHD_SERVER="{wazuh_config["manager_address"]}" AGENT_NAME="{wazuh_config["agent_name"]}" /L*v C:\\wazuh-install.log',
        # Start Wazuh agent service
        'Start-Service -Name "WazuhAgent"'
    ]

    for cmd in install_commands:
        response = session.run_ps(cmd)
        if response.status_code != 0:
            raise Exception(f"Command failed: {cmd}\n{response.std_err}")

    # Wait for agent to register and send data
    print("Waiting for Wazuh agent to register and send data...")
    agent_id = None
    for _ in range(12):  # Wait up to 2 minutes
        agent_id = get_wazuh_agent_id(wazuh_config, wazuh_config['agent_name'])
        if agent_id:
            break
        time.sleep(10)
    if not agent_id:
        raise Exception("Wazuh agent failed to register")

    # Wait for alerts to be generated
    time.sleep(60)  # Wait additional time for alerts to be processed

    # Retrieve alerts
    alerts = get_wazuh_alerts(wazuh_config, agent_id)
    findings = parse_wazuh_alerts(alerts)

    return findings


def execute_linux_scan(ip_address, ssh_credentials, wazuh_config):
    ssh_client = SSHClient(ip_address, ssh_credentials['username'],
                           ssh_credentials['password'],
                           ssh_credentials['port'])

    # Install and configure Wazuh agent
    install_commands = [
        'curl -so wazuh-agent.sh https://packages.wazuh.com/4.x/installer/scripts/wazuh-agent.sh',
        f'sudo WAZUH_MANAGER="{wazuh_config["manager_address"]}" WAZUH_AGENT_GROUP="default" WAZUH_AGENT_NAME="{wazuh_config["agent_name"]}" WAZUH_REGISTRATION_PASSWORD="{wazuh_config["registration_password"]}" bash wazuh-agent.sh',
        'sudo systemctl restart wazuh-agent'
    ]
    for cmd in install_commands:
        ssh_client.execute_command(cmd)
    ssh_client.close()

    # Wait for agent to register and send data
    print("Waiting for Wazuh agent to register and send data...")
    agent_id = None
    for _ in range(12):  # Wait up to 2 minutes
        agent_id = get_wazuh_agent_id(wazuh_config, wazuh_config['agent_name'])
        if agent_id:
            break
        time.sleep(10)
    if not agent_id:
        raise Exception("Wazuh agent failed to register")

    # Wait for alerts to be generated
    time.sleep(60)  # Wait additional time for alerts to be processed

    # Retrieve alerts
    alerts = get_wazuh_alerts(wazuh_config, agent_id)
    findings = parse_wazuh_alerts(alerts)

    return findings


def get_wazuh_agent_id(wazuh_config, agent_name):
    url = f'https://{wazuh_config["manager_address"]}:55000/agents?name={agent_name}'
    response = requests.get(url, auth=(wazuh_config['api_user'], wazuh_config['api_password']), verify=False)
    agents = response.json().get('data', {}).get('affected_items', [])
    if agents:
        return agents[0]['id']
    else:
        return None


def get_wazuh_alerts(wazuh_config, agent_id):
    url = f'https://{wazuh_config["manager_address"]}:55000/alerts?agent_ids={agent_id}'
    response = requests.get(url, auth=(wazuh_config['api_user'], wazuh_config['api_password']), verify=False)
    alerts = response.json().get('data', {}).get('affected_items', [])
    return alerts


def parse_wazuh_alerts(alerts):
    findings = ''
    for alert in alerts:
        findings += json.dumps(alert, indent=2) + '\n'
    return findings or 'No threats detected'
