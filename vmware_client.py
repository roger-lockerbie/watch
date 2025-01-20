# vmware_client.py
#!/usr/bin/env python3
import ssl
import time
import logging
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import os
import sys
from colorama import Fore


class VMwareClient:
    def __init__(self, config):
        self.config = config
        self.host = config['vmware']['host']
        self.username = config['vmware']['username']
        self.password = os.getenv('VMWARE_PASSWORD')
        if not self.password:
            logging.error("Error: VMWARE_PASSWORD environment variable not set")
            sys.exit(1)
        self.port = config['vmware']['port']
        self.service_instance = self.connect()

    def connect(self):
        context = ssl._create_unverified_context()
        try:
            si = SmartConnect(host=self.host,
                              user=self.username,
                              pwd=self.password,
                              port=self.port,
                              sslContext=context)
            if not si:
                raise Exception("Could not connect to VMware vCenter/host")
            logging.info(f"Connected to VMware host: {self.host}")
            return si
        except Exception as e:
            logging.error(f"VMware connection failed: {e}")
            sys.exit(1)

    def disconnect(self):
        Disconnect(self.service_instance)
        logging.info("Disconnected from VMware host")

    def get_vm_by_name(self, vm_name):
        content = self.service_instance.RetrieveContent()
        obj_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        vm_list = obj_view.view
        obj_view.Destroy()
        for vm in vm_list:
            if vm.name == vm_name:
                logging.debug(f"Found VM: {vm_name}")
                return vm
        raise Exception(f"VM {vm_name} not found")

    def wait_for_task(self, task):
        while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
            time.sleep(1)
        if task.info.state == vim.TaskInfo.State.error:
            logging.error(f"Task error: {task.info.error}")
            raise Exception(task.info.error)
        logging.debug(f"Task completed with state: {task.info.state}")

    def power_off_vm(self, vm):
        if vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOff:
            task = vm.PowerOff()
            self.wait_for_task(task)
            logging.info(f"VM {vm.name} powered off")

    def power_on_vm(self, vm):
        if vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
            task = vm.PowerOn()
            self.wait_for_task(task)
            logging.info(f"VM {vm.name} powered on")

    def shutdown_guest(self, vm):
        # Attempts graceful shutdown if tools are available
        if vm.guest.toolsStatus == 'toolsOk' and vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
            try:
                vm.ShutdownGuest()
                logging.info(f"Initiated graceful shutdown for VM: {vm.name}")
                return True
            except Exception as e:
                logging.error(f"Graceful shutdown failed for VM {vm.name}: {e}")
                return False
        return False

    def graceful_shutdown_vm(self, vm, timeout=120):
        if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOff:
            logging.info(f"VM {vm.name} is already powered off.")
            return  # Already off
        logging.info(f"Attempting graceful shutdown of VM: {vm.name}")
        if self.shutdown_guest(vm):
            start = time.time()
            while time.time() - start < timeout:
                vm = self.get_vm_by_name(vm.name)
                if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOff:
                    logging.info(f"VM {vm.name} gracefully shut down.")
                    return
                time.sleep(5)
            logging.warning(f"Graceful shutdown timed out. Forcing power off {vm.name}")
        else:
            logging.warning(f"VMware Tools not available or shutdown failed, forcing power off {vm.name}")

        self.power_off_vm(vm)

    def get_vm_ip(self, vm):
        logging.info(f"Waiting for IP address of VM: {vm.name}")
        while not vm.guest.ipAddress:
            time.sleep(5)
            vm = self.get_vm_by_name(vm.name)
        logging.info(f"VM {vm.name} has IP address: {vm.guest.ipAddress}")
        return vm.guest.ipAddress
