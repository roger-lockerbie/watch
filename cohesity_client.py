#!/usr/bin/env python3
import os
import time
import sys
from pyhesity import api, apiauth, apidrop
from colorama import Fore
import json

class CohesityClient:
    def __init__(self, config):
        self.config = config
        self.vip = config['cohesity']['vip']
        self.username = config['cohesity']['username']
        self.domain = config['cohesity']['domain']
        self.password = os.getenv('COHESITY_PASSWORD')
        if not self.password:
            print(Fore.RED + "Error: COHESITY_PASSWORD environment variable not set")
            sys.exit(1)
        self.connect()

    def connect(self):
        apiauth(vip=self.vip, username=self.username,
                domain=self.domain, password=self.password)

    def get_vm_id_and_snapshots(self, vm_name):
        # Search for VM using data-protect search (v2)
        search_url = f"data-protect/search/protected-objects?searchString={vm_name}&environments=kVMware&snapshotActions=RecoverVMs,RecoverVApps,RecoverVAppTemplates"
        results = api('get', search_url, v=2)
        if not results or 'objects' not in results:
            raise Exception(f"VM '{vm_name}' not found")

        vm_objects = [obj for obj in results['objects'] if obj['name'].lower() == vm_name.lower()]
        if not vm_objects:
            raise Exception(f"VM '{vm_name}' not found in search results")

        vm_obj = vm_objects[0]
        vm_id = vm_obj['id']

        # Get snapshots for the VM
        snapshots_url = f"data-protect/objects/{vm_id}/snapshots"
        snap_response = api('get', snapshots_url, v=2)
        if not snap_response or 'snapshots' not in snap_response:
            raise Exception(f"No snapshots found for VM '{vm_name}'")

        snapshots = snap_response['snapshots']
        # Sort snapshots by runStartTimeUsecs descending
        snapshots.sort(key=lambda s: s['runStartTimeUsecs'], reverse=True)
        return vm_id, snapshots

    def _walk_vm_folders(self, node, vmFolderId, fullPath=''):
        """Walk VM folders recursively, similar to walkVMFolders in PowerShell script."""
        newPath = f"{fullPath}/{node['protectionSource']['name']}"
        psource = node['protectionSource']
        vmWarePS = psource.get('vmWareProtectionSource', {})
        if vmWarePS.get('type') == 'kFolder':
            relParts = newPath.split('vm/', 1)
            relativePath = relParts[1] if len(relParts) > 1 else None
            if relativePath:
                vmFolderId[newPath] = psource['id']
                vmFolderId[relativePath] = psource['id']
                vmFolderId[f"/{relativePath}"] = psource['id']
                if len(newPath) > 1:
                    vmFolderId[newPath[1:]] = psource['id']

        if 'nodes' in node and node['nodes']:
            for subnode in node['nodes']:
                self._walk_vm_folders(subnode, vmFolderId, newPath)

    def clone_vm(self, vm_name, selected_snapshot=None):
        """
        Clone a VM using Cohesity, from a specific snapshot if selected_snapshot is provided.
        selected_snapshot: the snapshot dictionary chosen by the user containing runStartTimeUsecs, etc.
        If selected_snapshot is None, we fall back to latest snapshot logic as before.
        Returns: taskId of the clone task
        """
        vmware_cfg = self.config['vmware']
        vCenterName = vmware_cfg['host']
        dataCenterName = vmware_cfg['datacenterName']
        computeResource = vmware_cfg['computeResource']
        folderName = vmware_cfg['vmFolder']
        networkName = vmware_cfg['networkName']
        viewName = vmware_cfg.get('viewName', 'cloneVMs')
        prefix = vmware_cfg.get('prefix', 'clone-')
        powerOn = vmware_cfg.get('powerOn', True)
        detachNetwork = vmware_cfg.get('detachNetwork', False)
        resourcePoolName = vmware_cfg.get('resourcePoolName', 'Resources')

        # Find vCenter
        vCenterList = api('get',
                          '/entitiesOfType?environmentTypes=kVMware&vmwareEntityTypes=kVCenter&vmwareEntityTypes=kStandaloneHost')
        if not vCenterList:
            raise Exception("No vCenters found")
        vCenter = next((c for c in vCenterList if c['displayName'].lower() == vCenterName.lower()), None)
        if not vCenter:
            raise Exception(f"vCenter {vCenterName} not found")

        vCenterId = vCenter['id']

        # find vCenterSource including VM folders
        vCenterSources = api('get',
                             'protectionSources?environments=kVMware&includeVMFolders=true&excludeTypes=kVirtualMachine')
        vCenterSource = next(
            (src for src in vCenterSources if src['protectionSource']['name'].lower() == vCenterName.lower()), None)
        if not vCenterSource:
            raise Exception("vCenter source not found in protection sources")

        # Attempt to find resource pool
        resourcePools = api('get', f"/resourcePools?vCenterId={vCenterId}")
        print(
            Fore.BLUE + f"Available Resource Pools: {[rp['resourcePool']['vmwareEntity']['name'] for rp in resourcePools]}")

        if not resourcePools:
            raise Exception("No resource pools found")

        # Filter by data center
        filteredRP = [rp for rp in resourcePools if rp['dataCenter']['displayName'].lower() == dataCenterName.lower()]
        if not filteredRP:
            # Fallback: navigate through host folders to find computeResource
            # Find the data center node within protection sources
            dataCenterNodes = [node for node in vCenterSource.get('nodes', []) if
                               node['protectionSource']['name'].lower() == dataCenterName.lower()]
            if not dataCenterNodes:
                raise Exception(f"Datacenter '{dataCenterName}' not found in vCenter sources")

            dataCenterNode = dataCenterNodes[0]

            # Find the compute resource node
            computeResourceNodes = [node for node in dataCenterNode.get('nodes', []) if
                                    node['protectionSource']['name'].lower() == computeResource.lower()]
            if not computeResourceNodes:
                raise Exception(f"Compute Resource '{computeResource}' not found in datacenter '{dataCenterName}'")

            computeResourceNode = computeResourceNodes[0]

            # Find the resource pool under the compute resource
            resourcePoolNodes = [node for node in computeResourceNode.get('nodes', []) if
                                 node['protectionSource'].get('vmWareProtectionSource', {}).get(
                                     'type') == 'kResourcePool']
            if not resourcePoolNodes:
                raise Exception(f"No resource pools found under compute resource '{computeResource}'")

            # Assuming the first resource pool is desired
            resourcePool = resourcePoolNodes[0]
            resourcePoolId = resourcePool['protectionSource']['id']

            # Fetch the complete resource pool details
            allRPs = api('get', f"/resourcePools?vCenterId={vCenterId}")
            if not allRPs:
                raise Exception("No resource pools found after fallback")
            resourcePool = next((rp for rp in allRPs if rp['resourcePool']['id'] == resourcePoolId), None)
            if not resourcePool:
                raise Exception(f"Resource pool with ID '{resourcePoolId}' not found after fallback")
        else:
            # Further filter by compute resource
            compute_resource_lower = computeResource.lower()
            filteredRP = [rp for rp in filteredRP if
                          rp['resourcePool']['vmwareEntity']['name'].lower() == compute_resource_lower]
            if not filteredRP:
                available = [rp['resourcePool']['vmwareEntity']['name'] for rp in resourcePools if
                             rp['dataCenter']['displayName'].lower() == dataCenterName.lower()]
                raise Exception(
                    f"Compute Resource '{computeResource}' not found in data center '{dataCenterName}'. Available compute resources: {available}")

            resourcePool = filteredRP[0]
            resourcePoolId = resourcePool['resourcePool']['id']

        # Select VM folder
        vmFolderId = {}
        self._walk_vm_folders(vCenterSource, vmFolderId, '')
        folderId = vmFolderId.get(folderName)
        if not folderId:
            # Attempt case-insensitive match
            foundId = next((val for k, val in vmFolderId.items() if k.lower() == folderName.lower()), None)
            if not foundId:
                raise Exception(f"Folder '{folderName}' not found")
            folderId = foundId

        vmFolders = api('get', f"/vmwareFolders?resourcePoolId={resourcePoolId}&vCenterId={vCenterId}")
        if not vmFolders or 'vmFolders' not in vmFolders:
            raise Exception("No VM folders found")

        vmFolder = next((f for f in vmFolders['vmFolders'] if f['id'] == folderId), None)
        if not vmFolder:
            raise Exception(f"Folder '{folderName}' not found in vmFolders")

        # Find VM snapshot info using searchvms
        searchResults = api('get', f"/searchvms?entityTypes=kVMware&vmName={vm_name}")
        if not searchResults or 'vms' not in searchResults or not searchResults['vms']:
            raise Exception(f"VM '{vm_name}' not found in Cohesity snapshots")

        matches = [v for v in searchResults['vms'] if v['vmDocument']['objectName'].lower() == vm_name.lower()]
        if not matches:
            raise Exception(f"VM '{vm_name}' not found (exact match)")

        # Sort by latest snapshot
        matches.sort(key=lambda x: x['vmDocument']['versions'][0]['snapshotTimestampUsecs'], reverse=True)
        latestVM = matches[0]
        versions = latestVM['vmDocument']['versions']

        # If a selected_snapshot is provided, find the matching version
        if selected_snapshot:
            target_run_start = selected_snapshot['runStartTimeUsecs']
            # Find version with instanceId.jobStartTimeUsecs == target_run_start
            chosen_version = next(
                (ver for ver in versions if ver['instanceId']['jobStartTimeUsecs'] == target_run_start), None)
            if not chosen_version:
                raise Exception(f"No matching snapshot version found for runStartTimeUsecs={target_run_start}")
            version = chosen_version
        else:
            # Use latest snapshot
            version = versions[0]

        # Handle network/detachNetwork
        restoredObjectsNetworkConfig = {}
        if detachNetwork:
            restoredObjectsNetworkConfig['detachNetwork'] = True
            restoredObjectsNetworkConfig['disableNetwork'] = False
        else:
            if not networkName:
                raise Exception("Network name required")
            networks = api('get', f"/networkEntities?resourcePoolId={resourcePoolId}&vCenterId={vCenterId}")
            print(json.dumps(networks, indent=4))

            if not networks:
                raise Exception("No networks found")
            # Directly iterate over the list since 'networkEntities' key does not exist
            network = next((n for n in networks if n['displayName'].lower() == networkName.lower()), None)
            if not network:
                raise Exception(f"Network '{networkName}' not found")
            restoredObjectsNetworkConfig['networkEntity'] = network

        # Construct cloneTask
        cloneTask = {
            'name': 'Clone-VM',
            'objects': [
                {
                    'jobId': latestVM['vmDocument']['objectId']['jobId'],
                    'jobUid': latestVM['vmDocument']['objectId']['jobUid'],
                    'entity': latestVM['vmDocument']['objectId']['entity'],
                    'jobInstanceId': version['instanceId']['jobInstanceId'],
                    'startTimeUsecs': version['instanceId']['jobStartTimeUsecs']
                }
            ],
            'powerStateConfig': {
                'powerOn': powerOn
            },
            'continueRestoreOnError': False,
            'renameRestoredObjectParam': {
                'prefix': prefix
            },
            'restoreParentSource': {
                'type': vCenter['type'],
                'vmwareEntity': vCenter['vmwareEntity'],
                'id': vCenter['id'],
                'displayName': vCenter['displayName'],
                '_entityKey': 'vmwareEntity',
                '_typeEntity': vCenter['vmwareEntity']
            },
            'resourcePoolEntity': resourcePool['resourcePool'],
            'vmwareParams': {
                'targetVmFolder': vmFolder
            },
            'viewName': viewName,
            'restoredObjectsNetworkConfig': restoredObjectsNetworkConfig
        }

        # Print cloneTask for verification
        print(Fore.CYAN + "Constructed Clone Task Payload:")
        print(json.dumps(cloneTask, indent=4))

        # Make the API call to clone
        response = api('post', '/clone', cloneTask)
        if not response:
            raise Exception("No response from /clone API")

        print(Fore.CYAN + "Constructed Clone Task Payload Response:")
        print(json.dumps(response, indent=4))

        taskId = response['restoreTask']['performRestoreTaskState']['base']['taskId']
        return taskId

    def wait_for_clone_complete(self, task_id):
        """Wait until clone task completes successfully or fails."""
        finishedStates = ['kCanceled', 'kSuccess', 'kFailure', 'kWarning']
        while True:
            task = api('get', f"/restoretasks/{task_id}")
            if not task:
                raise Exception("Unable to retrieve task status from Cohesity")
            # Debug: Print the structure of the task response
            print(Fore.YELLOW + "Task Response:")
            print(json.dumps(task, indent=4))

            publicStatus = task['restoreTask']['performRestoreTaskState']['base']['publicStatus']
            if publicStatus in finishedStates:
                if publicStatus == 'kFailure':
                    errMsg = 'Unknown error'
                    base = task['restoreTask']['performRestoreTaskState']['base']
                    if 'error' in base and 'errorMsg' in base['error']:
                        errMsg = base['error']['errorMsg']
                    raise Exception(f"Clone task failed: {errMsg}")
                return publicStatus
            time.sleep(5)

    def destroy_clone(self, cloned_vm_name, wait=True):
        """
        Destroy the cloned VM using Cohesity's API as per destroyClone.ps1 logic.
        cloned_vm_name: name of the cloned VM to destroy
        wait: wait for completion before returning
        """

        # cloneType='vm' -> type=2
        cloneTypeMapping = {
            'vm': 2
        }

        clones = api('get',
                     "/restoretasks?restoreTypes=kCloneView&restoreTypes=kCloneApp&restoreTypes=kCloneVMs&restoreTypes=kConvertAndDeployVMs&restoreTypes=kCloneAppView")

        if not clones:
            raise Exception("No restore tasks found for destruction")

        active_vm_clones = []
        for clone in clones:
            if (clone['restoreTask'].get('destroyClonedTaskStateVec') is None and
                    clone['restoreTask']['performRestoreTaskState']['base']['type'] == cloneTypeMapping['vm'] and
                    clone['restoreTask']['performRestoreTaskState']['base']['publicStatus'] == 'kSuccess'):
                active_vm_clones.append(clone)

        taskId_to_destroy = None
        for clone in active_vm_clones:
            tId = clone['restoreTask']['performRestoreTaskState']['base']['taskId']
            fulltask = api('get', f"/restoretasks/{tId}")
            if ('restoreInfo' in fulltask['restoreTask']['performRestoreTaskState'] and
                    'restoreEntityVec' in fulltask['restoreTask']['performRestoreTaskState']['restoreInfo']):
                for vm in fulltask['restoreTask']['performRestoreTaskState']['restoreInfo']['restoreEntityVec']:
                    restored_vm_name = vm['restoredEntity']['vmwareEntity']['name']
                    if restored_vm_name.lower() == cloned_vm_name.lower():
                        taskId_to_destroy = tId
                        break
            if taskId_to_destroy:
                break

        if not taskId_to_destroy:
            raise Exception(f"Cloned VM {cloned_vm_name} not found among active clones")

        teardownResp = api('post', f"destroyclone/{taskId_to_destroy}", data=None)
        if not teardownResp:
            raise Exception("No response from destroyclone API")

        if wait:
            while True:
                updatedTask = api('get', f"/restoretasks/{taskId_to_destroy}")
                if 'destroyClonedTaskStateVec' in updatedTask['restoreTask'] and len(
                        updatedTask['restoreTask']['destroyClonedTaskStateVec']) > 0:
                    status = updatedTask['restoreTask']['destroyClonedTaskStateVec'][0]['status']
                    if status != 1:
                        break
                else:
                    break
                time.sleep(5)

    def create_alert(self, vm_name, findings):
        alert = {
            "alertCategory": "kSecurity",
            "alertSeverity": "kCritical",
            "alertState": "kOpen",
            "alertType": "kSecurityThreatDetected",
            "description": f"Malware detected on VM {vm_name}:\n{findings}"
        }
        response = api('post', 'alerts', alert)
        if 'id' in response:
            print(Fore.GREEN + f"Alert created with ID: {response['id']}")
        else:
            raise Exception("Failed to create alert")
