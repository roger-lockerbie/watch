#!/usr/bin/env python3
import os
import time
import sys
import logging
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
            logging.error( "Error: COHESITY_PASSWORD environment variable not set")
            sys.exit(1)
        self.connect()

    def connect(self):
        apiauth(vip=self.vip, username=self.username,
                domain=self.domain, password=self.password)

    def get_vm_id_and_snapshots(self, vm_name):
        # Search for VM using data-protect search (v2)
        search_url = f"data-protect/search/protected-objects?searchString={vm_name}&environments=kVMware&snapshotActions=RecoverVMs,RecoverVApps,RecoverVAppTemplates"
        logging.debug(f"API GET request to URL: {search_url}")
        results = api('get', search_url, v=2)
        logging.debug(f"API response: {results}")
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
        logging.debug(f"API GET request to URL: {snapshots_url}")
        logging.debug(f"API response: {snap_response}")
        if not snap_response or 'snapshots' not in snap_response:
            raise Exception(f"No snapshots found for VM '{vm_name}'")

        snapshots = snap_response['snapshots']
        # Sort snapshots by runStartTimeUsecs descending
        snapshots.sort(key=lambda s: s['runStartTimeUsecs'], reverse=True)
        return vm_id, snapshots

    def _walk_vm_folders(self, node, vmFolderId, fullPath=''):
        """Walk VM folders recursively"""
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

    def clone_vm(self, vm_name, selected_snapshot=None, suffix=None):
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
        logging.debug(
            f"API GET request to URL: /entitiesOfType?environmentTypes=kVMware&vmwareEntityTypes=kVCenter&vmwareEntityTypes=kStandaloneHost")
        logging.debug(f"API response: {vCenterList}")
        if not vCenterList:
            raise Exception("No vCenters found")
        vCenter = next((c for c in vCenterList if c['displayName'].lower() == vCenterName.lower()), None)
        if not vCenter:
            raise Exception(f"vCenter {vCenterName} not found")

        vCenterId = vCenter['id']

        # find vCenterSource including VM folders
        vCenterSources = api('get',
                             'protectionSources?environments=kVMware&includeVMFolders=true&excludeTypes=kVirtualMachine')
        logging.debug(
            f"API GET request to URL: protectionSources?environments=kVMware&includeVMFolders=true&excludeTypes=kVirtualMachine")
        logging.debug(f"API response: {vCenterSources}")
        vCenterSource = next(
            (src for src in vCenterSources if src['protectionSource']['name'].lower() == vCenterName.lower()), None)
        if not vCenterSource:
            raise Exception("vCenter source not found in protection sources")

        # Attempt to find resource pool
        resourcePools = api('get', f"/resourcePools?vCenterId={vCenterId}")
        logging.debug(f"API GET request to URL: /resourcePools?vCenterId={vCenterId}")
        logging.debug(f"API response: {resourcePools}")

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
            logging.debug(f"API GET request to URL: /resourcePools?vCenterId={vCenterId}")
            logging.debug(f"API response: {allRPs}")
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
        logging.debug(f"API GET request to URL: /vmwareFolders?resourcePoolId={resourcePoolId}&vCenterId={vCenterId}")
        logging.debug(f"API response: {vmFolders}")
        if not vmFolders or 'vmFolders' not in vmFolders:
            raise Exception("No VM folders found")

        vmFolder = next((f for f in vmFolders['vmFolders'] if f['id'] == folderId), None)
        if not vmFolder:
            raise Exception(f"Folder '{folderName}' not found in vmFolders")

        # Find VM snapshot info using searchvms
        searchResults = api('get', f"/searchvms?entityTypes=kVMware&vmName={vm_name}")
        logging.debug(f"API GET request to URL: /searchvms?entityTypes=kVMware&vmName={vm_name}")
        logging.debug(f"API response: {searchResults}")
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
            logging.debug(
                f"API GET request to URL: /networkEntities?resourcePoolId={resourcePoolId}&vCenterId={vCenterId}")
            logging.debug(f"API response: {networks}")

            if not networks:
                raise Exception("No networks found")
            # Directly iterate over the list since 'networkEntities' key does not exist
            network = next((n for n in networks if n['displayName'].lower() == networkName.lower()), None)
            if not network:
                raise Exception(f"Network '{networkName}' not found")
            restoredObjectsNetworkConfig['networkEntity'] = network

        # Construct cloneTask
        cloneTask = {
            'name': 'Clone-VM-Wazuh',
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
                'prefix': prefix,
                'suffix': suffix if suffix else ''
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

        logging.debug("Constructed Clone Task Payload:")
        logging.debug(json.dumps(cloneTask, indent=4))

        # Make the API call to clone
        response = api('post', '/clone', cloneTask)
        if not response:
            raise Exception("No response from /clone API")

        logging.debug("Constructed Clone Task Payload Response:")
        logging.debug(json.dumps(response, indent=4))

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
            logging.debug("Task Response:")
            logging.debug(json.dumps(task, indent=4))

            # Check if task is a list
            if isinstance(task, list):
                if len(task) == 0:
                    raise Exception("No tasks found in the response")
                task = task[0]  # Access the first (and presumably only) task

            try:
                publicStatus = task['restoreTask']['performRestoreTaskState']['base']['publicStatus']
            except KeyError as e:
                raise Exception(f"Unexpected task structure: missing key {e}")

            logging.info(f"Current Clone Task Status: {publicStatus}")

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
        clone_type_mapping = {'vm': 2}

        # Fetch restore tasks
        clones = api('get',
                     "/restoretasks?restoreTypes=kCloneView&restoreTypes=kCloneApp&restoreTypes=kCloneVMs&restoreTypes=kConvertAndDeployVMs&restoreTypes=kCloneAppView")

        if not isinstance(clones, list) or len(clones) == 0:
            raise Exception("Restore tasks list is empty or improperly formatted")

        active_vm_clones = []
        for clone in clones:
            task = clone.get('restoreTask', {})
            state = task.get('performRestoreTaskState', {}).get('base', {})
            if (not task.get('destroyClonedTaskStateVec') and
                    state.get('type') == clone_type_mapping['vm'] and
                    state.get('publicStatus') == 'kSuccess'):
                active_vm_clones.append(clone)

        # Process active clones
        taskId_to_destroy = None
        for clone in active_vm_clones:
            tId = clone['restoreTask']['performRestoreTaskState']['base']['taskId']
            fulltask = api('get', f"/restoretasks/{tId}")

            # Ensure fulltask is a dictionary
            if isinstance(fulltask, list) and len(fulltask) > 0:
                fulltask = fulltask[0]  # Extract the first item if it's a list
            else:
                raise Exception("Invalid API response: Expected a list with at least one dictionary item")

            if (fulltask.get('restoreTask') and
                    'performRestoreTaskState' in fulltask['restoreTask'] and
                    'restoreInfo' in fulltask['restoreTask']['performRestoreTaskState'] and
                    'restoreEntityVec' in fulltask['restoreTask']['performRestoreTaskState']['restoreInfo']):

                restore_info = fulltask['restoreTask']['performRestoreTaskState']['restoreInfo']
                for vm in restore_info['restoreEntityVec']:
                    restored_vm_name = vm.get('restoredEntity', {}).get('vmwareEntity', {}).get('name', '')
                    if restored_vm_name.lower() == cloned_vm_name.lower():
                        taskId_to_destroy = tId
                        break
            if taskId_to_destroy:
                break

        if not taskId_to_destroy:
            raise Exception(f"Cloned VM {cloned_vm_name} not found among active clones")

        # Destroy the task
        teardown_resp = api('post', f"/destroyclone/{taskId_to_destroy}", data=None)
        if not teardown_resp:
            raise Exception("No response from destroyclone API")

        if wait:
            while True:
                updated_task = api('get', f"/restoretasks/{taskId_to_destroy}")

                if isinstance(updated_task, list) and len(updated_task) > 0:
                    updated_task = updated_task[0]  # Extract first item if list

                destroy_states = updated_task.get('restoreTask', {}).get('destroyClonedTaskStateVec', [])
                if destroy_states and destroy_states[0].get('status') != 1:
                    break
                time.sleep(5)
