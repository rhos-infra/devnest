#!/usr/bin/env python

# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from datetime import timedelta
from jenkinsapi.custom_exceptions import PostRequired
from devnest.lib.exceptions import NodeDataError
from devnest.lib.exceptions import NodeReservationError
from devnest.lib import logger
from six.moves.urllib.parse import quote as urlquote
from xml.etree import ElementTree

import json
import re
import socket
import time

LOG = logger.LOG

# Tags used to get node data from node description
START_TAG = '<#{'
END_TAG = '}#>'


class NodeStatus(object):
    """Enumeration for the Node status."""
    (UNKNOWN, ONLINE, OFFLINE, TEMPORARILY_OFFLINE,
     RESERVED, REPROVISION, REPROVISION_PENDING, JOB_RUNNING) = range(8)


class NodeData(object):
    """Helper Class used to store values needed to properly parse response
       from Jenkins server containing data for the nodes. This information
       is available in the structure Jenkins.nodes._data['computer']
    """

    DISPLAY_NAME = "displayName"

    # Layout of the data: MONITOR_DATA:SWAP_SPACE_MONITOR:TOTAL_PHYSICAL_MEMORY
    MONITOR_DATA = "monitorData"
    SWAP_SPACE_MONITOR = "hudson.node_monitors.SwapSpaceMonitor"
    TOTAL_PHYSICAL_MEMORY = "totalPhysicalMemory"

    OFFLINE_REASON = "offlineCauseReason"


class NodeReservation(object):
    """Class to represent data stored in Jenkins master in the Node
       Offline Reason section. We store reservation data in that place
       because it's quickly available from the Jenkins API. More detailed
       node data requires subsequent queries which are slow.

    Args:
        reservation_starttime (:obj:`float`): EPOCH time when reserved
        reservation_endtime (:obj:`float`): EPOCH time when reservation expires
        reservation_owner (:obj:`str`): user who reserved node
        reprovision_pending (:obj:`bool`): if reprovision is pending
    """
    def __init__(self, reservation_starttime, reservation_endtime,
                 reservation_owner, reprovision_pending=False):
        self.reservation_starttime = reservation_starttime
        self.reservation_endtime = reservation_endtime
        self.reservation_owner = reservation_owner
        self.reserve_str = time.strftime("%Y/%m/%d, %H:%M:%S",
                                         time.localtime(reservation_endtime))
        self.reprovision_pending = reprovision_pending

    def get_reprovision_pending(self):
        """Return information if reprovision of node is pending (ongoing).

        Returns:
            (:obj:`bool`): True if reprovision is pending False otherwise
        """
        return self.reprovision_pending

    def set_reprovision_pending(self, reprovision_pending):
        """Set information if reprovision of node is pending (ongoing).

        Args:
            (:obj:`bool`): True if reprovision is pending False otherwise
        """
        self.reprovision_pending = reprovision_pending

    def get_reservation_endtime(self):
        """Return user friendly string of time when reservation expires.
           This data is stored in Jenkins Master together with EPOCH time
           so users can see when reservation expires using Jenkins UI.

        Returns:
            (:obj:`str`): Reservation end time in user friendly format.
        """
        return self.reserve_str

    def get_reservation_endtime_epoch(self):
        """Return EPOCH time when reservation expires.

        Returns:
            (:obj:`float`): EPOCH time when reservation expires.
        """
        return self.reservation_endtime

    def get_reservation_owner(self):
        """Return owner who reserved node.

        Returns:
            (:obj:`float`): owner who reserved node.
        """
        return self.reservation_owner

    def clear_reservation_endtime(self):
        """Sets the reservation endtime to starttime
        """
        self.reserve_str = "TO_REPROVISION"
        self.reservation_endtime = self.reservation_starttime

    def __str__(self):
        reservation = {'reservation': {
            'reservedUntil': self.reserve_str,
            'startTime': self.reservation_starttime,
            'endTime': self.reservation_endtime,
            'owner': self.reservation_owner,
            'reprovisionPending': self.reprovision_pending
        }}

        return json.dumps(reservation)


class NodeDetails(object):
    """Class to represent data stored in Jenkins master in the Node
       Description section. We store that data in description place
       because it's quickly available from the Jenkins API. More detailed
       node data requires subsequent queries which are slow.

    Args:
        node_labels (:obj:`list`): Labels associated with the node
        physical_ram (:obj:`str`): Physical RAM memory
        capabilities(:obj:`str`): Capabilities to be set in JSON str
    """
    def __init__(self, node_labels, physical_ram=None, capabilities={}):
        self.node_labels = node_labels
        self.physical_ram = physical_ram
        self.capabilities = capabilities

    def get_node_labels(self):
        """Return node labels

        Returns:
            (:obj:`list`): Labels associated with the node.
        """
        return self.node_labels

    def get_node_labels_from_capabilities(self):
        """Return node labels calculated from capabilities

        Format:
            cap_CAPABILITYNAME_VALUE

            Example:
              cap_cpus_4
              cap_ram_190GB

        Returns:
            (:obj:`list`): Labels from capabilities.
        """
        cap_labels = []
        for value in self.get_capabilities().keys():
            cap_labels.append("cap_%s_%s" % (value,
                              self.get_capabilities().get(value)))

        return cap_labels

    def get_physical_ram(self):
        """Return physical ram

        Returns:
            (:obj:`str`): Physical RAM memory.
        """
        return self.physical_ram

    def add_node_labels(self, node_labels=[]):
        """add node labels to already existing ones

        Args:
            node_labels(:obj:`list`): labels to be added
        """
        self.node_labels = list(set(self.node_labels + node_labels))

    def remove_node_labels(self, node_labels=[]):
        """remove node labels if they exists

        Args:
            node_labels(:obj:`list`): labels to be removed
        """
        self.node_labels = [label for label in self.node_labels
                            if label not in node_labels]

    def remove_all_node_labels(self):
        """remove all node labels
        """
        self.node_labels = []

    def get_capability(self, capability_name):
        """Return node capabilities

        Args:
            capability_name(:obj:`str`): capability name

        Returns:
            (:obj:`str`): string representation of capability value or ""
        """

        capability_value = self.get_capabilities().get(capability_name)

        return capability_value or ""

    def get_capabilities(self):
        """Return node capabilities

        Returns:
            (:obj:`str`): JSON str with node capabilities or empty dictionary
        """
        if not isinstance(self.capabilities, dict):
            self.capabilities = {}

        return self.capabilities

    def set_capabilities(self, capabilities):
        """Set node capabilities

        Args:
            capabilities(:obj:`str`): Capabilities to be set in JSON str
        """

        self.capabilities = capabilities

    def __str__(self):
        json_str = START_TAG

        node_details = {
            'reservation': {
                'labels': self.node_labels
            }
        }
        if (len(self.get_capabilities()) > 0):
            node_details.update({'capabilities': self.get_capabilities()})
        json_str += json.dumps(node_details)
        json_str += END_TAG
        return json_str


class Node(object):
    """Representation of the Jenkins node.

    Raises:
        NodeDataError: If there was error while getting data for the node.

    Args:
        jenkins_instance(:obj:`Jenkins`): Jenkins instance
        node_name (:obj:`str`): Node name
        jenkins_instance(:obj:`Jenkins.nodes._data['computer']`): Node
    """
    def __init__(self, jenkins_instance, node_name, nodes_data):
        self.node_name = node_name
        self.node_data = None

        self.jenkins = jenkins_instance
        self.node = None

        for node_dt in nodes_data:
            if node_dt.get(NodeData.DISPLAY_NAME) == node_name:
                self.node_data = node_dt
                break

        if not self.node_data:
            raise NodeDataError("Failed to get data for node %s" % node_name)

        self.reservation_info = self._get_reservation_info()
        self.node_status = self.get_node_status()
        description = self.node_data.get('description')
        self.node_details = self._node_details_from_description(description)
        self._config = None

    def reserve(self, reservation_time, owner=None, reprovision_pending=False,
                force_reserve=False):
        """Marks node as reserved for requested time.
        Reserved node is put temporarily offline, is it can finish currently
        running task and metadata is stored in the offline reason section
        containing information about reservation. See NodeReservation class.

        Raises:
            NodeReservationError: If there was error while making attempt to
                                  reserve node.

        Args:
            reservation_time (:obj:`int`): Requested reservation time in Hours
            owner (:obj:`int`): Override automatically discovered username
            reprovision_pending (:obj:`bool`): If reprovision pending state
            force_reserve (:obj:`bool`): Reserve even if node is running CI job
        """
        LOG.info('Attempting to reserve node: %s for %s Hours' % (
                 self.get_name(), reservation_time))

        if self.node_status != NodeStatus.ONLINE and not force_reserve:
            raise NodeReservationError("Node %s is not Online and "
                                       "can't be reserved." % self.get_name())

        if self.node_status != NodeStatus.JOB_RUNNING and \
           self.node_status != NodeStatus.ONLINE and force_reserve:
            raise NodeReservationError("--force can be used only when node %s"
                                       " is running CI job." % self.get_name())

        if self.reservation_info is not None:
            raise NodeReservationError("Node %s is not released properly and "
                                       "can't be reserved. Use -l option to "
                                       "get more info." % self.get_name())

        if not owner:
            owner = self.jenkins.requester.username
        start_time = time.time()
        offset_time = timedelta(hours=reservation_time).total_seconds()
        end_time = start_time + offset_time

        self.reservation_info = NodeReservation(start_time, end_time, owner,
                                                reprovision_pending)

        jenkins_node = self.jenkins.get_node(self.get_name())

        slave_xml = ElementTree.fromstring(jenkins_node.get_config())

        ip_address = None

        for slave_element in slave_xml.findall('launcher'):
            ip_address = slave_element.find('host').text

        jenkins_node.toggle_temporarily_offline(str(self.reservation_info))

        LOG.info('Node: %s reserved for %s Hours by %s' % (
                 self.get_name(), reservation_time, owner))

        username = self.node_details.get_capability('username')
        password = self.node_details.get_capability('password')

        if username and len(username) > 0 and password and len(password) > 0:
            LOG.info('Node access (pass: "%s"): $ ssh %s@%s'
                     % (password, username, ip_address))
        else:
            LOG.info('Node ssh: %s' % (ip_address))

        LOG.info('Cancel reservation with "devnest release'
                 ' %s"' % (self.get_name()))
        return dict(
            host=self.get_name(),
            username=username,
            password=password,
            ip_address=ip_address,
        )

    def extend_reservation(self, extend_reservation_time, force_username=False):
        """Extend reservation for additional time.

        Raises:
            NodeReservationError: If there was error while making attempt to
                                  extend reservation.

        Args:
            extend_reservation_time (:obj:`int`): Requested reservation time in Hours
            force_username (:obj:`bool`): Extend even if not owner of reservation
        """

        reservation_owner = self.get_reservation_owner()

        if not self.node_data.get('temporarilyOffline') or \
           reservation_owner == "":
            raise NodeReservationError("Node %s is currently not reserved nor "
                                       "queued to be reserved. Reservation "
                                       "can not be extended. Node state: %s" %
                                       (self.get_name(),
                                        self.get_node_status_str()))

        if not force_username:
            jenkins_user = self.jenkins.requester.username
            if reservation_owner != jenkins_user:
                raise NodeReservationError("Node %s is currently reserved by "
                                           "%s. Use --force flag to extend "
                                           "reservation for different user." %
                                           (self.get_name(), reservation_owner))

        LOG.info('Extending node reservation: %s by %s Hours' % (
                 self.get_name(), extend_reservation_time))

        res = self.reservation_info

        # If reservation is pending reprovisioning, but it's not yet
        # being reprovisioned, extend time from now, because
        # reservation was already expired.
        if self.get_node_status() == NodeStatus.REPROVISION:
            start_time = time.time()
            offset_time = timedelta(hours=extend_reservation_time).total_seconds()
            new_end_time = start_time + offset_time
        else:
            offset_time = timedelta(hours=extend_reservation_time).total_seconds()
            new_end_time = res.reservation_endtime + offset_time

        new_reservation = NodeReservation(res.reservation_starttime,
                                          new_end_time, res.reservation_owner,
                                          False)
        self._set_offline_cause(str(new_reservation))
        LOG.info('Node %s is reserved until: %s' % (self.get_name(),
                 new_reservation.get_reservation_endtime()))

    def set_reprovision_pending(self):
        """Sets node as in reprovision pending state"""
        LOG.info('Marking %s as reprovision pending' % self.get_name())
        if not self.reservation_info and self.node_status == NodeStatus.ONLINE:
            LOG.info('Node %s is online, reserving...' % self.get_name())
            self.reserve(0, owner='devnest_reprovisioner',
                         reprovision_pending=True)
        else:
            self.reservation_info.clear_reservation_endtime()
            self.reservation_info.set_reprovision_pending(True)
            self._set_offline_cause(str(self.reservation_info))

    def clear_reservation(self, bring_online=False):
        """Clears reservation for particular node and optionally
        brings it online."""
        if self.node_status not in (NodeStatus.RESERVED, NodeStatus.REPROVISION):
            pass

        if bring_online and self.node_status != NodeStatus.ONLINE:
            node = self._get_node_instance()

            if not node.is_temporarily_offline():
                node.toggle_temporarily_offline("Devnest bringing node back...")

            node.set_online()
            LOG.info('Node %s is no longer reserved' % self.get_name())
        elif bring_online:
            LOG.info('Node %s was already online' % self.get_name())
        elif self.node_status == NodeStatus.RESERVED:
            LOG.info('Marking %s to be reprovisioned' % self.get_name())
            self.reservation_info.clear_reservation_endtime()
            self._set_offline_cause(str(self.reservation_info))
            LOG.info('Node %s is no longer reserved and will be '
                     'reprovisioned' % self.get_name())
        else:
            LOG.info('Node %s is not reserved' % self.get_name())

    def get_node_url(self):
        """Get node URL
        Returns:
            (:obj:`str`): node url
        """
        return self.jenkins.get_nodes_url() + "/" + self.get_name()

    def get_reservation_endtime(self):
        if self.reservation_info:
            reservation_endtime = self._get_reservation_endtime_epoch()
            current_time = time.time()
            if reservation_endtime and reservation_endtime <= current_time:
                return "Outdated, reprovision pending..."
            return self.reservation_info.get_reservation_endtime()
        return ""

    def get_reservation_owner(self):
        if self.reservation_info:
            return self.reservation_info.get_reservation_owner()
        return ""

    def get_node_status_str(self):
        """Return node status.

        Returns:
            (:obj:`NodeStatus`): node status
        """
        if self.node_status == NodeStatus.OFFLINE:
            return "disabled"

        if self.node_status == NodeStatus.TEMPORARILY_OFFLINE:
            return "temporarily offline"

        if self.node_status == NodeStatus.ONLINE:
            return "free"

        if self.node_status == NodeStatus.RESERVED:
            return "reserved"

        if self.node_status == NodeStatus.REPROVISION:
            return "pending"

        if self.node_status == NodeStatus.REPROVISION_PENDING:
            return "reprovisioning"

        if self.node_status == NodeStatus.JOB_RUNNING:
            return "CI job running"

        return "Unknown"

    def get_node_ip_address(self):
        """Return IP address of the node.

        Returns:
            (:obj:`str`): node IP address or empty string
        """
        ip_address = None
        description = self.node_data.get('description')
        ip_address = re.findall(r'[0-9]+(?:\.[0-9]+){3}', description)

        if ip_address and len(ip_address) == 1:
            try:
                socket.inet_aton(ip_address[0])
                ip_address = ip_address[0]
            except socket.error:
                ip_address = ""

        return ip_address

    def get_name(self):
        """Return name of the node.

        Returns:
            (:obj:`str`): node name
        """
        return self.node_name

    def is_node_in_group(self, groups):
        """Check if node belongs to one of the group passed. The check
           happens by finding if group is within the node labels from
           description.

        Args:
            inventory_file (:obj:`list`): groups to which node may belong

        Returns:
            (:obj:`bool`): True if node is in the group, False otherwise
        """
        if not self.node_details:
            return False

        node_groups = self.node_details.get_node_labels()
        for group in groups:
            if group in node_groups:
                return True

        return False

    def get_node_status(self):
        """Returns status of the node object.

        Returns:
            (:obj:`NodeStatus`): Calculated status of the node (Online,
                                 Reserved, Offline, etc...)
        """

        # First check if the node is unused
        if not self.node_data.get('idle'):
            return NodeStatus.JOB_RUNNING

        # If it's not offline it may be temporarily offline
        temp_offline = self.node_data.get('temporarilyOffline')
        offline = self.node_data.get('offline')
        reservation_endtime = self._get_reservation_endtime_epoch()
        current_time = time.time()
        reprovision_pending = False
        if self.reservation_info:
            reprovision_pending \
                = self.reservation_info.get_reprovision_pending()

        if reservation_endtime and reservation_endtime > current_time:
            return NodeStatus.RESERVED

        if reservation_endtime and reservation_endtime <= current_time:
            if not reprovision_pending:
                return NodeStatus.REPROVISION
            return NodeStatus.REPROVISION_PENDING

        if offline:
            return NodeStatus.OFFLINE

        if temp_offline:
            return NodeStatus.TEMPORARILY_OFFLINE

        return NodeStatus.ONLINE

    def update_capabilities(self, capabilities):
        """Update node capabilities

        Args:
            capabilities (:obj:`str`): json string representing capabilities
        """
        try:
            capabilities = capabilities.replace("'", '"')
            json_data = json.loads(capabilities)
            node_details = self.node_details
            node_details.set_capabilities(json_data)
            self._update_node_with_node_details(node_details)
        except ValueError:
            raise NodeDataError("Improper json format for capabilities:"
                                " '%s'" % capabilities)

    def _node_details_from_description(self, description):
        """Parse description and return Node details.

        Returns:
            (:obj:`float`): EPOCH time when reservation expires.
        """
        node_labels = []
        capabilities = None

        try:
            details_start = description.index(START_TAG) + len(START_TAG)
            details_end = description.index(END_TAG, details_start)
            details_json = description[details_start:details_end]
            json_data = json.loads(details_json.replace("'", '"'))
            node_labels = json_data.get('reservation').get('labels')
            capabilities = json_data.get('capabilities')
        except (ValueError, AttributeError):
            LOG.debug('Could not read details data for '
                      'node: %s' % self.get_name())

        physical_ram = self._get_total_physical_mem()

        return NodeDetails(node_labels, physical_ram, capabilities)

    def _get_reservation_endtime_epoch(self):
        """Return EPOCH time when reservation expires.

        Returns:
            (:obj:`float`): EPOCH time when reservation expires.
        """
        if self.reservation_info:
            return self.reservation_info.get_reservation_endtime_epoch()
        return None

    def _get_reservation_info(self):
        """Return object with metadata about reservation.

        Returns:
            (:obj:`NodeReservation`): Reservation metadata or None if
                                      no reservation metadata was found.
        """
        offline_cause_reason = self.node_data.get(NodeData.OFFLINE_REASON)

        reservation_info = None

        if offline_cause_reason:
            try:
                json_data = json.loads(offline_cause_reason)
                res_data = json_data.get('reservation')
                if res_data:
                    owner = str(res_data.get('owner'))
                    start_time = float(res_data.get('startTime'))
                    end_time = float(res_data.get('endTime'))
                    reprovision_pending = bool(res_data.get(
                                               'reprovisionPending'))

                    reservation_info = NodeReservation(start_time, end_time,
                                                       owner,
                                                       reprovision_pending)

            except (TypeError, ValueError):
                LOG.debug('Could not read reservation data for node %s,'
                          ' invalid json format: %s' % (self.get_name(),
                                                        offline_cause_reason))

        return reservation_info

    def _get_total_physical_mem(self):
        """Get total physical memory - human readable string with suffix.

        Args:
            inventory_file (:obj:`int`): memory in bytes

        Returns:
            (:obj:`str`): memory with suffix or empty string if 0
        """
        memory_size = 0

        try:
            monitor_dt = self.node_data.get(NodeData.MONITOR_DATA)
            swap_space_dt = monitor_dt.get(NodeData.SWAP_SPACE_MONITOR)
            memory_size = swap_space_dt.get(NodeData.TOTAL_PHYSICAL_MEMORY)
        except Exception:
            pass

        if memory_size == 0:
            return ""

        for value in ['bytes', 'KB', 'MB', 'GB']:
            if memory_size < 1024.0:
                return "%3.1f%s" % (memory_size, value)
            memory_size /= 1024.0
        return "%3.1f%s" % (memory_size, 'TB')

    def clear_all_groups(self):
        """Clears all the groups from node
        """
        LOG.info('Removing groups from node: %s' % self.get_name())
        description_str = self._get_config_data('description')
        node_details = self._node_details_from_description(description_str)
        node_details.remove_all_node_labels()

        self._update_node_with_node_details(node_details)
        LOG.info('Groups removed from node: %s' % self.get_name())

    def update_with_groups(self, groups=[]):
        """Update node with the provided gruops. This removes any other
        groups from the node.

        Args:
            groups(:obj:`list`): groups to be associated with the node
        """
        LOG.info('Updating groups "%s" for node: %s' % (",".join(groups),
                                                        self.get_name()))
        description_str = self._get_config_data('description')
        node_details = self._node_details_from_description(description_str)
        node_details.remove_all_node_labels()
        node_details.add_node_labels(groups)

        self._update_node_with_node_details(node_details)
        LOG.info('Updated, node %s is in groups: %s' % (self.get_name(),
                 ",".join(node_details.get_node_labels())))

    def add_groups(self, groups=[]):
        """Add node to groups.

        Args:
            groups(:obj:`list`): groups to be added
        """
        LOG.info('Adding groups "%s" to node: %s' % (",".join(groups),
                                                     self.get_name()))
        description_str = self._get_config_data('description')
        node_details = self._node_details_from_description(description_str)
        node_details.add_node_labels(groups)

        self._update_node_with_node_details(node_details)
        LOG.info('Added, node %s is in groups: %s' % (self.get_name(),
                 ",".join(node_details.get_node_labels())))

    def remove_groups(self, groups=[]):
        """Remove groups from node if they exists.

        Args:
            groups(:obj:`list`): groups to be removed
        """
        description_str = self._get_config_data('description')
        node_details = self._node_details_from_description(description_str)
        node_details.remove_node_labels(groups)

        self._update_node_with_node_details(node_details)

    def get_node_config_xml(self):
        """Get node config data

        Returns:
            (:obj:`string`): config in XML format
        """
        self._set_node_config()
        return self._config

    def disconnect(self, msg='disconnected_by_devnest'):
        """Disconnect the node from Jenkins master
        """
        node_url = self.get_node_url()

        LOG.info('Disconnecting %s from Jenkins master' % self.node_name)

        self.jenkins.requester.post_and_confirm_status("%s/doDisconnect?offlineMessage=%s" % (node_url, msg), data={})

    def _update_node_with_node_details(self, node_details):
        """Update node with NodeDetails data.

        Args:
            node_details(:obj:`NodeDetails`): update node with NodeDetails
        """
        description_str = self._get_config_data('description')
        LOG.debug('Node %s, description: %s' % (self.get_name(),
                                                description_str))
        # Remove extra metadata from the description
        if START_TAG in description_str and END_TAG in description_str:
            description_regex = START_TAG + ".*?" + END_TAG
            description_str = re.sub(description_regex, '', description_str)

        self._set_node_config()
        config_str = self._config

        # Set json data for the description
        config_str = \
            self._set_config_data(config_str, 'description',
                                  "%s %s" % (description_str, node_details))

        node_labels = node_details.get_node_labels()
        node_labels_cap = node_details.get_node_labels_from_capabilities()
        node_labels = list(set(node_labels + node_labels_cap))

        config_str = \
            self._set_config_data(config_str, 'label',
                                  ' '.join(node_labels))

        self._upload_config_data(config_str)

    def _set_node_config(self):
        """Returns XML with node config

        Returns:
            (:obj:`string`): XML with node config
        """
        node = self._get_node_instance()
        if self._config is None:
            node.load_config()
        self._config = node._config

    def _set_config_data(self, config_str, tag, data_str):
        """Set node config data

        Args:
            config_str (:obj:`string`): string representing config
            tag (:obj:`string`): tag to which data_str will be set
            data_str (:obj:`string`): data_str to be set for node

        Returns:
            (:obj:`string`): Modified node config data string
        """
        slave_xml = ElementTree.fromstring(config_str)

        slave_xml.find(tag).text = data_str

        config_str = ElementTree.tostring(slave_xml)

        LOG.debug('Node %s, config changed %s: %s' % (self.get_name(),
                                                      tag, data_str))
        return config_str

    def _upload_config_data(self, config_str):
        node = self._get_node_instance()
        node.upload_config(config_str)
        LOG.debug('Node %s, config uploaded' % self.get_name())

    def _get_config_data(self, tag):
        """Get node config data

        Args:
            tag (:obj:`string`): tag from which data will be returned

        Returns:
            (:obj:`string`): data from the tag
        """
        self._set_node_config()
        slave_xml = ElementTree.fromstring(self._config)
        return slave_xml.find(tag).text

    def _set_offline_cause(self, message):
        """Set offline cause for the node. Jenkinsapi does not have this
           functionality so we have to write one.

        Args:
            message (:obj:`string`): message to be used as offline reason
        """
        node = self._get_node_instance()
        url = node.baseurl + \
            "/changeOfflineCause?offlineMessage=" + urlquote(message)
        try:
            self.jenkins.requester.get_and_confirm_status(url)
        except PostRequired:
            self.jenkins.requester.post_and_confirm_status(url, data={})

    def _get_node_instance(self):
        """Returns instance of the Jenkins Node Class

        Returns:
            (:obj:`jenkinsapi.Node`): instance of the Jenkins Node class
        """
        node = None
        if self.node is None:
            node = self.jenkins.get_node(self.node_name)
            self.node = node
        else:
            node = self.node
        return node
