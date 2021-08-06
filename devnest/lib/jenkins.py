#!/usr/bin/env python

# Copyright 2019 Red Hat, Inc.
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

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import requests
import fnmatch

import os

from devnest.lib import exceptions
from devnest.lib import logger
from devnest.lib.node import Node
from jenkinsapi.jenkins import Jenkins
from jenkinsapi.utils.crumb_requester import CrumbRequester
from jenkinsapi.custom_exceptions import JenkinsAPIException
from xml.etree import ElementTree
requests.packages.urllib3.disable_warnings()

LOG = logger.LOG


class JenkinsInstance(object):
    """Representation of the Jenkins Instance.

    Args:
        jenkins_url (:obj:`str`): string value of the Jenkins url
        username (:obj:`str`): username to be used for Jenkins connection
        password (:obj:`str`): password for the Jenkins user
        config_file (:obj:`str`): path to config file
    """
    def __init__(self, jenkins_url=None, username=None, password=None,
                 config_file=None):

        self.jenkins_nodes = []

        config_url = None
        config_username = None
        config_password = None

        # Read config once if one of the args is missing
        if not (jenkins_url and username and password):
            config_url, config_username, config_password = \
                self._get_credentials_from_config(config_file)

        self.jenkins_url = config_url if not jenkins_url else jenkins_url
        self.jenkins_username = config_username if not username else username
        self.jenkins_password = config_password if not password else password

        LOG.info('Using Jenkins URL: %s' % self.jenkins_url)
        LOG.debug('Using username: %s' % self.jenkins_username)
        LOG.debug('Using password: %s' % self.jenkins_password)

        self.jenkins = self._get_jenkins_instance()

    def get_nodes(self, node_regex=None, group=None):
        """Return list of all nodes or subset based on regex.

        Args:
            tester (:obj:`str`): string value of the regex

        Returns:
            (:Node:`list`): Jenkins nodes
        """

        nodes = self.jenkins.nodes

        filtered_nodes = []

        if node_regex:
            filtered_nodes = sorted(fnmatch.filter(nodes.keys(), node_regex))
        else:
            filtered_nodes = nodes.keys()

        nodes_data = nodes._data['computer']

        for node in filtered_nodes:
            cur_node = Node(self.jenkins, node, nodes_data)
            if group is None:
                self.jenkins_nodes.append(cur_node)
            else:
                if cur_node.is_node_in_group([group]):
                    self.jenkins_nodes.append(cur_node)

        return self.jenkins_nodes

    def _get_slave_xmls_from_dir(self, xml_directory):
        slave_xmls = []
        files = os.listdir(xml_directory)

        for filepath in files:
            full_filepath = os.path.join(xml_directory, filepath)
            if full_filepath.lower().endswith(".xml"):
                if not os.path.isfile(full_filepath):
                    LOG.debug('Found XML file which is not valid'
                              ' file: %s' % full_filepath)
                if not os.access(full_filepath, os.R_OK):
                    LOG.debug('XML file not readable: %s' % full_filepath)

                slave_name = None

                try:
                    slave_xml = ElementTree.parse(full_filepath)
                    slave_name = slave_xml.find('name').text
                    if not slave_name or len(slave_name) == 0:
                        LOG.error('Improper XML node config: '
                                  '%s' % full_filepath)
                    else:
                        slave_xmls.append(full_filepath)
                except ElementTree.ParseError:
                    LOG.error('Improper XML node config: '
                              '%s' % full_filepath)
        return slave_xmls

    def create_update_node_from_xml(self, xml_path, offline, directory=False):
        """Create or update node based on passed path to XML file
           or directory that contains XML files

        Raises:
            NodeConfigError: If XML is invalid.

        Args:
            xml_path (:obj:`str`): path to XML file with node details
            offline (:obj:`bool`): whether to offline the node(s) after registering them in Jenkins Master
        """

        slave_xmls = []

        if not directory and not os.path.isfile(xml_path):
            raise exceptions.NodeConfigError("Node config is not regular "
                                             "file: %s" % xml_path)

        if directory and not os.path.isdir(xml_path):
            raise exceptions.NodeConfigError("Node config is not regular "
                                             "directory: %s" % xml_path)

        if not os.access(xml_path, os.R_OK):
            raise exceptions.NodeConfigError("Node config is not readable: "
                                             "%s" % xml_path)

        if directory:
            slave_xmls = self._get_slave_xmls_from_dir(xml_path)
            LOG.info('Found %s valid config files in directory: '
                     '%s' % (len(slave_xmls), xml_path))
        else:
            slave_xmls = [xml_path]

        for s_xml_path in slave_xmls:
            slave_name = None

            try:
                slave_xml = ElementTree.parse(s_xml_path)
                slave_name = slave_xml.find('name').text
            except ElementTree.ParseError:
                raise exceptions.NodeConfigError("Improper XML node config: "
                                                 "%s" % s_xml_path)

            if not slave_name or len(slave_name) == 0:
                raise exceptions.NodeConfigError("Node name not found in config: "
                                                 "%s" % s_xml_path)

            baseurl = '%s/computer/%s' % (self.jenkins.baseurl, slave_name)

            config_str = ElementTree.tostring(slave_xml.getroot())

            LOG.info('Node config: %s using file: %s' % (slave_name, s_xml_path))
            try:
                LOG.info('Trying to apply new config to an existing node (if exists): %s' % slave_name)
                self.jenkins.requester.post_xml_and_confirm_status("%s/config.xml"
                                                                   % baseurl,
                                                                   data=config_str)

            except JenkinsAPIException as e:
                LOG.debug('Exception caught during previous step: %s' % e)
                LOG.info('Creating a new node: %s' % slave_name)
                label = '"devnest_creating_a_new_slave (executed from host: %s)"' % os.uname()[1]
                self.jenkins.create_node(slave_name, labels=label)
                self.jenkins.requester.post_xml_and_confirm_status("%s/config.xml"
                                                                   % baseurl,
                                                                   data=config_str)

            finally:
                if eval(offline):
                    LOG.info("Take the slave offline after it's been registered with Jenkins Master")
                    hostname = os.uname()[1]
                    offline_message = 'devnest_making_slave_offline_after_setup (executed from host: %s)' % hostname
                    self.jenkins.requester.post_and_confirm_status("%s/toggleOffline"
                                                                   % baseurl, data={'offlineMessage': offline_message})

            LOG.info('Node %s updated' % slave_name)

    def get_jenkins_username(self):
        """Return jenkins username used to log in.

        Returns:
            (:obj:`str`): Jenkins username
        """
        return self.jenkins_username

    def _get_jenkins_instance(self):
        """Return jenkins object instance.

        Returns:
            (:obj:`Jenkins`): Jenkins object instance.
        """

        jenkins_obj = Jenkins(self.jenkins_url,
                              requester=CrumbRequester(self.jenkins_username,
                                                       self.jenkins_password,
                                                       baseurl=self.jenkins_url,
                                                       ssl_verify=False))

        LOG.debug('Connected to Jenkins, Version: %s' % jenkins_obj.version)

        return jenkins_obj

    def _get_credentials_from_config(self, config_file):
        """Return url, username and password of the Jenkins instance from
           config file.

        Returns:
            str, str, str: url, username and password from the config file
        """

        url = None
        username = None
        password = None

        config = ConfigParser.RawConfigParser()
        LOG.debug('Reading config from: %s' % config_file)

        cfg = config.read(config_file)

        if len(cfg) == 1:
            url = config.get("jenkins", "url")
            username = config.get("jenkins", "user")
            password = config.get("jenkins", "password")
            return url, username, password

        raise exceptions.ConfigParser("Failed to get username, "
                                      "password or url from config "
                                      "file (%s)." % config_file)
