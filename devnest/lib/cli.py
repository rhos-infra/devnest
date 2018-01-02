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

from devnest.lib import logger

from devnest.lib.jenkins import JenkinsInstance
from requests.exceptions import ConnectionError
from devnest.lib.exceptions import CommandError
from devnest.lib.exceptions import NodeCliException
from devnest.lib.exceptions import NodeReservationError
from devnest.lib.node import NodeStatus

import argparse
import datetime
import logging
from terminaltables import AsciiTable
import sys
import os

LOG = logger.LOG

DEFAULT_CONFIG = [
    os.path.expanduser("~") + "/.config/jenkins_jobs/jenkins_jobs.ini",
    "/etc/jenkins_jobs/jenkins_jobs.ini"
]

LIST_FORMATS = ['csv', 'table']


class Action(object):
    """Enumeration for the CLI Action."""
    (LIST, RELEASE, RESERVE, MANAGE, CAPABILITIES) = range(5)


class JenkinsNodeShell(object):

    def get_base_parser(self):
        formatter = argparse.ArgumentDefaultsHelpFormatter
        parser = argparse.ArgumentParser(prog='devnest',
                                         description='CLI to reserve, release'
                                         ' or manage hardware in DevNest.',
                                         formatter_class=formatter,
                                         add_help=False)

        parser.add_argument('-?', '-h', '--help',
                            action='help',
                            help='Show this help message and exit')

        parser.add_argument('-v', '--verbose',
                            action='store_true',
                            help='increase output verbosity')

        parser.add_argument('--conf',
                            help='Configuration file. [jenkins] section '
                                 'is the same as in jenkins-job-builder.')

        parser.add_argument('--url',
                            help='The Jenkins URL to use.'
                                 'This overrides the url specified in the '
                                 'configuration file')

        parser.add_argument('-u', '--user',
                            help='The Jenkins user to use for authentication.'
                                  'This overrides the user specified in the '
                                  'configuration file')

        parser.add_argument('-p', '--password',
                            help='Password or API token to use for '
                                 'authenticating towards Jenkins. This '
                                 'overrides the password specified in the '
                                 'configuration file.')

        subparsers = parser.add_subparsers(title='node action subcommands',
                                           help='possible actions')

        # Node parser is used by multiple subparsers
        node_parser = argparse.ArgumentParser(add_help=False)
        node_parser.add_argument('node',
                                 nargs='?',
                                 metavar='"NODE_REGEXP"',
                                 default=None,
                                 help='Node regex to perform action on, '
                                      'use quotes around')

        # Nest name (nest is a group of hardware by nest name)
        nest_parser = argparse.ArgumentParser(add_help=False)
        nest_group = nest_parser.add_mutually_exclusive_group(required=True)
        nest_group.add_argument('-g', '--group',
                                default="'shared'",
                                help='Node group from which list will happen')
        # Hide this option from standard user, it's for all nests
        nest_group.add_argument('-a', '--all',
                                action='store_true',
                                help=argparse.SUPPRESS)

        list_parser = subparsers.add_parser('list',
                                            parents=[node_parser, nest_parser],
                                            formatter_class=formatter,
                                            help='list available node(s)')
        list_parser.set_defaults(action=Action.LIST)

        release_parser = subparsers.add_parser('release',
                                               parents=[node_parser],
                                               formatter_class=formatter,
                                               help='release node(s)')
        release_parser.set_defaults(action=Action.RELEASE)

        reserve_parser = subparsers.add_parser('reserve',
                                               parents=[node_parser,
                                                        nest_parser],
                                               formatter_class=formatter,
                                               help='reserve node')
        reserve_parser.set_defaults(action=Action.RESERVE)

        # List
        list_parser.add_argument('-f', '--format',
                                 default='table',
                                 help='Parseable output, options: csv,table')

        # Reserve
        reserve_parser.add_argument('-t', '--time',
                                    type=int,
                                    default=3,
                                    help='Time in hours for the box to be reserved')

        # Owner that reserved node.
        reserve_parser.add_argument('-o', '--owner',
                                    help=argparse.SUPPRESS)

        # Release - force releases server reserved by different user
        release_parser.add_argument('-f', '--force',
                                    action='store_true',
                                    help=argparse.SUPPRESS)

        # Release - brings node online after reservation is released
        release_parser.add_argument('-o', '--online',
                                    action='store_true',
                                    help=argparse.SUPPRESS)

        # Group parser
        group_parser = argparse.ArgumentParser(add_help=False)
        manage_group = group_parser.add_mutually_exclusive_group(required=True)

        manage_group.add_argument('-l', '--list',
                                  action='store_true',
                                  help="list all groups")
        manage_group.add_argument('-g', '--get',
                                  action='store_true',
                                  help="get groups for node")
        manage_group.add_argument('-u', '--update',
                                  help="update node with comma separated "
                                       "group(s)")
        manage_group.add_argument('-a', '--add',
                                  help="add comma separated group(s) "
                                       "to node if not already")
        manage_group.add_argument('-r', '--remove',
                                  help="remove comma separated group(s) "
                                       "from node if they exists")
        manage_group.add_argument('-c', '--clear',
                                  action='store_true',
                                  help="clear all groups from node")
        # Manage section
        manage_parser = subparsers.add_parser('manage-groups',
                                              parents=[node_parser,
                                                       group_parser],
                                              formatter_class=formatter,
                                              help='manage node groups, use '
                                                   'with caution')
        manage_parser.set_defaults(action=Action.MANAGE)

        # Capabilities parser
        capabilities_parser = argparse.ArgumentParser(add_help=False)
        capabilities_group = \
            capabilities_parser.add_mutually_exclusive_group(required=True)
        capabilities_group.add_argument('-l', '--list',
                                        action='store_true',
                                        help="list capabilities")
        capabilities_group.add_argument('-u', '--update',
                                        help="update node(s) capabilities"
                                             "passed as json dictionary")

        capabilities = subparsers.add_parser('capabilities',
                                             parents=[node_parser,
                                                      capabilities_parser],
                                             formatter_class=formatter,
                                             help='manage node capabilities')
        capabilities.set_defaults(action=Action.CAPABILITIES)
        return parser

    def _get_default_config(self):
        """Return path to the default jenkins config if exists

        Returns:
            (:obj:`str`): config path
        """
        config_path = None
        for path in DEFAULT_CONFIG:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                config_path = path
                break

        return config_path

    def parse_args(self, argv):
        parser = self.get_base_parser()
        args = parser.parse_args(argv)

        parseable_output = False
        if "parseable" in args and args.parseable is True:
            parseable_output = True

        if args.verbose and not parseable_output:
            LOG.setLevel(level=logging.DEBUG)
            LOG.debug('devnest running in debug mode')

        if parseable_output:
            # On machine parseable output disable info logging
            # to not spoil the output
            LOG.setLevel(level=logging.ERROR)

        if not args.conf and not (args.user and args.password and args.url):
            if self._get_default_config():
                args.conf = self._get_default_config()
            else:
                raise CommandError("You must provide either username, password"
                                   " and url or path to configuration file"
                                   " via --conf option.")

        return args

    def main(self, argv):
        parser_args = self.parse_args(argv)
        LOG.debug("%s" % parser_args)

        LOG.info("Connecting to Jenkins...")
        jenkins_obj = JenkinsInstance(parser_args.url, parser_args.user,
                                      parser_args.password,
                                      parser_args.conf)

        # List nodes
        if parser_args.action is Action.LIST:
            group = parser_args.group
            if parser_args.all:
                group = None

            jenkins_nodes = jenkins_obj.get_nodes(node_regex=parser_args.node,
                                                  group=group)

            if parser_args.format is None or parser_args.format == 'table':
                print(_get_node_table_str(jenkins_nodes))
            elif parser_args.format in LIST_FORMATS:
                print(_get_node_parseable_str(jenkins_nodes))
            else:
                err_msg = "List format '%s' is not supported." \
                          % parser_args.format
                raise CommandError(err_msg)

        # Reserve node
        if parser_args.action is Action.RESERVE:
            reservation_time = parser_args.time
            group = parser_args.group
            if parser_args.all:
                group = None
            jenkins_nodes = jenkins_obj.get_nodes(node_regex=parser_args.node,
                                                  group=group)
            if len(jenkins_nodes) != 1:
                err_msg = "Found %s nodes maching your reservation" \
                          % len(jenkins_nodes)
                if len(jenkins_nodes) > 1:
                    err_msg += ". Please specify only one.\n" \
                               + _get_node_table_str(jenkins_nodes)
                raise CommandError(err_msg)

            reserve_node = jenkins_nodes[0]
            if reserve_node.get_node_status() != NodeStatus.ONLINE:
                err_msg = "Node %s is not online and can not be reserved. " \
                    % reserve_node.get_name()
                err_msg += "Node status: %s. Try release the node." \
                    % reserve_node.get_node_status_str()
                raise CommandError(err_msg)

            reservation_owner = parser_args.owner
            reserve_node.reserve(reservation_time, owner=reservation_owner)

        # Clear Reservation
        if parser_args.action is Action.RELEASE:
            jenkins_nodes = jenkins_obj.get_nodes(node_regex=parser_args.node,
                                                  group=None)
            if len(jenkins_nodes) != 1:
                err_msg = "Found %s nodes maching your node pattern" \
                          % len(jenkins_nodes)
                if len(jenkins_nodes) > 1:
                    err_msg += ". Please specify only one.\n" \
                               + _get_node_table_str(jenkins_nodes)
                raise CommandError(err_msg)

            reserve_node = jenkins_nodes[0]

            reserve_user = reserve_node.get_reservation_owner()
            jenkins_user = jenkins_obj.get_jenkins_username()
            if reserve_user != jenkins_user and not parser_args.force:
                err_msg = "Node %s is reserved by %s and can not " \
                          "be released unless used with --force flag." \
                    % (reserve_node.get_name(), reserve_user)
                raise CommandError(err_msg)

            reserve_node.clear_reservation(bring_online=parser_args.online)

        # Group manage
        if parser_args.action is Action.MANAGE:
            jenkins_nodes = jenkins_obj.get_nodes(node_regex=parser_args.node,
                                                  group=None)
            # group-manage -l
            if parser_args.list:
                all_groups = []
                for node in jenkins_nodes:
                    all_groups += node.node_details.get_node_labels()
                print("Available groups: " + ",".join(list(set(all_groups))))

            # group-manage -g
            elif parser_args.get:
                print(_get_node_groups_table_str(jenkins_nodes))

            else:
                if len(jenkins_nodes) != 1:
                    err_msg = "Found %s nodes maching your node pattern" \
                              % len(jenkins_nodes)
                    if len(jenkins_nodes) > 1:
                        err_msg += ". Please specify only one.\n" \
                                   + _get_node_table_str(jenkins_nodes)
                    raise CommandError(err_msg)

                node = jenkins_nodes[0]

                if parser_args.clear:
                    node.clear_all_groups()
                elif parser_args.update:
                    groups = parser_args.update.split(",")
                    node.update_with_groups(groups)
                elif parser_args.add:
                    groups = parser_args.add.split(",")
                    node.add_groups(groups)
                elif parser_args.remove:
                    groups = parser_args.remove.split(",")
                    node.remove_groups(groups)

        # Capabilities
        if parser_args.action is Action.CAPABILITIES:
            jenkins_nodes = jenkins_obj.get_nodes(node_regex=parser_args.node,
                                                  group=None)
            # capabilities -l
            if parser_args.list:
                print(_get_capabilities_str(jenkins_nodes))

            # capabilities -u
            if parser_args.update:
                for node in jenkins_nodes:
                    node.update_capabilities(parser_args.update)


def _get_capabilities_str(jenkins_nodes):
    """Creates nicely formatted table with capabilities info.

    Returns:
        (:obj:`str`): Table with capabilities info ready to be printed
    """
    table_data = [["Host", "State", "Capabilities"]]
    node_list = [[i.get_name(), i.get_node_status_str(),
                  i.node_details.get_capabilities()] for i in jenkins_nodes]
    table_data.extend(node_list)
    ascii_table = AsciiTable(table_data).table
    return ascii_table


def _get_node_table_str(jenkins_nodes):
    """Creates nicely formatted table with node info.

    Returns:
        (:obj:`str`): Table with node info ready to be printed
    """
    table_data = [["Host", "State",
                   "RAM", "CPU", "Reserved by", "Reserved until"]]
    node_list = [[i.get_name(),
                  i.get_node_status_str(),
                  i.node_details.get_physical_ram(),
                  i.node_details.get_capability('cpu'),
                  i.get_reservation_owner(),
                  i.get_reservation_endtime()] for i in jenkins_nodes]
    table_data.extend(node_list)
    ascii_table = AsciiTable(table_data).table
    return ascii_table


def _get_node_groups_table_str(jenkins_nodes):
    """Creates nicely formatted table with node info.

    Returns:
        (:obj:`str`): Table with node info ready to be printed
    """
    table_data = [["Host", "State",
                   "RAM", "Reserved by", "Groups"]]
    node_list = [[i.get_name(), i.get_node_status_str(),
                  i.node_details.get_physical_ram(), i.get_reservation_owner(),
                  ",".join([str(item) for item in i.node_details.get_node_labels()])] for i in jenkins_nodes]
    table_data.extend(node_list)
    ascii_table = AsciiTable(table_data).table
    return ascii_table


def _get_node_parseable_str(jenkins_nodes):
    """Creates ; separated node info.

    Returns:
        (:obj:`str`): Node info separated by ';'
    """
    node_str = ""
    count = 1
    for node in jenkins_nodes:
        node_list = [node.get_name(), node.get_node_status_str(),
                     node.node_details.get_physical_ram(),
                     node.node_details.get_capability('cpu'),
                     node.get_reservation_owner(),
                     node.get_reservation_endtime()]
        node_str += ";".join([str(item) for item in node_list])
        if count < len(jenkins_nodes):
            node_str += "\n"
        count += 1

    return node_str


def main(args=None):
    start_time = datetime.datetime.now()

    LOG.debug('Started devnest: %s' %
              start_time.strftime('%Y-%m-%d %H:%M:%S'))

    try:
        if args is None:
            args = sys.argv[1:]

        JenkinsNodeShell().main(args)
    except NodeReservationError as ex:
        LOG.error(ex.message)
        sys.exit(1)
    except NodeCliException as ex:
        LOG.error(ex.message)
        sys.exit(1)
    except ConnectionError as ex:
        LOG.error(ex.message)
        sys.exit(1)
    except Exception:
        raise
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
    finally:
        finish_time = datetime.datetime.now()
        LOG.debug('Finished devnest: %s' %
                  finish_time.strftime('%Y-%m-%d %H:%M:%S'))
        LOG.debug('Run time: %s [H]:[M]:[S].[ms]' %
                  str(finish_time - start_time))


if __name__ == "__main__":
    main()
