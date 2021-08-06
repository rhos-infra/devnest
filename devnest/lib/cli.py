#!/usr/bin/env python

# Copyright 2017, 2018 Red Hat, Inc.
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
from devnest.lib.exceptions import NodeConfigError
from devnest.lib.exceptions import NodeReservationError
from devnest.lib.node import NodeStatus

import argparse
import datetime
import json
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
    (DISCONNECT, LIST, RELEASE, RESERVE, GROUP, CAPABILITIES, SETUP, EXTEND, DUMP) = range(9)


class Columns(object):
    """Enumeration for the columns."""
    (HOST, STATE, RAM, CPU, RESERVED, UNTIL, GROUPS,
     CAPABILITIES, IP_ADDRESS) = range(9)

    DEFAULT = 'host,state,ram,cpu,reserved,until,ip_address'
    DEFAULT_JSON = 'state,host'

    @staticmethod
    def get_columns(columns_string):
        columns = []
        for column in columns_string.split(','):
            if column.upper() in Columns.__dict__:
                columns.append(Columns.__dict__.get(column.upper()))
            else:
                raise CommandError("Unknown column: %s" % column)

        return columns

    @staticmethod
    def to_str(column):
        return {
            Columns.HOST: 'Host',
            Columns.STATE: 'State',
            Columns.RAM: 'RAM',
            Columns.CPU: 'CPU',
            Columns.RESERVED: 'Reserved by',
            Columns.UNTIL: 'Reserved until',
            Columns.GROUPS: 'Groups',
            Columns.CAPABILITIES: 'Capabilities',
            Columns.IP_ADDRESS: 'IP Address',
        }[column]

    @staticmethod
    def to_data(node, column):
        return {
            Columns.HOST: node.get_name(),
            Columns.STATE: node.get_node_status_str(),
            Columns.RAM: node.node_details.get_physical_ram(),
            Columns.CPU: node.node_details.get_capability('cpu'),
            Columns.RESERVED: node.get_reservation_owner(),
            Columns.UNTIL: node.get_reservation_endtime(),
            Columns.GROUPS: ",".join(sorted(
                                     node.node_details.get_node_labels())),
            Columns.CAPABILITIES: node.node_details.get_capabilities(),
            Columns.IP_ADDRESS: node.get_node_ip_address(),
        }[column]


class JenkinsNodeShell(object):

    def get_base_parser(self):
        formatter = argparse.ArgumentDefaultsHelpFormatter

        # Config parser
        config_parser = argparse.ArgumentParser(add_help=False)

        config_group = config_parser.add_argument_group()

        config_group.add_argument('--conf',
                                  default=os.environ.get('DEVNEST_CONF', None),
                                  help='Configuration file. [jenkins] section '
                                       'is the same as in '
                                       'jenkins-job-builder. [DEVNEST_CONF]')

        config_group.add_argument('--url',
                                  default=os.environ.get('DEVNEST_URL', None),
                                  help='The Jenkins URL to use.'
                                       'This overrides the url specified in '
                                       'the configuration file. [DEVNEST_URL]')

        config_group.add_argument('-u', '--user',
                                  default=os.environ.get('DEVNEST_USER', None),
                                  help='The Jenkins user to use for '
                                       'authentication. This overrides the '
                                       'user specified in the configuration '
                                       'file. [DEVNEST_USER]')

        config_group.add_argument('-p', '--password',
                                  default=os.environ.get('DEVNEST_PASSWORD',
                                                         None),
                                  help='Password or API token to use for '
                                       'authenticating towards Jenkins. '
                                       'This overrides the password specified '
                                       'in the configuration file. '
                                       '[DEVNEST_PASSWORD]')

        # Main parser
        parser = argparse.ArgumentParser(prog='devnest',
                                         parents=[config_group],
                                         description='CLI to reserve, release'
                                         ' or manage nodes in DevNest.',
                                         formatter_class=formatter,
                                         add_help=False)

        subparsers = parser.add_subparsers(title='node action subcommands',
                                           help='possible actions')

        parser.add_argument('-?', '-h', '--help',
                            action='help',
                            help='Show this help message and exit')

        parser.add_argument('-v', '--verbose',
                            action='store_true',
                            default=os.environ.get('DEVNEST_VERBOSE', False),
                            help='increase output verbosity. [DEVNEST_VERBOSE]')

        # Node parser is used by multiple subparsers
        node_parser = argparse.ArgumentParser(add_help=False)
        node_parser.add_argument('node_regex',
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

        disconnect_parser = subparsers.add_parser('disconnect',
                                                  parents=[node_parser, nest_parser],
                                                  formatter_class=formatter,
                                                  help='disconnect node(s) from Jenkins master')
        disconnect_parser.set_defaults(action=Action.DISCONNECT)

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

        extend_parser = subparsers.add_parser('extend',
                                              parents=[node_parser],
                                              formatter_class=formatter,
                                              help='extend reservation')

        extend_parser.set_defaults(action=Action.EXTEND)

        # List
        list_parser.add_argument('-f', '--format',
                                 default='table',
                                 help='Parseable output, '
                                 'options: csv,json,table')

        list_parser.add_argument('-c', '--column',
                                 help='Columns to show, default depends on format')

        list_parser.add_argument('-s', '--state',
                                 help='Limit output to defined state only')

        # Reserve
        reserve_parser.add_argument('-t', '--time',
                                    type=int,
                                    default=3,
                                    help='Time in hours for the box to be reserved')
        reserve_parser.add_argument('-j', '--json',
                                    action='store_true',
                                    help='Output node information in json')

        # Owner that reserved node.
        reserve_parser.add_argument('-o', '--owner',
                                    help=argparse.SUPPRESS)

        # Reserve - force reserves server on which CI job is running
        reserve_parser.add_argument('-f', '--force',
                                    action='store_true',
                                    help='Force reserve even if CI job is running.'
                                         'After such reservation wait until CI job will '
                                         'finish - state will become "reserved"')

        # Extend
        extend_parser.add_argument('-t', '--time',
                                   type=int,
                                   required=True,
                                   help='Time in hours for the reservation to be extended')

        # Extend - force to extend node reserved by different user
        extend_parser.add_argument('-f', '--force',
                                   action='store_true',
                                   help=argparse.SUPPRESS)

        # Release - force releases server reserved by different user
        release_parser.add_argument('-f', '--force',
                                    action='store_true',
                                    help=argparse.SUPPRESS)

        # Release - brings node online after reservation is released
        release_parser.add_argument('-o', '--online',
                                    action='store_true',
                                    help=argparse.SUPPRESS)
        release_parser.add_argument('-p', '--pending',
                                    action='store_true',
                                    help=argparse.SUPPRESS)

        # Group parser
        groups_parser = argparse.ArgumentParser(add_help=False)
        manage_group = groups_parser.add_mutually_exclusive_group(required=True)

        manage_group.add_argument('-a', '--add',
                                  help="add comma separated group(s) "
                                       "to node if not already")
        manage_group.add_argument('-c', '--clear',
                                  action='store_true',
                                  help="clear all groups from node")
        manage_group.add_argument('-g', '--get',
                                  action='store_true',
                                  help="get groups, without regex "
                                       "get all groups in devnest")
        manage_group.add_argument('-r', '--remove',
                                  help="remove comma separated group(s) "
                                       "from node if they exists")
        manage_group.add_argument('-s', '--set',
                                  help="set node with comma separated "
                                       "group(s)")
        # Manage section
        manage_parser = subparsers.add_parser('group',
                                              parents=[node_parser,
                                                       groups_parser],
                                              formatter_class=formatter,
                                              help='manage devnest groups, use '
                                                   'with caution')
        manage_parser.set_defaults(action=Action.GROUP)

        # Capability parser
        capability_parser = argparse.ArgumentParser(add_help=False)
        capability_group = \
            capability_parser.add_mutually_exclusive_group(required=True)
        capability_group.add_argument('-s', '--set',
                                      help="update node(s) capabilities"
                                           "passed as json dictionary")

        capability = subparsers.add_parser('capability',
                                           parents=[node_parser,
                                                    capability_parser],
                                           formatter_class=formatter,
                                           help='manage node capabilities')
        capability.set_defaults(action=Action.CAPABILITIES)

        # Node setup parser
        setup_options = argparse.ArgumentParser(add_help=False)
        setup_opts_group = \
            setup_options.add_mutually_exclusive_group(required=True)
        setup_opts_group.add_argument('-f', '--file',
                                      help='node config file')

        setup_opts_group.add_argument('-d', '--dir',
                                      help='node config(s) directory')

        setup_options.add_argument('-o', '--offline',
                                   action='store',
                                   default='True',
                                   metavar='True|False',
                                   help='whether to offline the node(s) after registering them in Jenkins Master')

        setup = subparsers.add_parser('setup',
                                      parents=[node_parser,
                                               setup_options],
                                      formatter_class=formatter,
                                      help='setup node(s) based on an XML file or a directory of XML files')

        setup.set_defaults(action=Action.SETUP)

        # Node dump parser
        dump = subparsers.add_parser('dump',
                                     parents=[node_parser],
                                     formatter_class=formatter,
                                     help='dump node config(s)')
        dump.add_argument('-d', '--dir',
                          required=True,
                          help='output config(s) directory')

        dump.set_defaults(action=Action.DUMP)

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

        jenkins_obj = JenkinsInstance(parser_args.url, parser_args.user,
                                      parser_args.password, parser_args.conf)

        # disconnect nodes from Jenkins master
        if parser_args.action is Action.DISCONNECT:
            group = parser_args.group
            if parser_args.all:
                group = None

            jenkins_nodes = jenkins_obj.get_nodes(parser_args.node_regex, group)

            for jenkins_node in jenkins_nodes:
                jenkins_node = jenkins_node.disconnect()

        # List nodes
        if parser_args.action is Action.LIST:
            group = parser_args.group
            if parser_args.all:
                group = None

            jenkins_nodes = jenkins_obj.get_nodes(parser_args.node_regex, group)

            if parser_args.state:
                jenkins_nodes = [node for node in jenkins_nodes
                                 if parser_args.state.lower()
                                 in node.get_node_status_str()]

            if parser_args.format is None or parser_args.format == 'table':
                if not parser_args.column:
                    parser_args.column = Columns.DEFAULT
                print(_get_node_table_str(jenkins_nodes, parser_args.column))
            elif parser_args.format == 'json':
                if not parser_args.column:
                    parser_args.column = Columns.DEFAULT_JSON
                print(_get_node_json_str(jenkins_nodes, parser_args.column))
            elif parser_args.format in LIST_FORMATS:
                if not parser_args.column:
                    parser_args.column = Columns.DEFAULT
                print(_get_node_parseable_str(jenkins_nodes,
                                              parser_args.column))
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

            first_available = False
            if not parser_args.node_regex:
                first_available = True

            jenkins_nodes = jenkins_obj.get_nodes(parser_args.node_regex, group)

            jenkins_nodes_first = []
            if first_available:
                for jenkins_node in jenkins_nodes:
                    if jenkins_node.get_node_status() == NodeStatus.ONLINE:
                        jenkins_nodes_first = [jenkins_node]
                        break
                if not jenkins_nodes_first and parser_args.force:
                    for jenkins_node in jenkins_nodes:
                        status = jenkins_node.get_node_status()
                        reserved_by = jenkins_node.get_reservation_owner()
                        if status == NodeStatus.JOB_RUNNING and not reserved_by:
                            jenkins_nodes_first = [jenkins_node]
                            break
                jenkins_nodes = jenkins_nodes_first

            if len(jenkins_nodes) != 1:
                err_msg = "Found %s nodes maching your reservation" \
                          % len(jenkins_nodes)
                if len(jenkins_nodes) > 1:
                    err_msg += ". Please specify only one.\n" \
                               + _get_node_table_str(jenkins_nodes)
                raise CommandError(err_msg)

            reserve_node = jenkins_nodes[0]

            if reserve_node.get_node_status() == NodeStatus.JOB_RUNNING and \
               not parser_args.force:
                err_msg = "A CI job is is currently running on %s node. Use --force flag " \
                          "to reserve the node.\n\tIt will be reserved and available once the currently " \
                          "running CI job finishes\n\tUse:\n\t" \
                          "    $ devnest list -g %s %s\n\tto check if " \
                          "CI job has finished and you can use it, if so the node "\
                          "status will become reserved.\n\tThis may take even few hours!" \
                          "\n\tMore details about current node usage is available at:" \
                          "\n\t    %s" \
                          % (reserve_node.get_name(), group,
                             reserve_node.get_name(),
                             reserve_node.get_node_url())

                raise CommandError(err_msg)

            if reserve_node.get_node_status() != NodeStatus.ONLINE and \
               not parser_args.force:
                err_msg = "Node %s is not online and can not be reserved. " \
                    % reserve_node.get_name()
                err_msg += "Node status: %s. Try releasing the node." \
                    % reserve_node.get_node_status_str()
                raise CommandError(err_msg)

            reservation_owner = parser_args.owner
            info = reserve_node.reserve(
                reservation_time, owner=reservation_owner,
                force_reserve=parser_args.force)
            if parser_args.json:
                print(json.dumps(info))

        # Extend Reservation
        if parser_args.action is Action.EXTEND:
            jenkins_nodes = jenkins_obj.get_nodes(parser_args.node_regex, group=None)

            if len(jenkins_nodes) != 1:
                err_msg = "Found %s nodes maching your node pattern" \
                          % len(jenkins_nodes)
                if len(jenkins_nodes) > 1:
                    err_msg += ". Please specify only one.\n" \
                               + _get_node_table_str(jenkins_nodes)
                raise CommandError(err_msg)

            node = jenkins_nodes[0]
            node.extend_reservation(parser_args.time, parser_args.force)

        # Clear Reservation
        if parser_args.action is Action.RELEASE:
            jenkins_nodes = jenkins_obj.get_nodes(parser_args.node_regex, group=None)

            if len(jenkins_nodes) != 1:
                err_msg = "Found %s nodes maching your node pattern" \
                          % len(jenkins_nodes)
                if len(jenkins_nodes) > 1:
                    err_msg += ". Please specify only one.\n" \
                               + _get_node_table_str(jenkins_nodes)
                raise CommandError(err_msg)

            reserve_node = jenkins_nodes[0]

            if parser_args.pending:
                reserve_node.set_reprovision_pending()
            else:
                reserve_user = reserve_node.get_reservation_owner()
                jenkins_user = jenkins_obj.get_jenkins_username()
                if reserve_user != jenkins_user and not parser_args.force:
                    err_msg = "Node %s is reserved by %s and can not " \
                              "be released unless used with --force flag." \
                        % (reserve_node.get_name(), reserve_user)
                    raise CommandError(err_msg)

                reserve_node.clear_reservation(bring_online=parser_args.online)

        # Group manage
        if parser_args.action is Action.GROUP:
            jenkins_nodes = jenkins_obj.get_nodes(parser_args.node_regex, group=None)

            # group -g
            if parser_args.get:
                all_groups = []
                for node in jenkins_nodes:
                    all_groups += node.node_details.get_node_labels()
                print("Available groups: " + ",".join(list(set(all_groups))))
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
                elif parser_args.set:
                    groups = parser_args.set.split(",")
                    node.update_with_groups(groups)
                elif parser_args.add:
                    groups = parser_args.add.split(",")
                    node.add_groups(groups)
                elif parser_args.remove:
                    groups = parser_args.remove.split(",")
                    node.remove_groups(groups)

        # Capabilities
        if parser_args.action is Action.CAPABILITIES:
            jenkins_nodes = jenkins_obj.get_nodes(parser_args.node_regex, group=None)

            # capabilities -s
            if parser_args.set:
                for node in jenkins_nodes:
                    node.update_capabilities(parser_args.set)

        if parser_args.action is Action.SETUP:
            if parser_args.file:
                jenkins_obj.create_update_node_from_xml(parser_args.file, parser_args.offline)
            elif parser_args.dir:
                jenkins_obj.create_update_node_from_xml(parser_args.dir, parser_args.offline,
                                                        directory=True)

        if parser_args.action is Action.DUMP:
            if not os.path.isdir(parser_args.dir):
                raise NodeConfigError("Output dir is not regular "
                                      "directory: %s" % parser_args.dir)

            if not os.access(parser_args.dir, os.W_OK):
                raise NodeConfigError("Output dir is not writeable: "
                                      "%s" % parser_args.dir)

            jenkins_nodes = jenkins_obj.get_nodes(parser_args.node_regex,
                                                  group=None)

            for node in jenkins_nodes:
                if node.node_name == 'master':
                    # master node does not have config.xml
                    continue
                node_config_str = node.get_node_config_xml()
                config_xml_path = os.path.join(parser_args.dir,
                                               "%s.xml" % node.node_name)
                if os.path.isfile(config_xml_path):
                    LOG.error('File already exists: %s' % config_xml_path)
                    continue
                with open(config_xml_path, 'w') as output_config:
                    output_config.write(node_config_str)
                    LOG.info('Config file saved: %s' % config_xml_path)


def _get_node_table(jenkins_nodes, columns=Columns.DEFAULT):
    """Creates table with node info.

    Args:
        columns (:obj:`string`): comma separated list of columns

    Returns:
        (:obj:`list`): Table with node info
    """
    columns_list = Columns.get_columns(columns)
    table_data = [[Columns.to_str(x) for x in columns_list]]

    node_list = [[Columns.to_data(jenkins_node, column)
                  for column in columns_list]
                 for jenkins_node in jenkins_nodes]
    table_data.extend(node_list)
    return table_data


def _get_node_table_str(jenkins_nodes, columns=Columns.DEFAULT):
    """Creates nicely formatted table with node info.

    Args:
        columns (:obj:`string`): comma separated list of columns

    Returns:
        (:obj:`str`): Table with node info ready to be printed
    """
    table_data = _get_node_table(jenkins_nodes, columns)
    return AsciiTable(table_data).table


def _get_node_parseable_str(jenkins_nodes, columns=Columns.DEFAULT):
    """Creates ; separated node info.

    Args:
        columns (:obj:`string`): comma separated list of columns

    Returns:
        (:obj:`str`): Node info separated by ';'
    """
    node_str = ""
    count = 1
    columns_list = Columns.get_columns(columns)
    for jenkins_node in jenkins_nodes:
        node_str += ";".join([str(Columns.to_data(jenkins_node, column))
                             for column in columns_list])
        if count < len(jenkins_nodes):
            node_str += "\n"
        count += 1
    return node_str


def _get_node_json_str(jenkins_nodes, columns=Columns.DEFAULT_JSON):
    """Creates json node info.

    Args:
        columns (:obj:`string`): comma separated list of columns

    Returns:
        (:obj:`str`): Node info in json format
    """
    json_table = []
    table_data = _get_node_table(jenkins_nodes, columns)
    columns_table = columns.split(",")
    header_row = True
    for node_row in table_data:
        if header_row:
            header_row = False
            continue
        json_table.append(dict(zip(columns_table, node_row)))

    return json.dumps(json_table)


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
