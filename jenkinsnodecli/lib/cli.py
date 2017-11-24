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

from jenkinsnodecli.lib import logger

from jenkinsnodecli.lib.jenkins import JenkinsInstance
from requests.exceptions import ConnectionError
from jenkinsnodecli.lib.exceptions import CommandError
from jenkinsnodecli.lib.exceptions import NodeCliException
from jenkinsnodecli.lib.exceptions import NodeReservationError

import argparse
import datetime
import logging
from terminaltables import AsciiTable
import sys

LOG = logger.LOG


class JenkinsNodeShell(object):

    def get_base_parser(self):
        parser = argparse.ArgumentParser(prog='jenkinsnodecli',
                                         description='CLI to perform various '
                                         'tasks to Jenkins Node(s).',
                                         add_help=False)

        parser.add_argument('-?', '-h', '--help',
                            action='help',
                            help='show this help message and exit')

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

        parser.add_argument('-l', '--list-nodes',
                            action='store_true',
                            help='List nodes based on NODE_REGEXP')

        parser.add_argument('-r', '--reserve',
                            type=int,
                            help='Reserve node for time period in HOURS')

        parser.add_argument('-c', '--clear-reservation',
                            action='store_true',
                            help='Clear reservation')

        parser.add_argument('node',
                            nargs='?',
                            metavar='NODE_REGEXP')

        return parser

    def parse_args(self, argv):
        parser = self.get_base_parser()
        args = parser.parse_args(argv)

        if args.verbose:
            LOG.setLevel(level=logging.DEBUG)
            LOG.debug('Jenkins Node CLI running in debug mode')

        if not args.conf and not (args.user and args.password and args.url):
            raise CommandError("You must provide either username, password"
                               " and url or path to configuration file"
                               " via --conf option.")
        return args

    def main(self, argv):
        parser_args = self.parse_args(argv)

        if parser_args.reserve and not parser_args.node:
            raise CommandError("You must provide node name.")

        if parser_args.clear_reservation and not parser_args.node:
            raise CommandError("You must provide node name.")

        if parser_args.list_nodes or '-l' in argv:
            if parser_args.reserve or parser_args.clear_reservation:
                raise CommandError("--list command must not be, mixed with "
                                   "--reserve or --clear-reservation")

        if not parser_args.list_nodes and '-l' not in argv:
            if not parser_args.node:
                raise CommandError("You need to specify CLI argument.")

        jenkins_obj = JenkinsInstance(parser_args.url, parser_args.user,
                                      parser_args.password,
                                      parser_args.conf)

        # List nodes
        if parser_args.list_nodes or '-l' in argv:
            jenkins_nodes = jenkins_obj.get_nodes(node_regex=parser_args.node)
            print(_get_node_table_str(jenkins_nodes))

        # Reserve
        if parser_args.reserve and parser_args.node:
            reservation_time = parser_args.reserve
            jenkins_nodes = jenkins_obj.get_nodes(node_regex=parser_args.node)
            if len(jenkins_nodes) != 1:
                err_msg = "Found %s nodes maching your reservation" \
                          % len(jenkins_nodes)
                if len(jenkins_nodes) > 1:
                    err_msg += ". Please specify only one.\n" \
                               + _get_node_table_str(jenkins_nodes)
                raise CommandError(err_msg)

            jenkins_nodes[0].reserve(reservation_time)

        # Clear Reservation
        if parser_args.clear_reservation and parser_args.node:
            jenkins_nodes = jenkins_obj.get_nodes(node_regex=parser_args.node)
            if len(jenkins_nodes) != 1:
                err_msg = "Found %s nodes maching your criteria" \
                          % len(jenkins_nodes)
                if len(jenkins_nodes) > 1:
                    err_msg += ". Please specify only one.\n" \
                               + _get_node_table_str(jenkins_nodes)
                raise CommandError(err_msg)

            jenkins_nodes[0].clear_reservation()


def _get_node_table_str(jenkins_nodes):
    """Creates nicely formatted table with node info.

    Returns:
        (:obj:`str`): Table with node info ready to be printed
    """
    table_data = [["Slave name", "Status",
                   "Physical Memory", "Reserved by", "Reserved until"]]
    node_list = [[i.get_name(), i.get_node_status_str(),
                  i.get_total_physical_mem(), i.get_reservation_owner(),
                  i.get_reservation_endtime()] for i in jenkins_nodes]
    table_data.extend(node_list)
    ascii_table = AsciiTable(table_data).table
    return ascii_table


def main(args=None):
    start_time = datetime.datetime.now()

    LOG.debug('Started jenkinsnodecli: %s' %
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
        LOG.debug('Finished jenkinsnodecli: %s' %
                  finish_time.strftime('%Y-%m-%d %H:%M:%S'))
        LOG.debug('Run time: %s [H]:[M]:[S].[ms]' %
                  str(finish_time - start_time))


if __name__ == "__main__":
    main()
