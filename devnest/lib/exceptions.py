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

LOG = logger.LOG


class NodeCliException(Exception):
    """Base Jenkins Node Cli Exception

    To use this class, inherit from it and define a
    a 'msg_fmt' property. That msg_fmt will get printf'd
    with the keyword arguments provided to the constructor.

    """

    msg_fmt = "An unknown exception occurred."

    def __init__(self, message=None, **kwargs):
        self.kwargs = kwargs
        self.message = message
        if not self.message:
            try:
                self.message = self.msg_fmt % kwargs
            except Exception:
                # arguments in kwargs doesn't match variables in msg_fmt
                import six
                for name, value in six.iteritems(kwargs):
                    LOG.error("%s: %s" % (name, value))
                self.message = self.msg_fmt


class CommandError(NodeCliException):
    def __init__(self, msg):
        super(self.__class__, self).__init__(msg)


class ConfigParser(NodeCliException):
    def __init__(self, msg):
        super(self.__class__, self).__init__(msg)


class NodeDataError(NodeCliException):
    def __init__(self, msg):
        super(self.__class__, self).__init__(msg)


class NodeConfigError(NodeCliException):
    def __init__(self, msg):
        super(self.__class__, self).__init__(msg)


class NodeReservationError(NodeCliException):
    def __init__(self, msg):
        super(self.__class__, self).__init__(msg)
