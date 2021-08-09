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

from setuptools import setup
# In python < 2.7.4, a lazy loading of package `pbr` will break
# setuptools if some other modules registered functions in `atexit`.
# solution from: http://bugs.python.org/issue15881#msg170215
try:
    import multiprocessing  # noqa
except ImportError:
    pass

setup(
    setup_requires=['pbr>=3.0.0', 'setuptools>=17.1', 'distro', 'selinux'],
    pbr=True)

import os  # noqa: E402
import distro  # noqa: E402

SELINUX_DISTROS = ["fedora", "rhel", "centos"]

if distro.linux_distribution(full_distribution_name=False)[0] in SELINUX_DISTROS:

    # For RedHat based systems, get selinux binding
    try:
        import selinux
    except ImportError as e:
        new_error = type(e)(e.message + ". check that 'libselinux-python is "
                                        "installed'")

        from distutils import sysconfig
        import shutil
        import sys

        if hasattr(sys, 'real_prefix'):
            # check for venv
            VENV_SITE = sysconfig.get_python_lib()

            SELINUX_PATH = os.path.join(
                sysconfig.get_python_lib(plat_specific=True,
                                         prefix=sys.real_prefix),
                "selinux")

            if not os.path.exists(SELINUX_PATH):
                raise new_error

            dest = os.path.join(VENV_SITE, "selinux")
            if os.path.exists(dest):
                raise new_error

            # filter precompiled files
            files = [os.path.join(SELINUX_PATH, f)
                     for f in os.listdir(SELINUX_PATH)
                     if not os.path.splitext(f)[1] in (".pyc", ".pyo")]

            # add extra file for (libselinux-python)
            _selinux_file = os.path.join(
                sysconfig.get_python_lib(plat_specific=True,
                                         prefix=sys.real_prefix),
                "_selinux.so")
            if os.path.exists(_selinux_file):
                shutil.copy(_selinux_file, os.path.dirname(dest))
                files.append(_selinux_file)

            os.makedirs(dest)
            for f in files:
                shutil.copy(f, dest)
        else:
            raise new_error
        import selinux  # noqa
