##
# Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# DRI: Cyrus Daboo, cdaboo@apple.com
##

from distutils.core import setup, Extension
import sys

if sys.platform in ["darwin", "macosx"]: 

    """
    On Mac OS X we build the actual Python module linking to the
    Kerberos.framework.
    """

    module1 = Extension(
        'kerberos',
        extra_link_args = ['-framework', 'Kerberos'],
        sources = [
            'src/kerberos.c',
            'src/kerberosbasic.c',
            'src/kerberosgss.c',
            'src/base64.c'
        ],
    )
    
    setup (
        name = 'kerberos',
        version = '1.0',
        description = 'This is a high-level interface to the Kerberos.framework',
        ext_modules = [module1]
    )

else:
    """
    On other OS's we simply include a stub file of prototypes.
    Eventually we should build the proper Kerberos module and link
    with appropriate local Kerberos libraries.
    """

    setup (
        name = 'kerberos',
        version = '1.0',
        description = 'This is a high-level interface to the Kerberos.framework',
        py_modules = ['kerberos']
    )
