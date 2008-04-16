##
# Copyright (c) 2006-2007 Apple Inc. All rights reserved.
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
import commands

setup (
    name = "kerberos",
    version = "1.0",
    description = "Kerberos high-level interface",
    ext_modules = [
        Extension(
            "kerberos",
            extra_link_args = commands.getoutput("krb5-config --libs gssapi").split(),
            extra_compile_args = commands.getoutput("krb5-config --cflags gssapi").split(),
            sources = [
                "src/kerberos.c",
                "src/kerberosbasic.c",
                "src/kerberosgss.c",
                "src/kerberospw.c",
                "src/base64.c"
            ],
        ),
    ],
)
