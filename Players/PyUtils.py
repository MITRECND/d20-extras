
# Python binary analysis d20 Player
# Copyright (C) 2021 MITRE Corporation

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from d20.Manual.Facts import PyInstallerTOCFact
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)

from PyInstaller.utils.cliutils.archive_viewer import (get_archive,
                                                       get_content, get_data)

from uncompyle6.main import decompile
from xdis.load import load_module_from_file_object
from xdis import magics

import io
import struct
import time


@registerPlayer(
    name="PyInstaller",
    description=("Deconstruct a PyInstaller executable."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['YARA'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False})
    )
)
class PyInstallerPlayer(PlayerTemplate):

    toc_extension_blacklist = [
        ".so",
        ".dylib",
        ".dll",
        ".zip",
    ]

    toc_string_blacklist = [
        "pyimod",
        "pyi_",
        # TODO: is this too restrictive?
        # "pyi",
        "manifest",
    ]

    yara_rules = [
        "pyinstaller",
    ]

    obj = None
    object_id = None
    fact_id = None

    def __init__(self, **kwargs):
        # PlayerTemplate registers the console as self.console
        super().__init__(**kwargs)
        self.disable = self.options.get("disable", False)

    def handleFact(self, **kwargs):
        if self.disable:
            return

        if 'fact' not in kwargs:
            raise RuntimeError("Expected 'fact' in arguments")

        factObj = kwargs['fact']
        if factObj.rule not in self.yara_rules:
            return

        self.fact_id = factObj.id
        self.object_id = factObj.parentObjects[0]
        self.obj = self.console.getObject(self.object_id)

        try:
            # Open archive
            # TODO: this function relies upon the file extension to determine
            # if this is a .pyz or not and whether to use ZlibArchive or
            # CArchiveReader. self.obj.onDisk returns the tmpfile which won't
            # have that extension.
            arch = get_archive(self.obj.onDisk)
            # Get TOC
            output = []
            get_content(arch, recursive=False, brief=True, output=output)
            # Add TOC contents as a Fact to preserve analyzed TOC list
            my_fact = PyInstallerTOCFact(
                parentObjects=[self.object_id],
                parentFacts=[self.fact_id],
                toc=output,
            )
            self.console.addFact(my_fact)
            # Loop over entries and extract relevant files
            for entry in output:
                # Skip if this entry is in the blacklists
                if (any(x in entry for x in self.toc_string_blacklist) or any(
                        entry.endswith(y)
                        for y in self.toc_extension_blacklist)):
                    self.console.print(
                        "{} in blacklist, skipping...".format(entry))
                    continue
                data = get_data(entry, arch)
                self.console.addObject(
                    data,
                    metadata={'filename': entry},
                    parentObjects=[self.object_id],
                    parentFacts=[self.fact_id],
                )
            return
        except Exception as e:
            self.console.print(e)
            return


@registerPlayer(
    name="PycDecompiler",
    description=("Decompile a pyc file."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['YARA'],
)
class PycDecompilerPlayer(PlayerTemplate):

    password = None

    yara_rules = [
        "pyc_file_magic_v1",
        "pyc_file_magic_v2",
        "pyc_file_magic_v3",
        "pyc_file_magic_bad_mod_timestamp",
    ]

    obj = None
    object_id = None
    fact_id = None

    def __init__(self, **kwargs):
        # PlayerTemplate registers the console as self.console
        super().__init__(**kwargs)
        self.disable = self.options.get("disable", False)

    def handleFact(self, **kwargs):
        if self.disable:
            return

        if 'fact' not in kwargs:
            raise RuntimeError("Expected 'fact' in arguments")

        factObj = kwargs['fact']
        if factObj.rule not in self.yara_rules:
            return

        self.fact_id = factObj.id
        self.object_id = factObj.parentObjects[0]
        self.obj = self.console.getObject(self.object_id)

        try:
            p = self.obj.data
            # If the first four bytes of our "pyc" are already a magic
            # that we are ok with, don't
            # prepend it to the data again.
            magic_found = False
            our_magic = magics.magic2int(p[:4])
            for key in magics.versions:
                if magics.magic2int(key) == our_magic:
                    magic_found = True
            if not magic_found:
                # restore pyc content by writing the file magic and
                # arbitrary modification data per spec
                pyc_header = b'\x03\xf3\x0d\x0a' + struct.pack(
                    'I', int(time.time()))
                _pyc = io.BytesIO(pyc_header + p)
            else:
                _pyc = io.BytesIO(p)
            s_out = io.StringIO()

            # try to decompile decompressed .pyc
            code_objects = {}
            (version, timestamp, magic_int, co, is_pypy,
             source_size) = load_module_from_file_object(_pyc, code_objects)
            decompile(version, co, s_out, code_objects=code_objects)

            s_out.seek(0)
            _py = s_out.read()
            # _py = _py.encode('utf-8')
            self.console.addObject(
                _py,
                metadata={
                    'filename':
                    "{}_decompiled".format(
                        self.obj.metadata.get('filename', 'pyc'))
                },
                parentObjects=[self.object_id],
                parentFacts=[self.fact_id],
            )
            return
        except Exception as e:
            self.console.print('Could not decompile decompressed payload!')
            raise RuntimeError(e)
