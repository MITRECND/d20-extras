# Copyright 2021 MITRE Corporation

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from d20.Manual.Facts import TrinityFact
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)


@registerPlayer(
    name="Trinity Detection",
    description=("Detect evidence of DLL sideloading (trinity technique) ",
                 "in processed SFX RAR files. PoC for object relationships."),
    creator="Jason Batchelor",
    version="0.1",
    engine_version="0.1",
    interests=['YARA'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False})
    )
)
class TrinityPlayer(PlayerTemplate):

    yara_rules = [
        "sfx_rar_pdb",
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

        trinity = {
            'three_decompressed_files': False,
            'parent_file_is_RAR': False,
            'RAR_sourced_to_SFX_EXE': False,
            'exe_count': 0,
            'dll_count': 0,
            'unk_count': 0,
            'trinity': False,
        }

        # Find objects decompressed (we've seen this used in
        # dll side-load attacks in sfx rars)
        for f in self.console.waitOnFacts('decompress'):

            ftype_rar = False
            parent_sfx = False

            # Don't bother if we dont have any parent objects to inspect,
            # though this should never happen
            if len(f.parentObjects) == 0:
                return

            # ensure we are only dealing with three decompressed files
            if len(f.decompressed_files) != 3:
                return
            trinity['three_decompressed_files'] = True

            # verify the decompressed file was in fact a rar file
            for pf in f.parentFacts:
                parent_fact = self.console.getFact(pf)
                if parent_fact.factType == 'mimetype':
                    if parent_fact.mimetype == 'application/x-rar':
                        trinity['parent_file_is_RAR'] = True
                        ftype_rar = True

            # check if rar file was found as an embedded file
            # based on obj id and inspect if source of embedded
            # is our original SFX EXE
            extracted = self.console.getAllFacts('extractedcontent')
            for e in extracted:
                if (f.parentObjects[0] in e.childObjects and
                        self.object_id in e.parentObjects):
                    trinity['RAR_sourced_to_SFX_EXE'] = True
                    parent_sfx = True

            # wait till mimetypes are collected on decompressed files
            # to avoid race condition
            self.console.waitOnFacts('mimetype')
            mimetypes = self.console.getAllFacts('mimetype')

            # ensure there is one of each dll, exe, and unknown file
            # type produced
            exe_count = 0
            dll_count = 0
            unk_count = 0
            for d in f.decompressed_files:
                if d['name'].endswith('.exe'):
                    exe_count += 1
                    continue
                if d['name'].endswith('dll'):
                    dll_count += 1
                    continue
                d_obj = d['object_id']
                for m in mimetypes:
                    if (m.parentObjects[0] == d_obj and
                            m.mimetype == 'application/octet-stream'):
                        unk_count += 1

            trinity['exe_count'] = exe_count
            trinity['dll_count'] = dll_count
            trinity['unk_count'] = unk_count

            # if all checks return true, signal trinity technique
            if (exe_count + dll_count + unk_count == 3 and
                    ftype_rar and
                    parent_sfx):
                trinity['trinity'] = True
                TFact = TrinityFact(parentFacts=[self.fact_id],
                                    parentObjects=[self.object_id],
                                    **trinity)
                self.console.addHyp(TFact)
                break
        return
