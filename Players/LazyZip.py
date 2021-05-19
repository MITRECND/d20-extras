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

from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)


@registerPlayer(
    name="Lazy Zip Append Extractor",
    description=("Extract data appended lazily to the end of a ZIP file."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['YARA'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False})
    )
)
class LazyZipPlayer(PlayerTemplate):

    yara_rules = [
        "lazy_zip_append",
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

        # This is the offset of EOCD
        offset = factObj.strings[0].get("offset")
        # The Comment is located 22 bytes into EOCD
        offset += 22
        appended_data = self.obj.data[offset:]

        self.console.addObject(
            appended_data,
            metadata={
                'filename':
                '{}_appended_payload'.format(
                    self.obj.metadata.get('filename', self.object_id))
            },
            parentObjects=[self.object_id],
            parentFacts=[self.fact_id],
        )

        return
