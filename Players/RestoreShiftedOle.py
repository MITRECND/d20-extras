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

import binascii


@registerPlayer(
    name="RestoreShiftedOle",
    description=("Shift an OLE object that seems to be corrupt by one "
                 "in an attempt to restore it."),
    creator="Jason Batchelor",
    version="0.1",
    engine_version="0.1",
    interests=['YARA'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False})
    )
)
class RestoreShiftedOlePlayer(PlayerTemplate):

    yara_rules = [
        "nibble_shifted_ole",
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

            self.console.print('Found a nibble shifted OLE!')

            hexlified = bytearray(binascii.hexlify(self.obj.data))
            restored = hexlified[1:]
            restored.append(hexlified[0])
            restored = binascii.unhexlify(restored)
            self.console.addObject(
                restored,
                metadata={
                    'filename':
                    '{}_restored'.format(
                        self.obj.metadata.get('filename', self.object_id))
                },
                parentObjects=[self.object_id],
                parentFacts=[self.fact_id],
            )

        except Exception as e:
            raise RuntimeError(e)
