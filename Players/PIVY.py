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

from d20.Manual.Facts import PIVYFact
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)

from malchive.decoders import pivy


@registerPlayer(
    name="PIVY Binary Dumper",
    description=("Dump elements of the PIVY RAT."),
    creator="Jason Batchelor",
    version="0.1",
    engine_version="0.1",
    interests=['YARA'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False})
    )
)
class PIVYBinDumpPlayer(PlayerTemplate):

    yara_rules = [
        "poison_ivy",
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

        self.callDecoder()
        return

    def callDecoder(self):

        stream = self.obj.data

        try:
            c = pivy.GetConfig(stream)
        except Exception as e:
            # Unable to parse configuration
            self.console.print(e)
            return

        fa = dict()
        fa = {'config': c.elements}

        my_fact = PIVYFact(parentObjects=[self.object_id],
                           parentFacts=[self.fact_id],
                           **fa)
        self.console.addFact(my_fact)

        return
