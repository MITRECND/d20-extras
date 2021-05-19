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

from d20.Manual.Facts import (AsciiStringFact, UnicodeStringFact,
                              StackStringFact)
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (NPCTemplate, registerNPC)

from malchive.utilities import superstrings
from operator import itemgetter


@registerNPC(
    name="Strings",
    description=("This NPC extracts readable acsii/unicode/stack strings",
                 " and adds them to the Fact table."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    options=Arguments(
        ("disable", {'type': bool, 'default': False}),
        ("stringmodifier", {'type': int, 'default': 15}),
        ("stringtype", {'type': list, 'default': ["all"]})
    )
)
class StringsNPC(NPCTemplate):

    smod = 15
    disable = False
    object_id = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.smod = self.options.get("stringmodifier", 15)
        self.stringtype = self.options.get("stringtype", ["all"])
        self.disable = self.options.get("disable", False)

    def handleData(self, **kwargs):
        if self.disable:
            return

        if 'data' not in kwargs:
            raise RuntimeError("Expected 'data' in arguments")

        dataObj = kwargs['data']
        data = dataObj.data
        self.object_id = dataObj.id
        results = self.find_strings(data)
        for r in sorted(results, key=itemgetter(0)):
            if r[1] == '(ascii)':
                stringFact = AsciiStringFact(
                    value=r[2].decode("utf-8"),
                    parentObjects=[self.object_id],
                )
            elif r[1] == '(unicode)':
                stringFact = UnicodeStringFact(
                    value=r[2].decode("utf-8"),
                    parentObjects=[self.object_id],
                )
            elif r[1] == '(stack)':
                stringFact = StackStringFact(
                    value=r[2].decode("utf-8"),
                    parentObjects=[self.object_id],
                )
            self.console.addFact(stringFact)

    def find_strings(self, data):
        s = superstrings.Superstrings(data, stringmodifier=self.smod)

        results = []
        option = self.stringtype
        if "all" in option:
            results.extend(s.find_ascii())
            results.extend(s.find_unicode())
            results.extend(s.find_stack_strings())
        elif "unicode" in option:
            results.extend(s.find_unicode())
        elif "stack" in option:
            results.extend(s.find_stack_strings())
        elif "ascii" in option:
            results.extend(s.find_ascii())

        return results
