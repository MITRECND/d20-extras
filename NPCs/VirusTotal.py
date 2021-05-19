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
from d20.Manual.Templates import (NPCTemplate, registerNPC)

from d20.Actions.VirusTotal import VirusTotal

import hashlib


# VirusTotal is an NPC. If we made it a Player we would have a conflict
# when the Hash NPC generated several hashes per object and tried to run
# VT on each one. This would result in 3+ VT lookups for the same file.


@registerNPC(
    name="VirusTotal",
    description=("Query VirusTotal for this object."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    options=Arguments(
        ("disable", {'type': bool, 'default': False})
    )
)
class VirusTotalNPC(NPCTemplate):

    disable = False
    hash_value = None
    object_id = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.disable = self.options.get("disable", False)

    def handleData(self, **kwargs):
        if self.disable:
            return

        if 'data' not in kwargs:
            raise RuntimeError("Expected 'data' in arguments")

        dataObj = kwargs['data']
        data = dataObj.data
        self.hash_value = hashlib.sha1(data).hexdigest()
        self.object_id = dataObj.id
        session = self.console.requests
        vt = VirusTotal(
            hash_value=self.hash_value,
            object_id=self.object_id,
            session=session
        )
        # self.console.print(vt._test_lookup())
        self._add_fact(vt.report_lookup())
        self._add_fact(vt.behaviour_lookup())
        self._add_fact(vt.submissions_lookup())
        self._add_fact(vt.comments_lookup())

    def _add_fact(self, fact=None):
        if fact:
            self.console.addFact(fact)
        return
