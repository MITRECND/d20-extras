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

from d20.Manual.Facts import YARAFact

import binascii
import yara


@registerNPC(
    name="YARA",
    description=("Run YARA against this object."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    options=Arguments(
        ("disable", {'type': bool, 'default': False}),
        ("rules", {'type': list, 'default': []})
    )
)
class YARANPC(NPCTemplate):

    object_id = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.disable = self.options.get("disable", False)
        self.rules = self.options.get("rules", None)

    def match_callback(self, data):
        strs = data['strings']
        new_strs = []
        for s in strs:
            d = {
                'offset': s[0],
                s[1]: s[2],
            }
            if isinstance(s[2], bytes):
                h = binascii.hexlify(s[2]).decode('utf-8')
                t = iter(h)
                d[s[1]] = '{ ' + ' '.join(a + b for a, b in zip(t, t)) + ' }'
            new_strs.append(d)
        data['strings'] = new_strs
        yf = YARAFact(parentObjects=[self.object_id], **data)
        self.console.addFact(yf)

    def handleData(self, **kwargs):
        if self.disable:
            return

        if 'data' not in kwargs:
            raise RuntimeError("Expected 'data' in arguments")
        if self.rules is None:
            raise RuntimeError("Expected rule files in config.")

        dataObj = kwargs['data']
        data = dataObj.data
        self.object_id = dataObj.id

        filepaths = dict()
        c = 1
        for fp in self.rules:
            filepaths['namespace{0}'.format(c)] = fp
            c += 1

        rules = yara.compile(filepaths=filepaths)
        rules.match(data=data,
                    callback=self.match_callback,
                    which_callbacks=yara.CALLBACK_MATCHES)
        return
