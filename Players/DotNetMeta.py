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

from d20.Manual.Facts import DotNetFact
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)

from malchive.utilities.dotnetdumper import YaraScanner


@registerPlayer(
    name=".NET Metadata Extractor",
    description=("Extract .NET metadata from a file."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['YARA'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False})
    )
)
class DotNetMetaPlayer(PlayerTemplate):

    yara_rules = [
        "dotnet",
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

        filename = "object_{}".format(self.object_id)
        scanner = YaraScanner(filename, self.obj.data)
        scanner.match()
        md = scanner.metadata

        md.pop('module', None)
        if 'module_name' in md:
            md['module_name'] = str(md['module_name'])
        if 'typelib' in md:
            md['typelib'] = str(md['typelib'])
        if 'version' in md:
            md['version'] = str(md['version'])

        my_fact = DotNetFact(parentObjects=[self.object_id],
                             parentFacts=[self.fact_id],
                             **md)
        self.console.addFact(my_fact)

        for filename, data in scanner.results:
            self.console.addObject(
                data,
                metadata={'filename': filename},
                parentObjects=[self.object_id],
                parentFacts=[self.fact_id, my_fact.id],
            )

        for stream in md['streams']:
            sd = self.obj.data[stream['offset']:stream['offset'] +
                               stream['size']]
            self.console.addObject(
                sd,
                metadata={
                    'filename':
                    str(stream['name']).replace('\'', '').replace('b#', '#')
                },
                parentObjects=[self.object_id],
                parentFacts=[self.fact_id, my_fact.id],
            )

        return
