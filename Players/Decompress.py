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

from d20.Actions.Decompress import Unzip, Unrar, Un7z
from d20.Manual.Facts import DecompressFact
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)


@registerPlayer(
    name="Decompress",
    description=("Decompress and add any resulting files to the objects"
                 " table."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['mimetype'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False}),
        ("password", {'type': str, 'default': None})
    )
)
class DecompressPlayer(PlayerTemplate):

    password = None

    interesting_mts = [
        # "application/epub+zip",
        # "application/x-archive",
        # "application/x-stuffit",
        "application/zip",
        "application/gzip",
        "application/jar",
        "application/java-archive",
        "application/rar",
        "application/x-7z-compressed",
        "application/x-lzma",
        "application/x-ace",  # unace
        "application/x-gzip",
        "application/x-rar",
        "application/x-tar",
        "application/x-zip-compressed",
        "application/x-bzip2",
        # "application/octet-stream",
        "application/vnd.debian.binary-package",
        "application/vnd.ms-cab-compressed",
        "application/x-arj",
        "application/x-lha",
        "application/x-rpm",
        "application/x-xz",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",      # noqa: E501
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",    # noqa: E501
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ]

    obj = None
    object_id = None
    fact_id = None

    def __init__(self, **kwargs):
        # PlayerTemplate registers the console as self.console
        super().__init__(**kwargs)
        self.disable = self.options.get("disable", False)
        self.password = self.options.get("password", None)
        self.mt_map = {
            "application/zip": self.unzip,
            "application/x-rar": self.unrar,
            "application/gzip": self.un7zip,
            "application/jar": self.un7zip,
            "application/java-archive": self.un7zip,
            "application/rar": self.un7zip,
            "application/x-7z-compressed": self.un7zip,
            "application/x-ace": self.unace,
            "application/x-gzip": self.un7zip,
            "application/x-tar": self.un7zip,
            "application/x-zip-compressed": self.un7zip,
            "application/x-bzip2": self.un7zip,
            "application/octet-stream": self.un7zip,
            "application/vnd.debian.binary-package": self.un7zip,
            "application/vnd.ms-cab-compressed": self.un7zip,
            "application/x-arj": self.un7zip,
            "application/x-lha": self.un7zip,
            "application/x-lzma": self.un7zip,
            "application/x-rpm": self.un7zip,
            "application/x-xz": self.un7zip,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": self.unzip,      # noqa: E501
            "application/vnd.openxmlformats-officedocument.presentationml.presentation": self.unzip,    # noqa: E501
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": self.unzip,            # noqa: E501
        }

    def handleFact(self, **kwargs):
        if self.disable:
            return

        if 'fact' not in kwargs:
            raise RuntimeError("Expected 'fact' in arguments")

        factObj = kwargs['fact']
        if factObj.mimetype not in self.interesting_mts:
            return

        self.fact_id = factObj.id
        self.object_id = factObj.parentObjects[0]
        self.obj = self.console.getObject(self.object_id)

        try:
            # Use mimetype to determine how to decompress
            results = self.mt_map[factObj.mimetype]()
            files_decompressed = []
            for result in results:
                d = {
                    'object_id':
                    self.console.addObject(
                        result['data'],
                        metadata={'filename': result['name']},
                        parentObjects=[self.object_id],
                    ),
                    'name':
                    result['name'],
                }
                files_decompressed.append(d)
            data = {
                'decompressed_files': files_decompressed,
            }
            df = DecompressFact(parentObjects=[self.object_id],
                                parentFacts=[self.fact_id],
                                **data)
            self.console.addFact(df)
            return
        except Exception as e:
            raise RuntimeError(e)

    def unzip(self):
        try:
            results = Unzip().unzip(obj=self.obj, password=self.password)
            return results
        except Exception as e:
            self.console.print(e)
            return []

    def unrar(self):
        try:
            results = Unrar().unrar(obj=self.obj, password=self.password)
            return results
        except Exception as e:
            self.console.print(e)
            return []

    def un7zip(self):
        try:
            results = Un7z().un7z(obj=self.obj, password=self.password)
            return results
        except Exception as e:
            self.console.print(e)
            return []

    def unace(self):
        # Not implemented
        return
