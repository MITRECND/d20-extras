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

from d20.Manual.Facts import EXIFFact
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)

import exiftool


@registerPlayer(
    name="EXIFTool",
    description=("Run EXIF Tool on an object and add Facts to the table."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['mimetype'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False})
    )
)
class EXIFToolPlayer(PlayerTemplate):

    interesting_mts = [
        "image/gif",
        "image/jpeg",
        "image/png",
        "image/svg+xml",
        "image/tiff",
        "image/vnd.adobe.photoshop",
        "image/x-ico",
        "image/x-icon",
        "image/x-ms-bmp",
        "image/x-portable-bitmap",
        "image/x-portable-greymap",
        "image/x-portable-pixmap",
        "image/x-xcf",
        "video/3gpp",
        "video/mp4",
        "video/quicktime",
        "video/x-flv",
        "video/x-ms-asf",
        "video/x-msvideo",
    ]

    fact_id = None
    object_id = None

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
        if factObj.mimetype not in self.interesting_mts:
            return

        self.fact_id = factObj.id
        self.object_id = factObj.parentObjects[0]
        self.obj = self.console.getObject(self.object_id)

        try:
            with exiftool.ExifTool() as et:
                metaDict = et.get_metadata(self.obj.onDisk)
                data = {
                    'exif': metaDict,
                }
                exiffact = EXIFFact(
                    parentObjects=[self.object_id],
                    parentFacts=[self.fact_id],
                    **data,
                )
                self.console.addFact(exiffact)
            return
        except Exception as e:
            raise RuntimeError(e)
