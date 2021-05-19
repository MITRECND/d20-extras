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
from d20.Manual.Templates import (BackStoryTemplate, registerBackStory)

from d20.Actions.VirusTotal import VirusTotal


@registerBackStory(
    name="VTDownload",
    description=("Searches VT for the hash and downloads the file."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    default_weight=1,
    options=Arguments(
        ("test", {'type': bool, 'default': False})
    ),
    category="file_download")
class VTDownload(BackStoryTemplate):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # If we have options, they would go here
        self.test = self.options.get("test", False)

    def handleFact(self, **kwargs):

        # This should be the VTDownloadFact
        factObj = kwargs['fact']

        # Did we get a Fact we can handle?
        if factObj.factType != 'vt_download' or not factObj.enable:
            return

        filehash = factObj.filehash

        session = self.console.requests
        vt = VirusTotal(hash_value=filehash, session=session)
        response = vt.file_download()

        if response.status_code == 200:
            data = response.content

            # TODO Should find a way to not query VT again
            # but make a filename in metadata. Use hash?
            self.console.addObject(
                data,
                metadata={
                    'downloaded': True,
                    'BackStory': 'vt_download'
                },
            )

            # Break so other backstories in the category
            # don't run
            return True

        elif response.status_code == 204:
            self.console.print("204: Request Rate Limit Exceeded")
        elif response.status_code == 400:
            self.console.print("400: Bad Request")
        elif response.status_code == 403:
            self.console.print("403: Access Forbidden")
        elif response.status_code == 404:
            self.console.print("404: File Not Found")
        else:
            self.console.print(response.text)
