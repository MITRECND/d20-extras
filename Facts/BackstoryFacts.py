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

from d20.Manual.Facts import (Fact, registerFact)

from d20.Manual.Facts.Fields import (StringField, BooleanField)


@registerFact('backstory')
class BulkAnalyzeFact(Fact):
    _type_ = 'bulk_analyze'
    directory = StringField()
    recursive = BooleanField(default=False)
    enable = BooleanField()


@registerFact('backstory')
class VTDownloadFact(Fact):
    _type_ = 'vt_download'
    vt_api_key = StringField()
    vt_download_url = StringField(
        default='https://www.virustotal.com/vtapi/v2/file/download')
    filehash = StringField()
    enable = BooleanField()
