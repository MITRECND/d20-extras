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

from d20.Manual.Facts.Fields import (StringField, ListField, IntegerField,
                                     DictField)


@registerFact('virustotal')
class VirusTotalReportFact(Fact):
    _type_ = 'VirusTotal Report'
    response_code = IntegerField()
    verbose_msg = StringField()
    resource = StringField()
    scan_id = StringField()
    md5 = StringField()
    sha1 = StringField()
    sha256 = StringField()
    scan_date = StringField()
    permalink = StringField()
    positives = IntegerField()
    total = IntegerField()
    scans = DictField()


@registerFact('virustotal')
class VirusTotalBehaviourFact(Fact):
    _type_ = 'VirusTotal Behaviour'
    response_code = IntegerField()
    hash = StringField()
    info = DictField()
    network = DictField()
    behavior = DictField()
    verbose_msg = StringField()


@registerFact('virustotal')
class VirusTotalSubmissionsFact(Fact):
    _type_ = 'VirusTotal Submissions'
    response_code = IntegerField()
    verbose_msg = StringField()
    resource = StringField()
    submissions = ListField()


@registerFact('virustotal')
class VirusTotalCommentsFact(Fact):
    _type_ = 'VirusTotal Comments'
    response_code = IntegerField()
    verbose_msg = StringField()
    resource = StringField()
    comments = ListField()
