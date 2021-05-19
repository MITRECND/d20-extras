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

from d20.Actions import registerAction
from d20.Manual.Facts import (VirusTotalReportFact, VirusTotalCommentsFact,
                              VirusTotalBehaviourFact,
                              VirusTotalSubmissionsFact)
from d20.Manual.Options import Arguments


@registerAction(
    name="virustotal",
    options=Arguments(
        ("uri", {'type': str, 'default': None}),
        ("api_key", {'type': str, 'default': None}),
    )
)
class VirusTotal(object):
    '''Class for supporting VirusTotal Actions.'''

    uri = None
    api_key = None
    hash_value = None
    fact_id = None
    object_id = None

    def __init__(self,
                 hash_value=None,
                 fact_id=None,
                 object_id=None,
                 session=None,
                 **kwargs):

        # Set up basics for requests
        self.uri = self.options.get('uri', None)
        self.api_key = self.options.get('api_key', None)
        if self.uri is None or self.api_key is None:
            return
        if not self.uri.endswith('/'):
            self.uri = self.uri + '/'
        self.hash_value = hash_value
        if fact_id is not None:
            self.fact_id = [fact_id]
        if object_id is not None:
            self.object_id = [object_id]

        self.session = session

        # Requests headers and params for query
        self.headers = {
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'gzip',
        }
        self.params = {
            'apikey': self.api_key,
            'resource': self.hash_value,
            'hash': self.hash_value,
        }

        # Query locations
        self.download = self.uri + 'file/download'
        self.report = self.uri + 'file/report'
        self.behaviour = self.uri + 'file/behaviour'
        self.submissions = self.uri + 'file/submissions'
        self.comments = self.uri + 'comments/get'

        return

    def _vt_lookup(self, uri):
        if self.session:
            response = self.session.get(uri,
                                        params=self.params,
                                        headers=self.headers)
        else:
            return None
        if response.status_code == 200:
            json_response = response.json()
            if not isinstance(json_response, dict):
                json_response = None
        else:
            json_response = None
        return json_response

    def _test_lookup(self):
        # Only used for testing values being passed around
        vtf = {
            "uri": self.uri,
            "api_key": self.api_key,
            "hash": self.hash_value,
            "object_id": self.object_id,
            "fact_id": self.fact_id,
        }
        return vtf

    def file_download(self):
        # Not using _vt_lookup since we are dealing with a file
        response = self.session.get(self.download,
                                    params=self.params,
                                    headers=self.headers)
        return response

    def report_lookup(self):
        vtf = self._vt_lookup(self.report)
        if vtf is not None:
            vtf = VirusTotalReportFact(parentObjects=self.object_id,
                                       parentFacts=self.fact_id,
                                       **vtf)
        return vtf

    def behaviour_lookup(self):
        vtf = self._vt_lookup(self.behaviour)
        if vtf is not None:
            vtf = VirusTotalBehaviourFact(parentObjects=self.object_id,
                                          parentFacts=self.fact_id,
                                          **vtf)
        return vtf

    def submissions_lookup(self):
        vtf = self._vt_lookup(self.submissions)
        if vtf is not None:
            vtf = VirusTotalSubmissionsFact(parentObjects=self.object_id,
                                            parentFacts=self.fact_id,
                                            **vtf)
        return vtf

    def comments_lookup(self):
        vtf = self._vt_lookup(self.comments)
        if vtf is not None:
            vtf = VirusTotalCommentsFact(parentObjects=self.object_id,
                                         parentFacts=self.fact_id,
                                         **vtf)
        return vtf
