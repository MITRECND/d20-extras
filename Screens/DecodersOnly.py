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

from d20.Manual.Logger import logging
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (ScreenTemplate, registerScreen)

from typing import List

import json
import binascii
import datetime

LOGGER = logging.getLogger(__name__)


class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            try:
                outstring = str(obj, 'utf-8')
                if not outstring.isprintable():
                    raise UnicodeError('utf-8',
                                       "non-printable characters in sequence",
                                       obj)
            except UnicodeError:
                outstring = "0x%s" % (binascii.hexlify(obj).decode('utf8'))
            return outstring
        if isinstance(obj, datetime.datetime):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


@registerScreen(
    name="decoders",
    version="0.1",
    engine_version="0.1",
    options=Arguments(
        ("exclude", {'type': list, 'default': []}),
        ("remove_object_data", {'type': bool, 'default': False}),
        ("include_core_facts", {'type': bool, 'default': False}),
        ("convert_bytes", {'type': bool, 'default': True})
    )
)
class DecodersOnly(ScreenTemplate):

    exclusions: List[str] = []

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.exclusions = self.options.get("exclude", [])
        self.remove_object_data = self.options.get("remove_object_data", False)
        self.include_core_facts = self.options.get('include_core_facts', False)
        # Parent object inits
        # facts - dictionary of game facts
        # hyps - dictionary of game hypotheses
        # objects - list of objects
        # options - any options passed from config

    def present(self):
        cls = BytesEncoder
        if not self.options.get('convert_bytes', True):
            cls = None

        gameData = self.filter()
        try:
            return json.dumps(gameData, cls=cls, indent=4)
        except Exception:
            LOGGER.exception("Error attempting to JSON serialize game data")

    def filter(self):
        gameData = {}

        for (_type, column) in self.facts.items():
            if any(e in _type for e in self.exclusions):
                continue
            for fact in column:
                if 'decoder' in fact.factGroups:
                    fact_info = fact._nonCoreFacts
                    fact_info['tainted'] = False
                    if self.include_core_facts:
                        fact_info.update(self.formatData(fact._coreFacts))
                    if gameData.get(fact.factType, None) is None:
                        gameData[fact.factType] = []
                    gameData[fact.factType].append(fact_info)

        for (_type, column) in self.hyps.items():
            if any(e in _type for e in self.exclusions):
                continue
            for hyp in column:
                if 'decoder' in hyp.factGroups:
                    hyp_info = hyp._nonCoreFacts
                    hyp_info['decoder'] = hyp.factType
                    hyp_info['tainted'] = True
                    if self.include_core_facts:
                        hyp_info.update(self.formatData(hyp._coreFacts))
                    if gameData.get(hyp.factType, None) is None:
                        gameData[hyp.factType] = []
                    gameData[hyp.factType].append(fact_info)

        return gameData

    def formatData(self, data):
        return {key.strip('_'): value for (key, value) in data.items()}
