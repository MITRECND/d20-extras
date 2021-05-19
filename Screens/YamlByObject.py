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

import yaml
import binascii
from collections import OrderedDict

LOGGER = logging.getLogger(__name__)


class CustomDumper(yaml.Dumper):
    @staticmethod
    def bytes_representer(dumper, data):
        try:
            outstring = str(data, 'utf-8')
            if not outstring.isprintable():
                raise UnicodeError('utf-8',
                                   "non-printable characters in sequence",
                                   data)
        except UnicodeError:
            outstring = "0x%s" % (binascii.hexlify(data).decode('utf8'))
        return dumper.represent_str(outstring)

    @staticmethod
    def ordered_dict_representer(dumper, data):
        out_list = list()
        for (key, value) in data.items():
            out_list.append({key: value})
        return dumper.represent_list(out_list)


@registerScreen(
    name="yaml_by_object",
    version="0.1",
    engine_version="0.1",
    options=Arguments(
        ("exclude", {'type': list, 'default': []}),
        ("remove_object_data", {'type': bool, 'default': False}),
        ("include_core_facts", {'type': bool, 'default': False}),
        ("convert_bytes", {'type': bool, 'default': True})
    )
)
class YAMLByObject(ScreenTemplate):

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
        gameData = self.filter()
        CustomDumper.add_representer(bytes, CustomDumper.bytes_representer)
        CustomDumper.add_representer(OrderedDict,
                                     CustomDumper.ordered_dict_representer)

        try:
            return yaml.dump(gameData, Dumper=CustomDumper, indent=4)
        except Exception:
            LOGGER.exception("Error attempting to yaml serialize game data")

    def filter(self):
        gameData = {}

        gameData['objects'] = list()
        # Dangling Facts/Hyps shouldn't really show up unless a
        # BackStory adds something prior to Object 0 being added
        gameData['dangling_facts'] = list()
        gameData['dangling_hyps'] = list()
        for obj in self.objects:
            objdata = obj._coreInfo
            objdata.update(self.formatData(obj._creationInfo))
            objdata['parentObjects'] = obj.parentObjects
            objdata['parentFacts'] = obj.parentFacts
            objdata['childObjects'] = obj.childObjects
            if self.remove_object_data:
                objdata.pop('data')
            gameData['objects'].append(objdata)

        for (_type, column) in self.facts.items():
            if any(e in _type for e in self.exclusions):
                continue
            for fact in column:
                fact_info = fact._nonCoreFacts
                fact_info['tainted'] = False
                ifs = fact._internalFacts
                obj_ids = ifs['_parentObjects_']
                if self.include_core_facts:
                    fact_info.update(self.formatData(fact._coreFacts))
                if len(obj_ids) > 0:
                    for i in obj_ids:
                        try:
                            gameData['objects'][i][_type].append(fact_info)
                        except Exception:
                            gameData['objects'][i][_type] = []
                            gameData['objects'][i][_type].append(fact_info)
                else:
                    fact_info['id'] = fact.id
                    gameData['dangling_facts'].append(fact_info)

        for (_type, column) in self.hyps.items():
            if any(e in _type for e in self.exclusions):
                continue
            for hyp in column:
                hyp_info = hyp._nonCoreFacts
                hyp_info['tainted'] = True
                ifs = hyp._internalFacts
                obj_ids = ifs['_parentObjects_']
                if self.include_core_facts:
                    hyp_info.update(self.formatData(hyp._coreFacts))
                if len(obj_ids) > 0:
                    for i in obj_ids:
                        try:
                            gameData['objects'][i][_type].append(hyp_info)
                        except Exception:
                            gameData['objects'][i][_type] = []
                            gameData['objects'][i][_type].append(hyp_info)
                else:
                    hyp_info['id'] = hyp.id
                    gameData['dangling_hyps'].append(hyp_info)

        return gameData

    def formatData(self, data):
        return {key.strip('_'): value for (key, value) in data.items()}
