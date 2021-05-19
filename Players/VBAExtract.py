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

from d20.Manual.Facts import (ExtractedMacroFact, AnalyzedMacroFact,
                              DeobfuscatedMacroFact, VBASummaryFact)
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)

from oletools.olevba3 import VBA_Parser


@registerPlayer(
    name="VBAExtract",
    description=(
        "Extract VBA code from an object and add Facts to the table."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['YARA'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False})
    )
)
class VBAExtractPlayer(PlayerTemplate):

    yara_rules = [
        "object_linking_embedding_compound_file",
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
        if factObj.rule not in self.yara_rules:
            return

        self.fact_id = factObj.id
        self.object_id = factObj.parentObjects[0]
        self.obj = self.console.getObject(self.object_id)

        obj_data = self.obj.data
        filename = "object_{}".format(self.object_id)

        # Code below here comes from examples found here:
        # https://github.com/decalage2/oletools/wiki/olevba
        try:
            vbaparser = VBA_Parser(filename, data=obj_data, relaxed=True)
        except Exception as e:
            self.console.print(e)
            return

        if vbaparser.detect_vba_macros():

            # Extract Macros
            for (filename, stream_path, vba_filename,
                 vba_code) in vbaparser.extract_macros():
                ed = {
                    'filename': filename,
                    'stream_path': stream_path,
                    'vba_filename': vba_filename,
                    'vba_code': vba_code,
                }
                my_fact = ExtractedMacroFact(parentObjects=[self.object_id],
                                             parentFacts=[self.fact_id],
                                             **ed)
                self.console.addFact(my_fact)

            # Analyze Macros
            results = vbaparser.analyze_macros(show_decoded_strings=True)
            # This breaks stuff if set to True? why?
            # deobfuscate=False)
            for kw_type, keyword, description in results:
                ad = {
                    'type': kw_type,
                    'keyword': keyword,
                    'description': description,
                }
                my_fact = AnalyzedMacroFact(parentObjects=[self.object_id],
                                            parentFacts=[self.fact_id],
                                            **ad)
                self.console.addHyp(my_fact)

            # Attempt to get Deobfuscated Macro Code
            revealed = vbaparser.reveal()
            rd = {
                'deobfuscated_macro_code': revealed,
            }
            my_fact = DeobfuscatedMacroFact(parentObjects=[self.object_id],
                                            parentFacts=[self.fact_id],
                                            **rd)
            self.console.addFact(my_fact)

            # Summary Info (has to be done after analyze_macros):
            sd = {
                'autoexec_keywords': vbaparser.nb_autoexec,
                'suspicious_keywords': vbaparser.nb_suspicious,
                'iocs': vbaparser.nb_iocs,
                'hex_obfuscated_strings': vbaparser.nb_hexstrings,
                'base64_obfuscated_strings': vbaparser.nb_base64strings,
                'dridex_obfuscated_strings': vbaparser.nb_dridexstrings,
                'vba_obfuscated_strings': vbaparser.nb_vbastrings,
            }
            my_fact = VBASummaryFact(parentObjects=[self.object_id],
                                     parentFacts=[self.fact_id],
                                     **sd)
            self.console.addFact(my_fact)
