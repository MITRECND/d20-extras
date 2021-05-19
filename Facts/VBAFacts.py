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

from d20.Manual.Facts.Fields import (StringField, StrOrBytesField,
                                     IntegerField)


@registerFact('vba')
class ExtractedMacroFact(Fact):
    _type_ = 'extracted_macro'
    filename = StringField()
    stream_path = StringField()
    vba_filename = StringField()
    vba_code = StrOrBytesField()


@registerFact('vba')
class AnalyzedMacroFact(Fact):
    _type_ = 'analyzed_macro'
    type = StringField()
    keyword = StringField()
    description = StringField()


@registerFact('vba')
class DeobfuscatedMacroFact(Fact):
    _type_ = 'deobfuscated_macro'
    deobfuscated_macro_code = StringField()


@registerFact('vba')
class VBASummaryFact(Fact):
    _type_ = 'vba_summary'
    autoexec_keywords = IntegerField()
    suspicious_keywords = IntegerField()
    iocs = IntegerField()
    hex_obfuscated_strings = IntegerField()
    base64_obfuscated_strings = IntegerField()
    dridex_obfuscated_strings = IntegerField()
    vba_obfuscated_strings = IntegerField()
