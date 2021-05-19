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


@registerFact('dotnet')
class DotNetFact(Fact):
    _type_ = 'dotnet_summary'
    assembly = DictField()
    assembly_refs = ListField()
    constants = ListField()
    guids = ListField()
    modulerefs = ListField()
    module_name = StringField()
    field_offsets = ListField()
    number_of_field_offsets = IntegerField()
    number_of_assembly_refs = IntegerField()
    number_of_constants = IntegerField()
    number_of_guids = IntegerField()
    number_of_modulerefs = IntegerField()
    number_of_resources = IntegerField()
    number_of_streams = IntegerField()
    number_of_user_strings = IntegerField()
    resources = ListField()
    streams = ListField()
    typelib = StringField()
    user_strings = ListField()
    version = StringField()
