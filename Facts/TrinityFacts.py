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

from d20.Manual.Facts.Fields import BooleanField, IntegerField


@registerFact('technique')
class TrinityFact(Fact):
    _type_ = 'trinity'
    three_decompressed_files = BooleanField()
    parent_file_is_RAR = BooleanField()
    RAR_sourced_to_SFX_EXE = BooleanField()
    exe_count = IntegerField()
    dll_count = IntegerField()
    unk_count = IntegerField()
    trinity = BooleanField()
