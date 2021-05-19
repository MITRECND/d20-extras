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

from d20.Manual.Facts.Fields import (StringField, ListField, DictField)


@registerFact('macho')
class MachOFact(Fact):
    _type_ = 'macho_summary'
    address_base = StringField()
    filename = StringField()
    nx = StringField()
    pie = StringField()


@registerFact('macho')
class MachOHeaderFact(Fact):
    _type_ = 'macho_header'
    magic = StringField()
    cpu_type = StringField()
    cpu_subtype = StringField()
    filetype = StringField()
    flags = ListField()
    number_of_commands = StringField()
    size_of_commands = StringField()
    reserved = StringField()


@registerFact('macho')
class MachOCommandFact(Fact):
    _type_ = 'macho_command'
    command = StringField()
    offset = StringField()
    size = StringField()


@registerFact('macho')
class MachOLibraryFact(Fact):
    _type_ = 'macho_library'
    library_name = StringField()
    timestamp = StringField()
    current_version = StringField()
    compatibility_version = StringField()


@registerFact('macho')
class MachOSegmentFact(Fact):
    _type_ = 'macho_segment'
    segment_name = StringField()
    virtual_address = StringField()
    virtual_size = StringField()
    offset = StringField()
    size = StringField()
    max_protection = StringField()
    init_protection = StringField()
    sections = ListField()


@registerFact('macho')
class MachOSectionFact(Fact):
    _type_ = 'macho_section'
    section_name = StringField()
    virtual_address = StringField()
    offset = StringField()
    size = StringField()
    alignment = StringField()
    number_of_relocations = StringField()
    relocation_offset = StringField()
    section_type = StringField()
    flags = ListField()
    relocations = ListField()


@registerFact('macho')
class MachOSymbolFact(Fact):
    _type_ = 'macho_symbol'
    symbol_name = StringField()
    symbol_type = StringField()
    number_of_sections = StringField()
    description = StringField()
    value = StringField()
    library = StringField()


@registerFact('macho')
class MachOSymbolCommandFact(Fact):
    _type_ = 'macho_symbol_command'
    symbol_offset = StringField()
    number_of_symbols = StringField()
    string_offset = StringField()
    string_size = StringField()


@registerFact('macho')
class MachODynamicSymbolCommandFact(Fact):
    _type_ = 'macho_dynamic_symbol_command'
    first_local_symbol_index = StringField()
    number_of_local_symbols = StringField()
    external_symbol_index = StringField()
    number_of_external_symbols = StringField()
    undefined_symbol_index = StringField()
    number_of_undefined_symbols = StringField()
    table_of_contents_offset = StringField()
    number_of_entries_in_toc = StringField()
    module_table_offset = StringField()
    number_of_entries_in_module_table = StringField()
    external_reference_table_offset = StringField()
    number_of_external_references = StringField()
    indirect_symbol_offset = StringField()
    number_of_indirect_symbols = StringField()
    external_relocation_offset = StringField()
    number_of_external_relocations = StringField()
    local_relocation_offset = StringField()
    number_of_local_relocations = StringField()


@registerFact('macho')
class MachOUUIDFact(Fact):
    _type_ = 'macho_uuid'
    uuid = StringField()


@registerFact('macho')
class MachOMainCommandFact(Fact):
    _type_ = 'macho_main_command'
    entrypoint = StringField()
    stack_size = StringField()


@registerFact('macho')
class MachOThreadCommandFact(Fact):
    _type_ = 'macho_thread_command'
    flavor = StringField()
    count = StringField()
    pc = StringField()


@registerFact('macho')
class MachORPathCommandFact(Fact):
    _type_ = 'macho_rpath_command'
    path = StringField()


@registerFact('macho')
class MachODylinkerFact(Fact):
    _type_ = 'macho_dylinker'
    path = StringField()


@registerFact('macho')
class MachOFunctionStartFact(Fact):
    _type_ = 'macho_function_start'
    offset = StringField()
    size = StringField()
    functions = ListField()


@registerFact('macho')
class MachODataInCodeFact(Fact):
    _type_ = 'macho_data_in_code'
    offset = StringField()
    size = StringField()
    entries = ListField()


@registerFact('macho')
class MachOSegmentSplitInfoFact(Fact):
    _type_ = 'macho_segment_split_info'
    offset = StringField()
    size = StringField()


@registerFact('macho')
class MachOSubFrameworkFact(Fact):
    _type_ = 'macho_sub_framework'
    umbrella = StringField()


@registerFact('macho')
class MachODyldEnvironmentFact(Fact):
    _type_ = 'macho_dyld_environment'
    value = StringField()


@registerFact('macho')
class MachODyldInfoFact(Fact):
    _type_ = 'macho_dyld_info'
    rebase = DictField()
    bind = DictField()
    weak_bind = DictField()
    lazy_bind = DictField()
    export = DictField()
    bindings = ListField()
    exports = ListField()


@registerFact('macho')
class MachOSourceVersionFact(Fact):
    _type_ = 'macho_source_version'
    version = StringField()


@registerFact('macho')
class MachOVersionMinFact(Fact):
    _type_ = 'macho_version_min'
    version = StringField()
    sdk = StringField()


@registerFact('macho')
class MachORelocationFact(Fact):
    _type_ = 'macho_relocation'
    address = StringField()
    size = StringField()
    relocation_type = StringField()
    pcrel = StringField()
    secseg = StringField()
    symbol = StringField()


@registerFact('macho')
class MachOEncryptionInfoFact(Fact):
    _type_ = 'macho_encryption_info'
    offset = StringField()
    size = StringField()
    encryption_id = StringField()


@registerFact('macho')
class MachOCTORFact(Fact):
    _type_ = 'macho_ctor'
    function_id = StringField()
    name = StringField()
    address = StringField()


@registerFact('macho')
class MachOUnwindFunctionFact(Fact):
    _type_ = 'macho_unwind_function'
    function_id = StringField()
    name = StringField()
    address = StringField()


@registerFact('macho')
class MachOFunctionFact(Fact):
    _type_ = 'macho_function'
    function_id = StringField()
    name = StringField()
    address = StringField()
