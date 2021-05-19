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

from d20.Manual.Facts.Fields import (StringField, ListField)


@registerFact('elf')
class ELFFact(Fact):
    _type_ = 'elf_summary'
    address_base = StringField()
    filename = StringField()
    nx = StringField()
    pie = StringField()
    virtual_size = StringField()


@registerFact('elf')
class ELFHeaderFact(Fact):
    _type_ = 'elf_header'
    endianness = StringField()
    entrypoint = StringField()
    filetype = StringField()
    header_size = StringField()
    identity_class = StringField()
    machine_type = StringField()
    magic = StringField()
    numberof_segments = StringField()
    numberof_sections = StringField()
    object_file_version = StringField()
    os_abi = StringField()
    processor_flags = StringField()
    program_header_offset = StringField()
    program_header_size = StringField()
    section_header_offset = StringField()
    section_header_size = StringField()
    version = StringField()


@registerFact('elf')
class ELFSectionFact(Fact):
    _type_ = 'elf_section'
    entropy = StringField()
    file_offset = StringField()
    name = StringField()
    segments = ListField()
    size = StringField()
    type = StringField()
    virtual_address = StringField()


@registerFact('elf')
class ELFSegmentFact(Fact):
    _type_ = 'elf_segment'
    segment_type = StringField()
    flags = StringField()
    file_offset = StringField()
    virtual_address = StringField()
    virtual_size = StringField()
    size = StringField()
    sections = ListField()


@registerFact('elf')
class ELFDynamicEntryFact(Fact):
    _type_ = 'elf_dynamic_entry'
    tag = StringField()
    value = StringField()
    info = ListField()


@registerFact('elf')
class ELFDynamicSymbolFact(Fact):
    _type_ = 'elf_dynamic_symbol'
    name = StringField()
    symbol_type = StringField()
    value = StringField()
    visibility = StringField()
    binding = StringField()
    import_export = StringField()
    version = StringField()


@registerFact('elf')
class ELFStaticSymbolFact(Fact):
    _type_ = 'elf_static_symbol'
    name = StringField()
    symbol_type = StringField()
    value = StringField()
    visibility = StringField()
    binding = StringField()
    import_export = StringField()
    version = StringField()


@registerFact('elf')
class ELFExportedSymbolFact(Fact):
    _type_ = 'elf_exported_symbol'
    name = StringField()
    symbol_type = StringField()
    value = StringField()
    visibility = StringField()
    binding = StringField()
    import_export = StringField()
    version = StringField()


@registerFact('elf')
class ELFImportedSymbolFact(Fact):
    _type_ = 'elf_imported_symbol'
    name = StringField()
    symbol_type = StringField()
    value = StringField()
    visibility = StringField()
    binding = StringField()
    import_export = StringField()
    version = StringField()


@registerFact('elf')
class ELFDynamicRelocationFact(Fact):
    _type_ = 'elf_dynamic_relocation'
    address = StringField()
    relocation_type = StringField()
    info = StringField()
    size = StringField()
    addend = StringField()
    purpose = StringField()
    symbol = StringField()


@registerFact('elf')
class ELFPLTGOTRelocationFact(Fact):
    _type_ = 'elf_pltgot_relocation'
    address = StringField()
    relocation_type = StringField()
    info = StringField()
    size = StringField()
    addend = StringField()
    purpose = StringField()
    symbol = StringField()


@registerFact('elf')
class ELFObjectRelocationFact(Fact):
    _type_ = 'elf_object_relocation'
    address = StringField()
    relocation_type = StringField()
    info = StringField()
    size = StringField()
    addend = StringField()
    purpose = StringField()
    symbol = StringField()


@registerFact('elf')
class ELFGNUHashFact(Fact):
    _type_ = 'elf_gnu_hash'
    number_of_buckets = StringField()
    first_symbol_index = StringField()
    shift_count = StringField()
    bloom_filters = ListField()
    buckets = ListField()
    hash_values = ListField()


@registerFact('elf')
class ELFSysvHashFact(Fact):
    _type_ = 'elf_sysv_hash'
    number_of_buckets = StringField()
    number_of_chains = StringField()
    buckets = ListField()
    chains = ListField()


@registerFact('elf')
class ELFNoteFact(Fact):
    _type_ = 'elf_note'
    note_id = StringField()
    name = StringField()
    note_type = StringField()
    description = StringField()
    sdk_version = StringField()
    ndk_version = StringField()
    ndk_build_number = StringField()
    abi = StringField()
    version = StringField()


@registerFact('elf')
class ELFConstructorFunctionFact(Fact):
    _type_ = 'elf_constructor_function'
    function_id = StringField()
    name = StringField()
    address = StringField()


@registerFact('elf')
class ELFFunctionFact(Fact):
    _type_ = 'elf_function'
    function_id = StringField()
    name = StringField()
    address = StringField()


@registerFact('elf')
class ELFTelfhashFact(Fact):
    _type_ = 'elf_telfhash'
    file = StringField()
    telfhash = StringField()
    msg = StringField()
