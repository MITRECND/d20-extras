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


@registerFact('pe')
class PEFact(Fact):
    _type_ = 'pe_summary'
    filename = StringField()
    file_format = StringField()
    nx = StringField()
    pie = StringField()
    virtual_size = StringField()


@registerFact('pe')
class PEDosHeaderFact(Fact):
    _type_ = 'pe_dos_header'
    addressof_new_exeheader = StringField()
    addressof_relocation_table = StringField()
    checksum = StringField()
    file_size_in_pages = StringField()
    header_size_in_paragraphs = StringField()
    initial_ip = StringField()
    initial_relative_cs = StringField()
    initial_relative_ss = StringField()
    initial_sp = StringField()
    magic = StringField()
    maximum_extra_paragraphs = StringField()
    minimum_extra_paragraphs = StringField()
    numberof_relocation = StringField()
    oem_id = StringField()
    oem_info = StringField()
    overlay_number = StringField()
    used_bytes_in_the_last_page = StringField()


@registerFact('pe')
class PEHeaderFact(Fact):
    _type_ = 'pe_header'
    characteristics = StringField()
    machine = StringField()
    numberof_sections = StringField()
    numberof_symbols = StringField()
    pointerto_symbol_table = StringField()
    signature = StringField()
    sizeof_optional_header = StringField()
    time_date_stamps = StringField()


@registerFact('hash')
class PEImpHashFact(Fact):
    _type_ = 'pe_imphash'
    value = StringField()


@registerFact('pe')
class PEOptionalHeaderFact(Fact):
    _type_ = 'pe_optional_header'
    addressof_entrypoint = StringField()
    baseof_code = StringField()
    baseof_data = StringField()
    checksum = StringField()
    dll_characteristics = StringField()
    file_alignment = StringField()
    imagebase = StringField()
    loader_flags = StringField()
    magic = StringField()
    major_image_version = StringField()
    major_linker_version = StringField()
    major_operating_system_version = StringField()
    major_subsystem_version = StringField()
    minor_image_version = StringField()
    minor_linker_version = StringField()
    minor_operating_system_version = StringField()
    minor_subsystem_version = StringField()
    numberof_rva_and_size = StringField()
    section_alignment = StringField()
    sizeof_code = StringField()
    sizeof_heap_commit = StringField()
    sizeof_heap_reserve = StringField()
    sizeof_headers = StringField()
    sizeof_image = StringField()
    sizeof_initialized_data = StringField()
    sizeof_stack_commit = StringField()
    sizeof_stack_reserve = StringField()
    sizeof_uninitialized_data = StringField()
    subsystem = StringField()
    win32_version_value = StringField()


@registerFact('pe')
class PEDataDirectoryFact(Fact):
    _type_ = "pe_data_directory"
    type = StringField()
    rva = StringField()
    size = StringField()
    section = StringField()


@registerFact('pe')
class PESectionFact(Fact):
    _type_ = 'pe_section'
    entropy = StringField()
    flags = StringField()
    name = StringField()
    offset = StringField()
    size = StringField()
    virtual_address = StringField()
    virtual_size = StringField()


@registerFact('pe')
class PESymbolFact(Fact):
    _type_ = 'pe_symbol'
    basic_type = StringField()
    complex_type = StringField()
    name = StringField()
    section_number = StringField()
    storage_class = StringField()
    value = StringField()


@registerFact('pe')
class PEImportFact(Fact):
    _type_ = 'pe_import'
    data = StringField()
    dll = StringField()
    hint = StringField()
    iat = StringField()
    name = StringField()


@registerFact('pe')
class PETLSFact(Fact):
    _type_ = 'pe_tls'
    addressof_callbacks = StringField()
    addressof_index = StringField()
    addressof_raw_data = StringField()
    callbacks = ListField()
    characteristics = StringField()
    data_directory = StringField()
    section = StringField()
    sizeof_raw_data = StringField()
    sizeof_zero_fill = StringField()


@registerFact('pe')
class PERelocationFact(Fact):
    _type_ = 'pe_relocation'
    entry_position = StringField()
    entry_type = StringField()
    virtual_address = StringField()


@registerFact('pe')
class PEExportFact(Fact):
    _type_ = 'pe_export'
    entries = ListField()
    flags = StringField()
    major_version = StringField()
    minor_version = StringField()
    name = StringField()
    ordinal_base = StringField()
    timestamp = StringField()


@registerFact('pe')
class PEDebugFact(Fact):
    _type_ = 'pe_debug'
    addressof_raw_data = StringField()
    age = StringField()
    characteristics = StringField()
    code_view_signature = StringField()
    debug_type = StringField()
    filename = StringField()
    guid = StringField()
    major_version = StringField()
    minor_version = StringField()
    pointerto_raw_data = StringField()
    pogo = DictField()
    timestamp = StringField()
    signature = StringField()
    sizeof_data = StringField()


@registerFact('pe')
class PESignatureFact(Fact):
    _type_ = 'pe_signature'
    certificates = ListField()
    content_information = DictField()
    digest_algorithm = StringField()
    signer_information = DictField()
    version = StringField()


@registerFact('pe')
class PERichHeaderFact(Fact):
    _type_ = 'pe_rich_header'
    key = StringField()
    entries = ListField()
    rich_hash = StringField()
    rich_pv = StringField()


@registerFact('pe')
class PEResourceFact(Fact):
    _type_ = 'pe_resource'
    dialogs = ListField()
    icons = ListField()
    manifest = StringField()
    type = ListField()
    version = DictField()
    languages = ListField()
    sub_languages = ListField()


@registerFact('pe')
class PELoadConfigurationFact(Fact):
    _type_ = 'pe_load_configuration'
    characteristics = StringField()
    code_integrity = DictField()
    critical_section_default_timeout = StringField()
    csd_version = StringField()
    decommit_free_block_threshold = StringField()
    decommit_total_free_threshold = StringField()
    dynamic_value_reloc_table = StringField()
    dynamic_value_reloc_table_offset = StringField()
    dynamic_value_reloc_table_section = StringField()
    editlist = StringField()
    gcf_check_function_pointer = StringField()
    gcf_dispatch_function_pointer = StringField()
    gcf_function_table = StringField()
    gcf_function_count = StringField()
    grf_failure_routine = StringField()
    grf_failure_routine_function_pointer = StringField()
    grf_verify_stackpointer_function_pointer = StringField()
    guard_address_taken_iat_entry_count = StringField()
    guard_address_taken_iat_entry_table = StringField()
    guard_long_jump_target_count = StringField()
    guard_long_jump_target_table = StringField()
    guard_flags = StringField()
    global_flags_clear = StringField()
    global_flags_set = StringField()
    hotpatch_table_offset = StringField()
    hybrid_metadata_pointer = StringField()
    lock_prefix_table = StringField()
    major_version = StringField()
    maximum_allocation_size = StringField()
    minor_version = StringField()
    process_affinity_mask = StringField()
    process_heap_flags = StringField()
    reserved1 = StringField()
    reserved3 = StringField()
    security_cookie = StringField()
    se_handler_count = StringField()
    se_handler_table = StringField()
    timedatestamp = StringField()
    version = StringField()
    virtual_memory_threshold = StringField()


@registerFact('pe')
class PEConstructorFunctionFact(Fact):
    _type_ = 'pe_constructor_function'
    address = StringField()
    idx = StringField()
    name = StringField()


@registerFact('pe')
class PEExceptionFunctionFact(Fact):
    _type_ = 'pe_exception_function'
    address = StringField()
    idx = StringField()
    name = StringField()


@registerFact('pe')
class PEFunctionFact(Fact):
    _type_ = 'pe_function'
    address = StringField()
    idx = StringField()
    name = StringField()
    size = StringField()
