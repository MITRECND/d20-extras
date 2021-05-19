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

# Code heavily influenced by the macho_reader example from the LIEF project:
# https://github.com/lief-project/LIEF/blob/master/examples/python/macho_reader.py

from d20.Manual.Facts import (
    MachOFact, MachOHeaderFact, MachOCommandFact, MachOLibraryFact,
    MachOSegmentFact, MachOSectionFact, MachOSymbolFact,
    MachOSymbolCommandFact, MachODynamicSymbolCommandFact, MachOUUIDFact,
    MachOMainCommandFact, MachOThreadCommandFact, MachORPathCommandFact,
    MachODylinkerFact, MachOFunctionStartFact, MachOSegmentSplitInfoFact,
    MachODataInCodeFact, MachOSubFrameworkFact, MachODyldInfoFact,
    MachOSourceVersionFact, MachOVersionMinFact, MachORelocationFact,
    MachOEncryptionInfoFact, MachODyldEnvironmentFact, MachOCTORFact,
    MachOUnwindFunctionFact, MachOFunctionFact)
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)

import lief
from lief import MachO


@registerPlayer(
    name="MachOMeta",
    description=("Parse a Mach-O object and add Facts to the table."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['mimetype'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False}),
        ("information", {'type': bool, 'default': True}),
        ("header", {'type': bool, 'default': True}),
        ("commands", {'type': bool, 'default': True}),
        ("libraries", {'type': bool, 'default': True}),
        ("segments", {'type': bool, 'default': True}),
        ("sections", {'type': bool, 'default': True}),
        ("symbols", {'type': bool, 'default': True}),
        ("symbol_command", {'type': bool, 'default': True}),
        ("dynamic_symbol_command", {'type': bool, 'default': True}),
        ("uuid", {'type': bool, 'default': True}),
        ("main_command", {'type': bool, 'default': True}),
        ("thread_command", {'type': bool, 'default': True}),
        ("rpath_command", {'type': bool, 'default': True}),
        ("dylinker", {'type': bool, 'default': True}),
        ("function_starts", {'type': bool, 'default': True}),
        ("data_in_code", {'type': bool, 'default': True}),
        ("segment_split_info", {'type': bool, 'default': True}),
        ("sub_framework", {'type': bool, 'default': True}),
        ("dyld_environment", {'type': bool, 'default': True}),
        ("dyld_info", {'type': bool, 'default': True}),
        ("rebase_opcodes", {'type': bool, 'default': True}),
        ("bind_opcodes", {'type': bool, 'default': True}),
        ("weak_bind_opcodes", {'type': bool, 'default': True}),
        ("lazy_bind_opcodes", {'type': bool, 'default': True}),
        ("export_trie", {'type': bool, 'default': True}),
        ("source_version", {'type': bool, 'default': True}),
        ("version_min", {'type': bool, 'default': True}),
        ("relocations", {'type': bool, 'default': True}),
        ("encryption_info", {'type': bool, 'default': True}),
        ("ctor", {'type': bool, 'default': True}),
        ("unwind_functions", {'type': bool, 'default': True}),
        ("functions", {'type': bool, 'default': True}),
    )
)
class MachOMetaPlayer(PlayerTemplate):

    interesting_mts = [
        'application/x-mach-binary',
    ]

    object_id = None
    fact_id = None
    lief = None
    macho = None

    format_str = "{}"
    format_hex = "0x{:x}"
    format_dec = "{:d}"

    def __init__(self, **kwargs):
        # PlayerTemplate registers the console as self.console
        super().__init__(**kwargs)
        self.disable = self.options.get("disable", False)
        self.information = self.options.get("information", True)
        self.header = self.options.get("header", True)
        self.commands = self.options.get("commands", True)
        self.libraries = self.options.get("libraries", True)
        self.segments = self.options.get("segments", True)
        self.sections = self.options.get("sections", True)
        self.symbols = self.options.get("symbols", True)
        self.symbol_command = self.options.get("symbol_command", True)
        self.dynamic_symbol_command = self.options.get(
            "dynamic_symbol_command", True)
        self.uuid = self.options.get("uuid", True)
        self.main_command = self.options.get("main_command", True)
        self.thread_command = self.options.get("thread_command", True)
        self.rpath_command = self.options.get("rpath_command", True)
        self.dylinker = self.options.get("dylinker", True)
        self.function_starts = self.options.get("function_starts", True)
        self.data_in_code = self.options.get("data_in_code", True)
        self.segment_split_info = self.options.get("segment_split_info", True)
        self.sub_framework = self.options.get("sub_framework", True)
        self.dyld_environment = self.options.get("dyld_environment", True)
        self.dyld_info = self.options.get("dyld_info", True)
        self.rebase_opcodes = self.options.get("rebase_opcodes", True)
        self.bind_opcodes = self.options.get("bind_opcodes", True)
        self.weak_bind_opcodes = self.options.get("weak_bind_opcodes", True)
        self.lazy_bind_opcodes = self.options.get("lazy_bind_opcodes", True)
        self.export_trie = self.options.get("export_trie", True)
        self.source_version = self.options.get("source_version", True)
        self.version_min = self.options.get("version_min", True)
        self.relocations = self.options.get("relocations", True)
        self.encryption_info = self.options.get("encryption_info", True)
        self.ctor = self.options.get("ctor", True)
        self.unwind_functions = self.options.get("unwind_functions", True)
        self.functions = self.options.get("functions", True)

    def handleFact(self, **kwargs):
        if self.disable:
            return

        if 'fact' not in kwargs:
            raise RuntimeError("Expected 'fact' in arguments")

        factObj = kwargs['fact']
        if factObj.mimetype not in self.interesting_mts:
            return

        self.fact_id = factObj.id
        self.object_id = factObj.parentObjects[0]
        self.obj = self.console.getObject(self.object_id)

        try:
            self.macho = lief.parse(self.obj.onDisk)
        except Exception as e:
            self.console.print(e)
            raise (e)

        # LIEF functions
        if self.information:
            self.get_information()
        if self.header:
            self.get_header()
        if self.commands:
            self.get_commands()
        if self.libraries:
            self.get_libraries()
        if self.segments:
            self.get_segments()
        if self.sections:
            self.get_sections()
        if self.symbols:
            self.get_symbols()
        if self.symbol_command:
            self.get_symbol_command()
        if self.dynamic_symbol_command:
            self.get_dynamic_symbol_command()
        if self.uuid:
            self.get_uuid()
        if self.main_command:
            self.get_main_command()
        if self.thread_command:
            self.get_thread_command()
        if self.rpath_command:
            self.get_rpath_command()
        if self.dylinker:
            self.get_dylinker()
        if self.function_starts:
            self.get_function_starts()
        if self.data_in_code:
            self.get_data_in_code()
        if self.segment_split_info:
            self.get_segment_split_info()
        if self.sub_framework:
            self.get_sub_framework()
        if self.dyld_environment:
            self.get_dyld_environment()
        if self.dyld_info:
            self.get_dyld_info()
        if self.rebase_opcodes:
            self.get_rebase_opcodes()
        if self.bind_opcodes:
            self.get_bind_opcodes()
        if self.weak_bind_opcodes:
            self.get_weak_bind_opcodes()
        if self.lazy_bind_opcodes:
            self.get_lazy_bind_opcodes()
        if self.export_trie:
            self.get_export_trie()
        if self.source_version:
            self.get_source_version()
        if self.version_min:
            self.get_version_min()
        if self.relocations:
            self.get_relocations()
        if self.encryption_info:
            self.get_encryption_info()
        if self.ctor:
            self.get_ctor()
        if self.unwind_functions:
            self.get_unwind_functions()
        if self.functions:
            self.get_functions()

    def get_information(self):
        infod = {
            "filename": self.format_str.format(self.macho.name),
            "address_base": self.format_hex.format(self.macho.imagebase),
            "pie": self.format_str.format(str(self.macho.is_pie)),
            "nx": self.format_str.format(str(self.macho.has_nx)),
        }
        infof = MachOFact(parentObjects=[self.object_id],
                          parentFacts=[self.fact_id],
                          **infod)
        self.console.addFact(infof)
        return

    def get_header(self):
        header = self.macho.header
        flags = [str(s).split(".")[-1] for s in header.flags_list]

        hd = {
            "magic":
            self.format_str.format(str(header.magic).split(".")[-1]),
            "cpu_type":
            self.format_str.format(str(header.cpu_type).split(".")[-1]),
            "cpu_subtype":
            self.format_hex.format(header.cpu_subtype),
            "filetype":
            self.format_str.format(str(header.file_type).split(".")[-1]),
            "flags":
            flags,
            "number_of_commands":
            self.format_dec.format(header.nb_cmds),
            "size_of_commands":
            self.format_hex.format(header.sizeof_cmds),
            "reserved":
            self.format_hex.format(header.reserved),
        }
        hf = MachOHeaderFact(parentObjects=[self.object_id],
                             parentFacts=[self.fact_id],
                             **hd)
        self.console.addFact(hf)
        return

    def get_commands(self):
        for command in self.macho.commands:
            cd = {
                "command":
                self.format_str.format(str(command.command).split(".")[-1]),
                "offset":
                self.format_hex.format(command.command_offset),
                "size":
                self.format_dec.format(command.size),
            }
            cf = MachOCommandFact(parentObjects=[self.object_id],
                                  parentFacts=[self.fact_id],
                                  **cd)
            self.console.addFact(cf)
        return

    def get_libraries(self):
        for library in self.macho.libraries:
            current_version_str = "{:d}.{:d}.{:d}".format(
                *library.current_version)
            compatibility_version_str = "{:d}.{:d}.{:d}".format(
                *library.compatibility_version)
            ld = {
                "library_name":
                self.format_str.format(library.name),
                "timestamp":
                self.format_dec.format(library.timestamp),
                "current_version":
                self.format_str.format(current_version_str),
                "compatibility_version":
                self.format_str.format(compatibility_version_str),
            }
            lf = MachOLibraryFact(parentObjects=[self.object_id],
                                  parentFacts=[self.fact_id],
                                  **ld)
            self.console.addFact(lf)
        return

    def get_segments(self):
        for segment in self.macho.segments:
            sections = [x for x in map(lambda s: s.name, segment.sections)]
            sd = {
                "segment_name": self.format_str.format(segment.name),
                "virtual_address":
                self.format_hex.format(segment.virtual_address),
                "virtual_size": self.format_hex.format(segment.virtual_size),
                "offset": self.format_hex.format(segment.file_offset),
                "size": self.format_hex.format(segment.file_size),
                "max_protection":
                self.format_hex.format(segment.max_protection),
                "init_protection":
                self.format_hex.format(segment.init_protection),
                "sections": sections,
            }
            sf = MachOSegmentFact(parentObjects=[self.object_id],
                                  parentFacts=[self.fact_id],
                                  **sd)
            self.console.addFact(sf)
        return

    def get_sections(self):
        for section in self.macho.sections:
            flags = [str(s).split(".")[-1] for s in section.flags_list]
            sd = {
                "section_name":
                self.format_str.format(section.name),
                "virtual_address":
                self.format_hex.format(section.virtual_address),
                "offset":
                self.format_hex.format(section.offset),
                "size":
                self.format_hex.format(section.size),
                "alignment":
                self.format_hex.format(section.alignment),
                "number_of_relocations":
                self.format_hex.format(section.numberof_relocations),
                "relocation_offset":
                self.format_hex.format(section.relocation_offset),
                "section_type":
                str(section.type).split(".")[-1],
                "flags":
                flags,
            }
            if len(section.relocations) > 0:
                rl = []
                for idx, reloc in enumerate(section.relocations):
                    name = reloc.symbol.name if reloc.has_symbol else ""
                    if reloc.has_section:
                        secname = " - " + reloc.section.name
                    else:
                        reloc.has_section = ""
                    type = str(reloc.type)
                    if reloc.architecture == MachO.CPU_TYPES.x86:
                        type = str(MachO.X86_RELOCATION(reloc.type))

                    if reloc.architecture == MachO.CPU_TYPES.x86_64:
                        type = str(MachO.X86_64_RELOCATION(reloc.type))

                    if reloc.architecture == MachO.CPU_TYPES.ARM:
                        type = str(MachO.ARM_RELOCATION(reloc.type))

                    if reloc.architecture == MachO.CPU_TYPES.ARM64:
                        type = str(MachO.ARM64_RELOCATION(reloc.type))

                    if reloc.architecture == MachO.CPU_TYPES.POWERPC:
                        type = str(MachO.PPC_RELOCATION(reloc.type))

                    rd = {
                        "id": idx,
                        "section": secname,
                        "name": name,
                        "address": reloc.address,
                        "relocation_type": type.split(".")[-1],
                        "size": reloc.size,
                        "pcrel": str(reloc.pc_relative),
                        "scat": str(reloc.is_scattered),
                    }
                    rl.append(rd)
                sd['relocations'] = rl
            sf = MachOSectionFact(parentObjects=[self.object_id],
                                  parentFacts=[self.fact_id],
                                  **sd)
            self.console.addFact(sf)
        return

    def get_symbols(self):
        symbols = self.macho.symbols
        if len(symbols) == 0:
            return
        for symbol in self.macho.symbols:
            libname = ""
            if symbol.has_binding_info and symbol.binding_info.has_library:
                libname = symbol.binding_info.library.name

            if symbol.value > 0 or not symbol.has_binding_info:
                symbol_value = symbol.value
            else:
                symbol_value = symbol.binding_info.address

            try:
                symbol_name = symbol.demangled_name
            except Exception:
                symbol_name = symbol.name
            sd = {
                "symbol_name":
                self.format_str.format(symbol_name),
                "symbol_type":
                self.format_hex.format(symbol.type),
                "number_of_sections":
                self.format_hex.format(symbol.numberof_sections),
                "description":
                self.format_str.format(symbol.description),
                "value":
                self.format_str.format(symbol_value),
                "library":
                self.format_str.format(libname),
            }
            sf = MachOSymbolFact(parentObjects=[self.object_id],
                                 parentFacts=[self.fact_id],
                                 **sd)
            self.console.addFact(sf)
        return

    def get_symbol_command(self):
        scmd = self.macho.symbol_command

        sd = {
            "symbol_offset": self.format_hex.format(scmd.symbol_offset),
            "number_of_symbols": self.format_dec.format(scmd.numberof_symbols),
            "string_offset": self.format_hex.format(scmd.strings_offset),
            "string_size": self.format_hex.format(scmd.strings_size),
        }
        sf = MachOSymbolCommandFact(parentObjects=[self.object_id],
                                    parentFacts=[self.fact_id],
                                    **sd)
        self.console.addFact(sf)
        return

    def get_dynamic_symbol_command(self):
        dyscmd = self.macho.dynamic_symbol_command

        sd = {
            "first_local_symbol_index":
            self.format_dec.format(dyscmd.idx_local_symbol),
            "number_of_local_symbols":
            self.format_dec.format(dyscmd.nb_local_symbols),
            "external_symbol_index":
            self.format_dec.format(dyscmd.idx_external_define_symbol),
            "number_of_external_symbols":
            self.format_dec.format(dyscmd.nb_external_define_symbols),
            "undefined_symbol_index":
            self.format_dec.format(dyscmd.idx_undefined_symbol),
            "number_of_undefined_symbols":
            self.format_dec.format(dyscmd.nb_undefined_symbols),
            "table_of_contents_offset":
            self.format_dec.format(dyscmd.toc_offset),
            "number_of_entries_in_toc":
            self.format_dec.format(dyscmd.nb_toc),
            "module_table_offset":
            self.format_hex.format(dyscmd.module_table_offset),
            "number_of_entries_in_module_table":
            self.format_dec.format(dyscmd.nb_module_table),
            "external_reference_table_offset":
            self.format_hex.format(dyscmd.external_reference_symbol_offset),
            "number_of_external_references":
            self.format_dec.format(dyscmd.nb_external_reference_symbols),
            "indirect_symbol_offset":
            self.format_hex.format(dyscmd.indirect_symbol_offset),
            "number_of_indirect_symbols":
            self.format_dec.format(dyscmd.nb_indirect_symbols),
            "external_relocation_offset":
            self.format_hex.format(dyscmd.external_relocation_offset),
            "number_of_external_relocations":
            self.format_dec.format(dyscmd.nb_external_relocations),
            "local_relocation_offset":
            self.format_hex.format(dyscmd.local_relocation_offset),
            "number_of_local_relocations":
            self.format_dec.format(dyscmd.nb_local_relocations),
        }
        sf = MachODynamicSymbolCommandFact(parentObjects=[self.object_id],
                                           parentFacts=[self.fact_id],
                                           **sd)
        self.console.addFact(sf)
        return

    def get_uuid(self):
        cmd = self.macho.uuid
        uuid_str = " ".join(map(lambda e: "{:02x}".format(e), cmd.uuid))
        ud = {
            "uuid": uuid_str,
        }
        uf = MachOUUIDFact(parentObjects=[self.object_id],
                           parentFacts=[self.fact_id],
                           **ud)
        self.console.addFact(uf)
        return

    def get_main_command(self):
        try:
            cmd = self.macho.main_command
        except Exception:
            return
        md = {
            "entrypoint": self.format_hex.format(cmd.entrypoint),
            "stack_size": self.format_hex.format(cmd.stack_size),
        }
        mf = MachOMainCommandFact(parentObjects=[self.object_id],
                                  parentFacts=[self.fact_id],
                                  **md)
        self.console.addFact(mf)
        return

    def get_thread_command(self):
        try:
            cmd = self.macho.thread_command
        except Exception:
            return
        td = {
            "flavor": self.format_hex.format(cmd.flavor),
            "count": self.format_hex.format(cmd.count),
            "pc": self.format_hex.format(cmd.pc),
        }
        tf = MachOThreadCommandFact(parentObjects=[self.object_id],
                                    parentFacts=[self.fact_id],
                                    **td)
        self.console.addFact(tf)
        return

    def get_rpath_command(self):
        try:
            cmd = self.macho.rpath
        except Exception:
            return
        rd = {
            "path": self.format_str.format(cmd.path),
        }
        rf = MachORPathCommandFact(parentObjects=[self.object_id],
                                   parentFacts=[self.fact_id],
                                   **rd)
        self.console.addFact(rf)
        return

    def get_dylinker(self):
        try:
            dd = {
                "path": self.format_str.format(self.macho.dylinker.name),
            }
        except Exception:
            return
        df = MachODylinkerFact(parentObjects=[self.object_id],
                               parentFacts=[self.fact_id],
                               **dd)
        self.console.addFact(df)
        return

    def get_function_starts(self):
        fstarts = self.macho.function_starts

        fd = {
            "offset": self.format_hex.format(fstarts.data_offset),
            "size": self.format_hex.format(fstarts.data_size),
        }
        fl = []
        for idx, address in enumerate(fstarts.functions):
            f = {
                "function_id": self.format_dec.format(idx),
                "address": self.format_hex.format(address),
            }
            fl.append(f)
        fd['functions'] = fl
        ff = MachOFunctionStartFact(parentObjects=[self.object_id],
                                    parentFacts=[self.fact_id],
                                    **fd)
        self.console.addFact(ff)
        return

    def get_data_in_code(self):
        try:
            datacode = self.macho.data_in_code
        except Exception:
            return

        dd = {
            "offset": self.format_hex.format(datacode.data_offset),
            "size": self.format_hex.format(datacode.data_size),
        }
        el = []
        for entry in datacode.entries:
            type_str = str(entry.type).split(".")[-1]
            ed = {
                "entry_type": type_str,
                "offset": self.format_hex.format(entry.offset),
                "length": self.format_dec.format(entry.length),
            }
            el.append(ed)
        dd['entries'] = el
        df = MachODataInCodeFact(parentObjects=[self.object_id],
                                 parentFacts=[self.fact_id],
                                 **dd)
        self.console.addFact(df)
        return

    def get_segment_split_info(self):
        try:
            sinfo = self.macho.segment_split_info
        except Exception:
            return
        sd = {
            "offset": self.format_hex.format(sinfo.data_offset),
            "size": self.format_hex.format(sinfo.data_size),
        }
        sf = MachOSegmentSplitInfoFact(parentObjects=[self.object_id],
                                       parentFacts=[self.fact_id],
                                       **sd)
        self.console.addFact(sf)
        return

    def get_sub_framework(self):
        try:
            sinfo = self.macho.sub_framework
        except Exception:
            return
        sd = {
            "umbrella": self.format_str.format(sinfo.umbrella),
        }
        sf = MachOSubFrameworkFact(parentObjects=[self.object_id],
                                   parentFacts=[self.fact_id],
                                   **sd)
        self.console.addFact(sf)
        return

    def get_dyld_environment(self):
        try:
            env = self.macho.dyld_environment
        except Exception:
            return
        dd = {
            "value": self.format_str.format(env.value),
        }
        df = MachODyldEnvironmentFact(parentObjects=[self.object_id],
                                      parentFacts=[self.fact_id],
                                      **dd)
        self.console.addFact(df)
        return

    def get_dyld_info(self):
        dyld_info = self.macho.dyld_info
        dd = {
            "rebase": {
                "offset": self.format_hex.format(dyld_info.rebase[0]),
                "size": self.format_hex.format(dyld_info.rebase[1]),
            },
            "bind": {
                "offset": self.format_hex.format(dyld_info.bind[0]),
                "size": self.format_hex.format(dyld_info.bind[1]),
            },
            "weak_bind": {
                "offset": self.format_hex.format(dyld_info.weak_bind[0]),
                "size": self.format_hex.format(dyld_info.weak_bind[1]),
            },
            "lazy_bind": {
                "offset": self.format_hex.format(dyld_info.lazy_bind[0]),
                "size": self.format_hex.format(dyld_info.lazy_bind[1]),
            },
            "export": {
                "offset": self.format_hex.format(dyld_info.export_info[0]),
                "size": self.format_hex.format(dyld_info.export_info[1]),
            },
        }
        bl = []
        for idx, binfo in enumerate(dyld_info.bindings):
            bd = {
                "class": str(binfo.binding_class).split(".")[-1],
                "binding_type": str(binfo.binding_type).split(".")[-1],
                "address": self.format_hex.format(binfo.address),
            }
            if binfo.has_symbol:
                bd['symbol'] = binfo.symbol.name

            if binfo.has_segment:
                bd['segment'] = binfo.segment.name

            if binfo.has_library:
                bd['library'] = binfo.library.name
            bl.append(bd)

        dd['bindings'] = bl
        el = []
        for idx, einfo in enumerate(dyld_info.exports):
            ed = {
                "address": self.format_hex.format(einfo.address),
                "export_name": einfo.symbol.name,
            }
            if einfo.alias:
                ed['alias'] = einfo.alias.name
                if einfo.alias_library:
                    ed['alias_library'] = einfo.alias_library.name
            el.append(ed)
        dd['exports'] = el
        df = MachODyldInfoFact(parentObjects=[self.object_id],
                               parentFacts=[self.fact_id],
                               **dd)
        self.console.addFact(df)
        return

    # NOT DONE YET
    def get_rebase_opcodes(self):
        # print("== Rebase opcodes ==")

        # print(self.macho.dyld_info.show_rebases_opcodes)
        return

    # NOT DONE YET
    def get_bind_opcodes(self):
        # print("== Bind opcodes ==")

        # print(self.macho.dyld_info.show_bind_opcodes)
        return

    # NOT DONE YET
    def get_weak_bind_opcodes(self):
        # print("== Weak bind opcodes ==")

        # print(self.macho.dyld_info.show_weak_bind_opcodes)
        return

    # NOT DONE YET
    def get_lazy_bind_opcodes(self):
        # print("== Lazy bind opcodes ==")

        # print(self.macho.dyld_info.show_lazy_bind_opcodes)
        return

    # NOT DONE YET
    def get_export_trie(self):
        # print("== Export trie ==")

        # print(self.macho.dyld_info.show_export_trie)
        return

    def get_source_version(self):
        try:
            version = self.macho.source_version.version
        except Exception:
            return
        sd = {
            "version": "{:d}.{:d}.{:d}.{:d}.{:d}".format(*version),
        }
        sf = MachOSourceVersionFact(parentObjects=[self.object_id],
                                    parentFacts=[self.fact_id],
                                    **sd)
        self.console.addFact(sf)
        return

    def get_version_min(self):
        try:
            version = self.macho.version_min.version
            sdk = self.macho.version_min.sdk
        except Exception:
            return
        sd = {
            "version": "{:d}.{:d}.{:d}".format(*version),
            "sdk": "{:d}.{:d}.{:d}".format(*sdk),
        }
        sf = MachOVersionMinFact(parentObjects=[self.object_id],
                                 parentFacts=[self.fact_id],
                                 **sd)
        self.console.addFact(sf)
        return

    def get_relocations(self):
        for reloc in self.macho.relocations:
            type_str = ""
            if reloc.origin == lief.MachO.RELOCATION_ORIGINS.DYLDINFO:
                type_str = str(lief.MachO.REBASE_TYPES(
                    reloc.type)).split(".")[-1]

            if reloc.origin == lief.MachO.RELOCATION_ORIGINS.RELOC_TABLE:
                if reloc.architecture == MachO.CPU_TYPES.x86:
                    type_str = str(MachO.X86_RELOCATION(reloc.type))

                if reloc.architecture == MachO.CPU_TYPES.x86_64:
                    type_str = str(MachO.X86_64_RELOCATION(reloc.type))

                if reloc.architecture == MachO.CPU_TYPES.ARM:
                    type_str = str(MachO.ARM_RELOCATION(reloc.type))

                if reloc.architecture == MachO.CPU_TYPES.ARM64:
                    type_str = str(MachO.ARM64_RELOCATION(reloc.type))

                if reloc.architecture == MachO.CPU_TYPES.POWERPC:
                    type_str = str(MachO.PPC_RELOCATION(reloc.type))

                type_str = type_str.split(".")[-1]

            symbol_name = ""
            if reloc.has_symbol:
                symbol_name = reloc.symbol.name

            secseg_name = ""
            if reloc.has_segment and reloc.has_section:
                secseg_name = "{}.{}".format(reloc.segment.name,
                                             reloc.section.name)
            else:
                if reloc.has_segment:
                    secseg_name = reloc.segment.name

                if reloc.has_section:
                    secseg_name = reloc.section.name

            rd = {
                "address": self.format_hex.format(reloc.address),
                "size": self.format_hex.format(reloc.size),
                "relocation_type": type_str,
                "pcrel": str(reloc.pc_relative),
                "secseg": secseg_name,
                "symbol": symbol_name,
            }
            rf = MachORelocationFact(parentObjects=[self.object_id],
                                     parentFacts=[self.fact_id],
                                     **rd)
            self.console.addFact(rf)
        return

    def get_encryption_info(self):
        try:
            cmd = self.macho.encryption_info
        except Exception:
            return
        ed = {
            "offset": self.format_hex.format(cmd.crypt_offset),
            "size": self.format_hex.format(cmd.crypt_size),
            "encryption_id": self.format_dec.format(cmd.crypt_id),
        }
        ef = MachOEncryptionInfoFact(parentObjects=[self.object_id],
                                     parentFacts=[self.fact_id],
                                     **ed)
        self.console.addFact(ef)
        return

    def get_ctor(self):
        for idx, f in enumerate(self.macho.ctor_functions):
            fd = {
                "function_id": self.format_dec.format(idx),
                "name": f.name,
                "address": self.format_hex.format(f.address),
            }
            ff = MachOCTORFact(parentObjects=[self.object_id],
                               parentFacts=[self.fact_id],
                               **fd)
            self.console.addFact(ff)
        return

    def get_unwind_functions(self):
        for idx, f in enumerate(self.macho.unwind_functions):
            fd = {
                "function_id": self.format_dec.format(idx),
                "name": f.name,
                "address": self.format_hex.format(f.address),
            }
            ff = MachOUnwindFunctionFact(parentObjects=[self.object_id],
                                         parentFacts=[self.fact_id],
                                         **fd)
            self.console.addFact(ff)
        return

    def get_functions(self):
        for idx, f in enumerate(self.macho.functions):
            fd = {
                "function_id": self.format_dec.format(idx),
                "name": f.name,
                "address": self.format_hex.format(f.address),
            }
            ff = MachOFunctionFact(parentObjects=[self.object_id],
                                   parentFacts=[self.fact_id],
                                   **fd)
            self.console.addFact(ff)
        return
