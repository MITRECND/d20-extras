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

# Code heavily influenced by the elf_reader example from the LIEF project:
# https://github.com/lief-project/LIEF/blob/master/examples/python/elf_reader.py
# NOTE:THIS IS VERY SLOW

from d20.Manual.Facts import (
    ELFFact, ELFHeaderFact, ELFSegmentFact, ELFDynamicEntryFact,
    ELFDynamicSymbolFact, ELFDynamicRelocationFact, ELFExportedSymbolFact,
    ELFImportedSymbolFact, ELFSectionFact, ELFStaticSymbolFact,
    ELFPLTGOTRelocationFact, ELFGNUHashFact, ELFSysvHashFact, ELFNoteFact,
    ELFConstructorFunctionFact, ELFFunctionFact, ELFObjectRelocationFact,
    ELFTelfhashFact)
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)

import lief
from lief import ELF
try:
    import telfhash
    TELFHASH_AVAILABLE = True
except ModuleNotFoundError:
    TELFHASH_AVAILABLE = False


@registerPlayer(
    name="ELFMeta",
    description=("Get ELF info on an object and add Facts to the table."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['mimetype'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False}),
        ("resolve_ordinals", {'type': bool, 'default': True}),
        ("ctor", {'type': bool, 'default': True}),
        ("exported_symbols", {'type': bool, 'default': True}),
        ("dynamic_entries", {'type': bool, 'default': True}),
        ("dynamic_symbols", {'type': bool, 'default': True}),
        ("functions", {'type': bool, 'default': True}),
        ("gnu_hash", {'type': bool, 'default': True}),
        ("header", {'type': bool, 'default': True}),
        ("imported_symbols", {'type': bool, 'default': True}),
        ("information", {'type': bool, 'default': True}),
        ("notes", {'type': bool, 'default': True}),
        ("relocations", {'type': bool, 'default': True}),
        ("sections", {'type': bool, 'default': True}),
        ("segments", {'type': bool, 'default': True}),
        ("static_symbols", {'type': bool, 'default': True}),
        ("sysv_hash", {'type': bool, 'default': True}),
        ("telfhash", {'type': bool, 'default': True})
    )
)
class ELFMetaPlayer(PlayerTemplate):

    interesting_mts = [
        'application/x-executable',
    ]
    filetype_search = [
        'ELF',
    ]

    fact_id = None
    lief = None
    obj = None
    object_id = None
    elf = None

    # Used for general formatting across the player
    format_str = "{}"
    format_hex = "0x{:x}"
    format_dec = "{:d}"

    def __init__(self, **kwargs):
        # PlayerTemplate registers the console as self.console
        super().__init__(**kwargs)
        self.disable = self.options.get("disable", False)
        self.resolve_ordinals = self.options.get("resolve_ordinals", True)
        self.ctor = self.options.get("ctor", True)
        self.exported_symbols = self.options.get("exported_symbols", True)
        self.dynamic_entries = self.options.get("dynamic_entries", True)
        self.dynamic_symbols = self.options.get("dynamic_symbols", True)
        self.functions = self.options.get("functions", True)
        self.gnu_hash = self.options.get("gnu_hash", True)
        self.header = self.options.get("header", True)
        self.imported_symbols = self.options.get("imported_symbols", True)
        self.information = self.options.get("information", True)
        self.notes = self.options.get("notes", True)
        self.relocations = self.options.get("relocations", True)
        self.sections = self.options.get("sections", True)
        self.segments = self.options.get("segments", True)
        self.static_symbols = self.options.get("static_symbols", True)
        self.sysv_hash = self.options.get("sysv_hash", True)
        self.telfhash = self.options.get("telfhash", True)

    def handleFact(self, **kwargs):
        if self.disable:
            return

        if 'fact' not in kwargs:
            raise RuntimeError("Expected 'fact' in arguments")

        factObj = kwargs['fact']
        if (factObj.mimetype not in self.interesting_mts
                and not any(f in factObj.filetype
                            for f in self.filetype_search)):
            return

        self.fact_id = factObj.id
        self.object_id = factObj.parentObjects[0]
        self.obj = self.console.getObject(self.object_id)

        # If we can't properly generate an ELF object, do nothing
        try:
            self.elf = lief.parse(self.obj.onDisk)
        except Exception as e:
            self.console.print(e)
            return

        # LIEF functions
        if self.ctor:
            self.get_ctor()
        if self.exported_symbols:
            self.get_exported_symbols()
        if self.dynamic_entries:
            self.get_dynamic_entries()
        if self.dynamic_symbols:
            self.get_dynamic_symbols()
        if self.functions:
            self.get_functions()
        if self.gnu_hash:
            self.get_gnu_hash()
        if self.header:
            self.get_header()
        if self.imported_symbols:
            self.get_imported_symbols()
        if self.information:
            self.get_information()
        if self.notes:
            self.get_notes()
        if self.relocations:
            self.get_all_relocations()
        if self.sections:
            self.get_sections()
        if self.segments:
            self.get_segments()
        if self.static_symbols:
            self.get_static_symbols()
        if self.sysv_hash:
            self.get_sysv_hash()
        if self.telfhash and TELFHASH_AVAILABLE:
            self.get_telfhash()

        return

    def get_information(self):
        infod = {
            "filename": self.format_str.format(self.elf.name),
            "address_base": self.format_hex.format(self.elf.imagebase),
            "virtual_size": self.format_hex.format(self.elf.virtual_size),
            "pie": self.format_str.format(str(self.elf.is_pie)),
            "nx": self.format_str.format(str(self.elf.has_nx)),
        }
        ef = ELFFact(parentObjects=[self.object_id],
                     parentFacts=[self.fact_id],
                     **infod)
        self.console.addFact(ef)
        return

    def get_header(self):
        header = self.elf.header
        identity = header.identity

        format_ide = "{:02x} {:<02x} {:<02x} {:<02x}"

        eflags_str = ""
        if header.machine_type == lief.ELF.ARCH.ARM:
            eflags_str = " - ".join(
                [str(s).split(".")[-1] for s in header.arm_flags_list])

        if header.machine_type in [
                lief.ELF.ARCH.MIPS, lief.ELF.ARCH.MIPS_RS3_LE,
                lief.ELF.ARCH.MIPS_X
        ]:
            eflags_str = " - ".join(
                [str(s).split(".")[-1] for s in header.mips_flags_list])

        if header.machine_type == lief.ELF.ARCH.PPC64:
            eflags_str = " - ".join(
                [str(s).split(".")[-1] for s in header.ppc64_flags_list])

        if header.machine_type == lief.ELF.ARCH.HEXAGON:
            eflags_str = " - ".join(
                [str(s).split(".")[-1] for s in header.hexagon_flags_list])

        hd = {
            "endianness":
            self.format_str.format(str(header.identity_data).split(".")[-1]),
            "entrypoint":
            self.format_hex.format(header.entrypoint),
            "filetype":
            self.format_str.format(str(header.file_type).split(".")[-1]),
            "header_size":
            self.format_dec.format(header.header_size),
            "identity_class":
            self.format_str.format(str(header.identity_class).split(".")[-1]),
            "machine_type":
            self.format_str.format(str(header.machine_type).split(".")[-1]),
            "magic":
            format_ide.format(identity[0], identity[1], identity[2],
                              identity[3]),
            "numberof_segments":
            self.format_dec.format(header.numberof_segments),
            "numberof_sections":
            self.format_dec.format(header.numberof_sections),
            "object_file_version":
            self.format_str.format(
                str(header.object_file_version).split(".")[-1]),
            "os_abi":
            self.format_str.format(str(header.identity_os_abi).split(".")[-1]),
            "processor_flags":
            self.format_hex.format(header.processor_flag) + eflags_str,
            "program_header_offset":
            self.format_hex.format(header.program_header_offset),
            "program_header_size":
            self.format_dec.format(header.program_header_size),
            "section_header_offset":
            self.format_hex.format(header.section_header_offset),
            "section_header_size":
            self.format_dec.format(header.section_header_size),
            "version":
            self.format_str.format(
                str(header.identity_version).split(".")[-1]),
        }
        hf = ELFHeaderFact(parentObjects=[self.object_id],
                           parentFacts=[self.fact_id],
                           **hd)
        self.console.addFact(hf)
        return

    def get_sections(self):
        if len(self.elf.sections) > 0:
            for section in self.elf.sections:
                segments_str = [
                    str(s.type).split(".")[-1] for s in section.segments
                ]
                sd = {
                    "name":
                    self.format_str.format(section.name),
                    "type":
                    str(section.type).split(".")[-1],
                    "virtual_address":
                    self.format_hex.format(section.virtual_address),
                    "file_offset":
                    self.format_hex.format(section.file_offset),
                    "size":
                    self.format_hex.format(section.size),
                    "entropy":
                    "{:f}".format(abs(section.entropy)),
                    "segments":
                    segments_str,
                }
                sf = ELFSectionFact(parentObjects=[self.object_id],
                                    parentFacts=[self.fact_id],
                                    **sd)
                self.console.addFact(sf)
        return

    def get_segments(self):
        # Segments
        if len(self.elf.segments) > 0:
            for segment in self.elf.segments:
                sections = segment.sections
                s = [section.name for section in sections]
                flags_str = ["-"] * 3
                if ELF.SEGMENT_FLAGS.R in segment:
                    flags_str[0] = "r"

                if ELF.SEGMENT_FLAGS.W in segment:
                    flags_str[1] = "w"

                if ELF.SEGMENT_FLAGS.X in segment:
                    flags_str[2] = "x"
                flags_str = "".join(flags_str)

                sd = {
                    "segment_type":
                    str(segment.type).split(".")[-1],
                    "flags":
                    flags_str,
                    "file_offset":
                    self.format_hex.format(segment.file_offset),
                    "virtual_address":
                    self.format_hex.format(segment.virtual_address),
                    "virtual_size":
                    self.format_hex.format(segment.virtual_size),
                    "size":
                    self.format_dec.format(segment.physical_size),
                    "sections":
                    s,
                }
                sf = ELFSegmentFact(parentObjects=[self.object_id],
                                    parentFacts=[self.fact_id],
                                    **sd)
                self.console.addFact(sf)
        return

    def get_dynamic_entries(self):
        if len(self.elf.dynamic_entries) == 0:
            return
        for entry in self.elf.dynamic_entries:
            if entry.tag == ELF.DYNAMIC_TAGS.NULL:
                continue
            ded = {
                "tag": str(entry.tag).split(".")[-1],
                "value": self.format_hex.format(entry.value),
            }
            if entry.tag in [
                    ELF.DYNAMIC_TAGS.SONAME, ELF.DYNAMIC_TAGS.NEEDED,
                    ELF.DYNAMIC_TAGS.RUNPATH, ELF.DYNAMIC_TAGS.RPATH
            ]:
                ded['info'] = [self.format_str.format(entry.name)]
            elif type(entry) is ELF.DynamicEntryArray:
                ded['info'] = list(map(hex, entry.array))
            elif entry.tag == ELF.DYNAMIC_TAGS.FLAGS:
                ded['info'] = [
                    str(ELF.DYNAMIC_FLAGS(s)).split(".")[-1]
                    for s in entry.flags
                ]
            elif entry.tag == ELF.DYNAMIC_TAGS.FLAGS_1:
                ded['info'] = [
                    str(ELF.DYNAMIC_FLAGS_1(s)).split(".")[-1]
                    for s in entry.flags
                ]
            else:
                ded['info'] = []
            deff = ELFDynamicEntryFact(parentObjects=[self.object_id],
                                       parentFacts=[self.fact_id],
                                       **ded)
            self.console.addFact(deff)
        return

    def _get_symbols(self, symbols, symbols_type=None):
        if symbols_type == "static":
            SYM_FACT = ELFStaticSymbolFact
        elif symbols_type == "dynamic":
            SYM_FACT = ELFDynamicSymbolFact
        elif symbols_type == "exported":
            SYM_FACT = ELFExportedSymbolFact
        elif symbols_type == "imported":
            SYM_FACT = ELFImportedSymbolFact
        else:
            return
        for symbol in symbols:
            if symbol.has_version:
                symbol_version = symbol.symbol_version
            else:
                symbol_version = ""
            import_export = ""

            if symbol.imported:
                import_export = "I"

            if symbol.exported:
                import_export = "E"

            try:
                symbol_name = symbol.demangled_name
            except Exception:
                symbol_name = symbol.name

            sd = {
                "name": symbol_name,
                "symbol_type": str(symbol.type).split(".")[-1],
                "value": self.format_hex.format(symbol.value),
                "visibility": str(symbol.visibility).split(".")[-1],
                "binding": str(symbol.binding).split(".")[-1],
                "import_export": import_export,
                "version": str(symbol_version),
            }
            sf = SYM_FACT(parentObjects=[self.object_id],
                          parentFacts=[self.fact_id],
                          **sd)
            self.console.addFact(sf)
        return

    def get_dynamic_symbols(self):
        self._get_symbols(self.elf.dynamic_symbols, "dynamic")
        return

    def get_static_symbols(self):
        self._get_symbols(self.elf.static_symbols, "static")
        return

    def get_exported_symbols(self):
        symbols = self.elf.exported_symbols
        if len(symbols) == 0:
            return
        self._get_symbols(symbols, "exported")

    def get_imported_symbols(self):
        symbols = self.elf.imported_symbols
        if len(symbols) == 0:
            return
        self._get_symbols(symbols, "imported")

    def _get_relocations(self, relocations, relocation_type=None):
        if relocation_type == "dynamic":
            REL_FACT = ELFDynamicRelocationFact
        elif relocation_type == "pltgot":
            REL_FACT = ELFPLTGOTRelocationFact
        elif relocation_type == "object":
            REL_FACT = ELFObjectRelocationFact
        else:
            return

        for relocation in relocations:
            type_ = str(relocation.type)
            if self.elf.header.machine_type == ELF.ARCH.x86_64:
                type_ = str(ELF.RELOCATION_X86_64(relocation.type))
            elif self.elf.header.machine_type == ELF.ARCH.i386:
                type_ = str(ELF.RELOCATION_i386(relocation.type))
            elif self.elf.header.machine_type == ELF.ARCH.ARM:
                type_ = str(ELF.RELOCATION_ARM(relocation.type))
            elif self.elf.header.machine_type == ELF.ARCH.AARCH64:
                type_ = str(ELF.RELOCATION_AARCH64(relocation.type))

            symbol_name = str(
                relocation.symbol.name) if relocation.has_symbol else ""

            rd = {
                "address": self.format_hex.format(relocation.address),
                "relocation_type": type_.split(".")[-1],
                "info": self.format_dec.format(relocation.info),
                "size": self.format_dec.format(relocation.size),
                "addend": self.format_hex.format(relocation.addend),
                "purpose": str(relocation.purpose).split(".")[-1],
                "symbol": symbol_name,
            }
            rf = REL_FACT(parentObjects=[self.object_id],
                          parentFacts=[self.fact_id],
                          **rd)
            self.console.addFact(rf)
        return

    def get_all_relocations(self):
        dynamicrelocations = self.elf.dynamic_relocations
        pltgot_relocations = self.elf.pltgot_relocations
        object_relocations = self.elf.object_relocations

        if len(dynamicrelocations) > 0:
            self._get_relocations(dynamicrelocations, "dynamic")

        if len(pltgot_relocations) > 0:
            self._get_relocations(pltgot_relocations, "pltgot")

        if len(object_relocations) > 0:
            self._get_relocations(object_relocations, "object")

    def get_gnu_hash(self):
        if not self.elf.use_gnu_hash:
            return

        gnu_hash = self.elf.gnu_hash

        gd = {
            "number_of_buckets": self.format_dec.format(gnu_hash.nb_buckets),
            "first_symbol_index":
            self.format_dec.format(gnu_hash.symbol_index),
            "shift_count": self.format_hex.format(gnu_hash.shift2),
            "bloom_filters": gnu_hash.bloom_filters,
            "buckets": gnu_hash.buckets,
            "hash_values": gnu_hash.hash_values,
        }
        gf = ELFGNUHashFact(parentObjects=[self.object_id],
                            parentFacts=[self.fact_id],
                            **gd)
        self.console.addFact(gf)
        return

    # NOT DONE YET
    def get_sysv_hash(self):
        if not self.elf.use_sysv_hash:
            return

        sysv_hash = self.elf.sysv_hash

        sd = {
            "number_of_buckets": self.format_dec.format(sysv_hash.nbucket),
            "number_of_chains": self.format_dec.format(sysv_hash.nchain),
            "buckets": sysv_hash.buckets,
            "chains": sysv_hash.chains,
        }
        sf = ELFSysvHashFact(parentObjects=[self.object_id],
                             parentFacts=[self.fact_id],
                             **sd)
        self.console.addFact(sf)
        return

    def get_notes(self):
        for idx, note in enumerate(self.elf.notes):
            description = note.description
            description_str = " ".join(
                map(lambda e: "{:02x}".format(e), description[:16]))

            nd = {
                "note_id":
                self.format_dec.format(idx),
                "name":
                self.format_str.format(note.name),
                "note_type":
                self.format_str.format(
                    str(ELF.NOTE_TYPES(note.type)).split(".")[-1]),
                "description":
                description_str,
            }

            if ELF.NOTE_TYPES(note.type) == ELF.NOTE_TYPES.ABI_TAG:

                note_details = note.details

                if type(note_details) == lief.ELF.AndroidNote:
                    nd['sdk_version'] = self.format_dec.format(
                        note_details.sdk_version)
                    nd['ndk_version'] = self.format_str.format(
                        note_details.ndk_version)
                    nd['ndk_build_number'] = self.format_str.format(
                        note_details.ndk_build_number)
                else:
                    version = note_details.version
                    version_str = "{:d}.{:d}.{:d}".format(
                        version[0], version[1], version[2])
                    nd['abi'] = self.format_str.format(
                        note_details.abi).split(".")[-1]
                    nd['version'] = self.format_str.format(version_str)

            if ELF.NOTE_TYPES(note.type) == ELF.NOTE_TYPES.GOLD_VERSION:
                nd['version'] = self.format_str.format("".join(
                    map(chr, note.description)))
            nf = ELFNoteFact(parentObjects=[self.object_id],
                             parentFacts=[self.fact_id],
                             **nd)
            self.console.addFact(nf)
        return

    def get_ctor(self):
        for idx, f in enumerate(self.elf.ctor_functions):
            fd = {
                "function_id": self.format_dec.format(idx),
                "name": self.format_str.format(f.name),
                "address": self.format_hex.format(f.address),
            }
            ff = ELFConstructorFunctionFact(parentObjects=[self.object_id],
                                            parentFacts=[self.fact_id],
                                            **fd)
            self.console.addFact(ff)

    def get_functions(self):
        for idx, f in enumerate(self.elf.functions):
            fd = {
                "function_id": self.format_dec.format(idx),
                "name": self.format_str.format(f.name),
                "address": self.format_hex.format(f.address),
            }
            ff = ELFFunctionFact(parentObjects=[self.object_id],
                                 parentFacts=[self.fact_id],
                                 **fd)
            self.console.addFact(ff)

    def get_telfhash(self):
        th = telfhash.telfhash(self.obj.onDisk)
        for t in th:
            tf = ELFTelfhashFact(parentObjects=[self.object_id],
                                 parentFacts=[self.fact_id],
                                 **t)
            self.console.addFact(tf)


#    Handled by the Strings NPC but saved here for reference
#    def get_strings(self):
#        print("== Strings ==\n")
#
#
#        strings = self.elf.strings
#        print("Strings: ({:d})".format(len(self.elf.strings)))
#        for s in strings:
#            print("    {}".format(s))
#
