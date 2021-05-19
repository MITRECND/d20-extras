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

# Code heavily influenced by the pe_reader example from the LIEF project:
# https://github.com/lief-project/LIEF/blob/master/examples/python/pe_reader.py

from d20.Manual.Facts import (
    PEFact, PEImpHashFact, PEDosHeaderFact, PEHeaderFact, PEOptionalHeaderFact,
    PEDataDirectoryFact, PESectionFact, PESymbolFact, PEImportFact, PETLSFact,
    PERelocationFact, PEExportFact, PEDebugFact, PESignatureFact,
    PERichHeaderFact, PEResourceFact, PELoadConfigurationFact,
    PEConstructorFunctionFact, PEExceptionFunctionFact, PEFunctionFact)
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)

from datetime import datetime

import hashlib
import json
import lief
import struct
import time

from functools import wraps
from lief import PE
from lief.PE import oid_to_string
from typing import Any, Dict


@registerPlayer(
    name="PEMeta",
    description=("Get PE info on an object and add Facts to the table."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['mimetype'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False}),
        ("resolve_ordinals", {'type': bool, 'default': True}),
        ("ctor", {'type': bool, 'default': True}),
        ("data_directories", {'type': bool, 'default': True}),
        ("debug", {'type': bool, 'default': True}),
        ("exception_functions", {'type': bool, 'default': True}),
        ("exports", {'type': bool, 'default': True}),
        ("functions", {'type': bool, 'default': True}),
        ("header", {'type': bool, 'default': True}),
        ("imports", {'type': bool, 'default': True}),
        ("information", {'type': bool, 'default': True}),
        ("resources", {'type': bool, 'default': True}),
        ("resource_data", {'type': bool, 'default': True}),
        ("load_configuration", {'type': bool, 'default': True}),
        ("relocations", {'type': bool, 'default': True}),
        ("rich_header", {'type': bool, 'default': True}),
        ("sections", {'type': bool, 'default': True}),
        ("section_data", {'type': bool, 'default': True}),
        ("signature", {'type': bool, 'default': True}),
        ("symbols", {'type': bool, 'default': True}),
        ("tls", {'type': bool, 'default': True})
    )
)
class PEMetaPlayer(PlayerTemplate):

    interesting_mts = [
        'application/x-dosexec',
    ]

    fact_id = None
    lief = None
    obj = None
    object_id = None
    pe = None
    pef: Dict[Any, Any] = {}

    # Used for general formatting across the player
    format_str = "{}"
    format_hex = "0x{:x}"
    format_dec = "{:d}"
    format_time = "%Y-%m-%d %H:%M:%S %Z"

    def __init__(self, **kwargs):
        # PlayerTemplate registers the console as self.console
        super().__init__(**kwargs)
        self.disable = self.options.get("disable", False)
        self.resolve_ordinals = self.options.get("resolve_ordinals", True)
        self.ctor = self.options.get("ctor", True)
        self.data_directories = self.options.get("data_directories", True)
        self.debug = self.options.get("debug", True)
        self.exception_functions = self.options.get("exception_functions",
                                                    True)
        self.exports = self.options.get("exports", True)
        self.functions = self.options.get("functions", True)
        self.header = self.options.get("header", True)
        self.imports = self.options.get("imports", True)
        self.information = self.options.get("information", True)
        self.resources = self.options.get("resources", True)
        self.resource_data = self.options.get("resource_data", True)
        self.load_configuration = self.options.get("load_configuration", True)
        self.relocations = self.options.get("relocations", True)
        self.rich_header = self.options.get("rich_header", True)
        self.sections = self.options.get("sections", True)
        self.section_data = self.options.get("section_data", True)
        self.signature = self.options.get("signature", True)
        self.symbols = self.options.get("symbols", True)
        self.tls = self.options.get("tls", True)

    def timing(f):
        """
            You can add @timing as a decorator to any method in this class to
            output execution time for tracking slowness.
        """

        @wraps(f)
        def wrapper(*args, **kwargs):
            start = datetime.now()
            result = f(*args, **kwargs)
            end = datetime.now()
            delta = end - start
            print('{} time: {:06.7f}'.format(f.__name__,
                                             delta.total_seconds()))
            return result

        return wrapper

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

        # If we can't properly generate a PE object, do nothing
        try:
            self.pe = lief.parse(self.obj.onDisk)
        except Exception as e:
            self.console.print(e)
            return

        if self.pe:
            # LIEF functions
            if self.ctor:
                self.get_ctor()
            if self.data_directories:
                self.get_data_directories()
            if self.debug:
                self.get_debug()
            if self.exception_functions:
                self.get_exception_functions()
            if self.exports:
                self.get_exports()
            if self.functions:
                self.get_functions()
            if self.header:
                self.get_header()
            if self.imports:
                self.get_imports()
            if self.information:
                self.get_information()
            if self.resources:
                self.get_resources()
            if self.load_configuration:
                self.get_load_configuration()
            if self.relocations:
                self.get_relocations()
            if self.rich_header:
                self.get_rich_header()
            if self.sections:
                self.get_sections()
            if self.signature:
                self.get_signature()
            if self.symbols:
                self.get_symbols()
            if self.tls:
                self.get_tls()

        return

    def get_information(self):
        infod = {
            'filename':
            self.format_str.format(self.pe.name),
            'file_format':
            self.format_str.format(str(self.pe.format).split(".")[-1]),
            'virtual_size':
            self.format_hex.format(self.pe.virtual_size),
            'pie':
            self.format_str.format(str(self.pe.is_pie)),
            'nx':
            self.format_str.format(str(self.pe.has_nx)),
        }
        ih = {
            'value': self.format_str.format(PE.get_imphash(self.pe)),
        }
        peff = PEFact(parentObjects=[self.object_id],
                      parentFacts=[self.fact_id],
                      **infod)
        self.console.addFact(peff)
        ihf = PEImpHashFact(parentObjects=[self.object_id],
                            parentFacts=[self.fact_id],
                            **ih)
        self.console.addFact(ihf)

    def get_header(self):
        dos_header = self.pe.dos_header
        header = self.pe.header
        optional_header = self.pe.optional_header

        dhd = {
            "addressof_new_exeheader":
            self.format_hex.format(dos_header.addressof_new_exeheader),
            "addressof_relocation_table":
            self.format_hex.format(dos_header.addressof_relocation_table),
            "checksum":
            self.format_hex.format(dos_header.checksum),
            "file_size_in_pages":
            self.format_dec.format(dos_header.file_size_in_pages),
            "header_size_in_paragraphs":
            self.format_dec.format(dos_header.header_size_in_paragraphs),
            "initial_ip":
            self.format_dec.format(dos_header.initial_ip),
            "initial_relative_cs":
            self.format_dec.format(dos_header.initial_relative_cs),
            "initial_relative_ss":
            self.format_dec.format(dos_header.initial_relative_ss),
            "initial_sp":
            self.format_hex.format(dos_header.initial_sp),
            "magic":
            self.format_str.format(str((dos_header.magic))),
            "maximum_extra_paragraphs":
            self.format_dec.format(dos_header.maximum_extra_paragraphs),
            "minimum_extra_paragraphs":
            self.format_dec.format(dos_header.minimum_extra_paragraphs),
            "numberof_relocation":
            self.format_dec.format(dos_header.numberof_relocation),
            "oem_id":
            self.format_dec.format(dos_header.oem_id),
            "oem_info":
            self.format_dec.format(dos_header.oem_info),
            "overlay_number":
            self.format_dec.format(dos_header.overlay_number),
            "used_bytes_in_the_last_page":
            self.format_dec.format(dos_header.used_bytes_in_the_last_page),
        }
        dhf = PEDosHeaderFact(parentObjects=[self.object_id],
                              parentFacts=[self.fact_id],
                              **dhd)
        self.console.addFact(dhf)

        char_str = " - ".join([
            str(chara).split(".")[-1] for chara in header.characteristics_list
        ])

        hd = {
            "characteristics":
            self.format_str.format(char_str),
            "machine":
            self.format_str.format(str(header.machine).split(".")[-1]),
            "numberof_sections":
            self.format_dec.format(header.numberof_sections),
            "numberof_symbols":
            self.format_dec.format(header.numberof_symbols),
            "pointerto_symbol_table":
            self.format_dec.format(header.pointerto_symbol_table),
            "signature":
            self.format_str.format("".join(map(chr, header.signature))),
            "sizeof_optional_header":
            self.format_dec.format(header.sizeof_optional_header),
            "time_date_stamps":
            self.format_dec.format(header.time_date_stamps),
        }
        hf = PEHeaderFact(parentObjects=[self.object_id],
                          parentFacts=[self.fact_id],
                          **hd)
        self.console.addFact(hf)

        dll_char_str = " - ".join([
            str(chara).split(".")[-1]
            for chara in optional_header.dll_characteristics_lists
        ])
        subsystem_str = str(optional_header.subsystem).split(".")[-1]
        magic = "PE32" if optional_header.magic == PE.PE_TYPE.PE32 else "PE64"

        ohd = {
            "addressof_entrypoint":
            self.format_hex.format(optional_header.addressof_entrypoint),
            "baseof_code":
            self.format_hex.format(optional_header.baseof_code),
            "checksum":
            self.format_hex.format(optional_header.checksum),
            "dll_characteristics":
            self.format_str.format(dll_char_str),
            "file_alignment":
            self.format_hex.format(optional_header.file_alignment),
            "imagebase":
            self.format_hex.format(optional_header.imagebase),
            "loader_flags":
            self.format_dec.format(optional_header.loader_flags),
            "magic":
            self.format_str.format(magic),
            "major_image_version":
            self.format_dec.format(optional_header.major_image_version),
            "major_linker_version":
            self.format_dec.format(optional_header.major_linker_version),
            "major_operating_system_version":
            self.format_dec.format(
                optional_header.major_operating_system_version),
            "major_subsystem_version":
            self.format_dec.format(optional_header.major_subsystem_version),
            "minor_image_version":
            self.format_dec.format(optional_header.minor_image_version),
            "minor_linker_version":
            self.format_dec.format(optional_header.minor_linker_version),
            "minor_operating_system_version":
            self.format_dec.format(
                optional_header.minor_operating_system_version),
            "minor_subsystem_version":
            self.format_dec.format(optional_header.minor_subsystem_version),
            "numberof_rva_and_size":
            self.format_dec.format(optional_header.numberof_rva_and_size),
            "section_alignment":
            self.format_hex.format(optional_header.section_alignment),
            "sizeof_code":
            self.format_dec.format(optional_header.sizeof_code),
            "sizeof_headers":
            self.format_hex.format(optional_header.sizeof_headers),
            "sizeof_heap_commit":
            self.format_hex.format(optional_header.sizeof_heap_commit),
            "sizeof_heap_reserve":
            self.format_hex.format(optional_header.sizeof_heap_reserve),
            "sizeof_image":
            self.format_hex.format(optional_header.sizeof_image),
            "sizeof_initialized_data":
            self.format_dec.format(optional_header.sizeof_initialized_data),
            "sizeof_stack_commit":
            self.format_hex.format(optional_header.sizeof_stack_commit),
            "sizeof_stack_reserve":
            self.format_hex.format(optional_header.sizeof_stack_reserve),
            "sizeof_uninitialized_data":
            self.format_dec.format(optional_header.sizeof_uninitialized_data),
            "subsystem":
            self.format_str.format(subsystem_str),
            "win32_version_value":
            self.format_dec.format(optional_header.win32_version_value),
        }
        if magic == "PE32":
            ohd['baseof_data'] = self.format_hex.format(
                optional_header.baseof_data)
        ohf = PEOptionalHeaderFact(parentObjects=[self.object_id],
                                   parentFacts=[self.fact_id],
                                   **ohd)
        self.console.addFact(ohf)

    def get_data_directories(self):
        for directory in self.pe.data_directories:
            if directory.has_section:
                section_name = directory.section.name
            else:
                section_name = ""
            ddd = {
                "type": str(directory.type).split('.')[-1],  # {:<24}
                "rva": "0x{:x}".format(directory.rva),
                "size": "0x{:x}".format(directory.size),
                "section": section_name,  # {:<8}
            }
            ddf = PEDataDirectoryFact(parentObjects=[self.object_id],
                                      parentFacts=[self.fact_id],
                                      **ddd)
            self.console.addFact(ddf)

    def get_sections(self):
        for section in self.pe.sections:
            flags = ""
            for flag in section.characteristics_lists:
                flags += str(flag).split(".")[-1] + " "
            sd = {
                "entropy": "{:f}".format(section.entropy),
                "flags": flags,
                "name": section.name,
                "offset": self.format_hex.format(section.offset),
                "size": self.format_hex.format(section.size),
                "virtual_address":
                self.format_hex.format(section.virtual_address),
                "virtual_size": self.format_hex.format(section.virtual_size),
            }

            sf = PESectionFact(parentObjects=[self.object_id],
                               parentFacts=[self.fact_id],
                               **sd)
            self.console.addFact(sf)

            if self.section_data:
                section_data = self.obj.data[section.offset:section.offset +
                                             section.size]
                self.console.addObject(section_data,
                                       metadata={'filename': section.name},
                                       parentObjects=[self.object_id],
                                       parentFacts=[self.fact_id, sf.id],)

    def get_symbols(self):
        if len(self.pe.symbols) > 0:
            for symbol in self.pe.symbols:
                section_nb_str = ""
                if symbol.section_number <= 0:
                    section_nb_str = str(
                        PE.SYMBOL_SECTION_NUMBER(
                            symbol.section_number)).split(".")[-1]
                else:
                    try:
                        section_nb_str = symbol.section.name
                    except Exception:
                        section_nb_str = "section<{:d}>".format(
                            symbol.section_number)
                try:
                    symbol_name = symbol.name[:20]
                except UnicodeDecodeError:
                    self.console.print("Error getting PE symbol name")
                    symbol_name = ""

                sd = {
                    "name": symbol_name,
                    "value": self.format_hex.format(symbol.value),
                    "section_number": section_nb_str,
                    "basic_type": str(symbol.base_type).split(".")[-1],
                    "complex_type": str(symbol.complex_type).split(".")[-1],
                    "storage_class": str(symbol.storage_class).split(".")[-1],
                }
                sf = PESymbolFact(parentObjects=[self.object_id],
                                  parentFacts=[self.fact_id],
                                  **sd)
                self.console.addFact(sf)
        else:
            self.console.print("No symbols found!")

    def get_imports(self):
        for import_ in self.pe.imports:
            if self.resolve_ordinals:
                import_ = lief.PE.resolve_ordinals(import_)
            for entry in import_.entries:
                imd = {
                    "dll": import_.name,
                    "name": entry.name,
                    "data": self.format_hex.format(entry.data),
                    "iat": self.format_hex.format(entry.iat_value),
                    "hint": self.format_hex.format(entry.hint),
                }
                imf = PEImportFact(parentObjects=[self.object_id],
                                   parentFacts=[self.fact_id],
                                   **imd)
                self.console.addFact(imf)

    def get_tls(self):
        tls = self.pe.tls
        callbacks = tls.callbacks
        ard = "0x{:x} 0x{:x}".format(
            tls.addressof_raw_data[0],
            tls.addressof_raw_data[1],
        )
        tlsd = {
            "addressof_callbacks":
            self.format_hex.format(tls.addressof_callbacks),
            "addressof_index": self.format_hex.format(tls.addressof_index),
            "addressof_raw_data": ard,
            "callbacks": [hex(c) for c in callbacks],
            "characteristics": self.format_hex.format(tls.characteristics),
            "sizeof_raw_data": self.format_hex.format(len(tls.data_template)),
            "sizeof_zero_fill": self.format_hex.format(tls.sizeof_zero_fill),
        }

        try:
            tlsd['data_directory'] = self.format_str.format(
                str(tls.directory.type).split('.')[1])
        except Exception as e:
            self.console.print(e)
            tlsd['data_directory'] = "None"
        try:
            tlsd['section'] = self.format_str.format(str(tls.section.name))
        except Exception as e:
            self.console.print(e)
            tlsd['section'] = "None"

        tlsf = PETLSFact(parentObjects=[self.object_id],
                         parentFacts=[self.fact_id],
                         **tlsd)
        self.console.addFact(tlsf)

    def get_relocations(self):
        for relocation in self.pe.relocations:
            virtual_address = hex(relocation.virtual_address)
            entries = relocation.entries
            for entry in entries:
                rd = {
                    "entry_position": self.format_hex.format(entry.position),
                    "entry_type": str(entry.type).split(".")[-1],
                    "virtual_address": virtual_address,
                }
                rf = PERelocationFact(parentObjects=[self.object_id],
                                      parentFacts=[self.fact_id],
                                      **rd)
                self.console.addFact(rf)

    def get_exports(self):
        exports = self.pe.get_export()
        entries = exports.entries
        ed = {
            "flags": self.format_hex.format(exports.export_flags),
            "major_version": self.format_dec.format(exports.major_version),
            "minor_version": self.format_dec.format(exports.minor_version),
            "name": exports.name,
            "ordinal_base": self.format_hex.format(exports.ordinal_base),
            "timestamp": self.format_hex.format(exports.timestamp),
        }
        entries = sorted(entries, key=lambda e: e.ordinal)
        el = []
        for entry in entries:
            extern = "True" if entry.is_extern else "False"
            end = {
                "address": self.format_hex.format(entry.address),
                "extern": extern,
                "name": entry.name,
                "ordinal": self.format_hex.format(entry.ordinal),
            }
            el.append(end)
        ed['entries'] = el
        ef = PEExportFact(parentObjects=[self.object_id],
                          parentFacts=[self.fact_id],
                          **ed)
        self.console.addFact(ef)

    def get_debug(self):
        debug_list = self.pe.debug
        for debug in debug_list:
            dd = {
                "characteristics":
                self.format_hex.format(debug.characteristics),
                "timestamp": time.strftime(self.format_time,
                                           time.gmtime(debug.timestamp)),
                "major_version":
                self.format_dec.format(debug.major_version),
                "minor_version":
                self.format_dec.format(debug.minor_version),
                "debug_type":
                str(debug.type).split(".")[-1],
                "sizeof_data":
                self.format_hex.format(debug.sizeof_data),
                "addressof_raw_data":
                self.format_hex.format(debug.addressof_rawdata),
                "pointerto_raw_data":
                self.format_hex.format(debug.pointerto_rawdata),
            }

            if debug.has_code_view:
                code_view = debug.code_view
                cv_signature = code_view.cv_signature

                if cv_signature in (lief.PE.CODE_VIEW_SIGNATURES.PDB_70,
                                    lief.PE.CODE_VIEW_SIGNATURES.PDB_70):
                    sig_str_l = list(
                        map(lambda e: "{:02x}".format(e),
                            code_view.signature))
                    sig_str = " ".join(sig_str_l)
                    dd['code_view_signature'] = self.format_str.format(
                        str(cv_signature).split(".")[-1])
                    dd['signature'] = self.format_str.format(sig_str)
                    dd['age'] = self.format_dec.format(code_view.age)
                    dd['filename'] = self.format_str.format(code_view.filename)

                    # Generate PDB GUID
                    # https://docs.microsoft.com/en-us/previous-versions/aa373931(v%3Dvs.80)
                    guid = '{{{0}-{1}-{2}-{3}-{4}}}'.format(
                        ''.join(reversed(sig_str_l[0:4])),
                        ''.join(reversed(sig_str_l[4:6])),
                        ''.join(reversed(sig_str_l[6:8])),
                        ''.join(reversed(sig_str_l[8:10])),
                        ''.join(sig_str_l[10:]),
                    )
                    dd['guid'] = guid

            if debug.has_pogo:
                pogo = debug.pogo
                pd = {
                    "signature":
                    self.format_str.format(str(pogo.signature).split(".")[-1]),
                }
                el = []
                for e in pogo.entries:
                    ed = {
                        "name": e.name,
                        "size": e.size,
                        "start_rva": e.start_rva,
                    }
                    el.append(ed)
                pd['entries'] = el
                dd['pogo'] = pd

            df = PEDebugFact(parentObjects=[self.object_id],
                             parentFacts=[self.fact_id],
                             **dd)
            self.console.addFact(df)

    def get_signature(self):
        try:
            signatures = self.pe.signatures
        except Exception:
            return
        for signature in signatures:
            sd = {
                "digest_algorithm": self.format_str.format(
                    oid_to_string(signature.digest_algorithm)),
                "version":
                self.format_dec.format(signature.version),
            }
            content_info = signature.content_info
            cid = {
                "content_type": self.format_str.format(
                    oid_to_string(content_info.content_type)),
                "digest_algorithm":
                self.format_str.format(oid_to_string(
                    content_info.digest_algorithm)),
                "type":
                self.format_str.format(oid_to_string(content_info.type)),
            }
            sd['content_information'] = cid

            cl = []
            for crt in signature.certificates:
                sn_str = ":".join(
                    map(lambda e: "{:02x}".format(e), crt.serial_number))
                valid_from_str = "-".join(map(
                    str, crt.valid_from[:3])) + " " + ":".join(
                        map(str, crt.valid_from[3:]))
                valid_to_str = "-".join(map(str, crt.valid_to[:3])) + " " + ":".join(map(str, crt.valid_to[3:]))  # noqa: E501
                cd = {
                    "issuer": self.format_str.format(crt.issuer),
                    "serial_number": self.format_str.format(sn_str),
                    "signature_algorithm": self.format_str.format(
                        oid_to_string(crt.signature_algorithm)),
                    "subject": self.format_str.format(crt.subject),
                    "valid_from": self.format_str.format(valid_from_str),
                    "valid_to": self.format_str.format(valid_to_str),
                    "version": self.format_dec.format(crt.version),
                }
                cl.append(cd)

            sd['certificates'] = cl

            signer_info = signature.signer_info

            try:
                issuer_str = " ".join(
                    map(lambda e: oid_to_string(e[0]) + " = " + e[1], signer_info.issuer[0]))  # noqa: E501
            except IndexError as e:
                self.console.print(e)
                issuer_str = ""

            sid = {
                "digest_algorithm":
                self.format_str.format(oid_to_string(
                    signer_info.digest_algorithm)),
                "issuer":
                self.format_str.format(issuer_str),
                "program_name":
                self.format_str.format(
                    signer_info.authenticated_attributes.program_name),
                "signature_algorithm":
                self.format_str.format(
                    oid_to_string(signer_info.signature_algorithm)),
                "url":
                self.format_str.format(
                    signer_info.authenticated_attributes.more_info),
                "version":
                self.format_dec.format(signer_info.version),
            }
            sd['signer_information'] = sid
            sf = PESignatureFact(parentObjects=[self.object_id],
                                 parentFacts=[self.fact_id],
                                 **sd)
            self.console.addFact(sf)

    def get_rich_header(self):
        rhd = {"key": self.format_hex.format(self.pe.rich_header.key)}
        el = []
        for entry in self.pe.rich_header.entries:
            ed = {
                "build_id": self.format_hex.format(entry.build_id),
                "count": self.format_dec.format(entry.count),
                "id": self.format_hex.format(entry.id),
            }
            el.append(ed)
        rhd['entries'] = el

        # Compute Rich Hash and Rich PV
        # Adopted from:
        # https://digital-forensics.sans.org/community/papers/grem/
        # leveraging-pe-rich-header-static-alware-etection-linking_6321
        # TODO: is there a cleaner way to do this with LIEF?
        rich_data = self.obj.data[0x80:]
        str_str = "<{0}I".format(str(int(len(rich_data) / 4)))
        try:
            data = list(struct.unpack(str_str, rich_data))
            checksum = data[1]
            # This is the Rich Header End marker
            rich_end = data.index(0x68636952)
        except Exception:
            self.console.print("Cannot find end of Rich Header")
            return
        rich_hasher = hashlib.md5()
        for i in range(rich_end):
            rich_hasher.update(struct.pack('<I', (data[i] ^ checksum)))
        rich_hash = rich_hasher.hexdigest()
        rhd['rich_hash'] = rich_hash
        rich_pver = hashlib.md5()
        for i in range(rich_end):
            if i > 3:
                if i % 2:
                    continue
                else:
                    rich_pver.update(struct.pack('<I', (data[i] ^ checksum)))
        rich_pv = rich_pver.hexdigest()
        rhd['rich_pv'] = rich_pv

        rf = PERichHeaderFact(parentObjects=[self.object_id],
                              parentFacts=[self.fact_id],
                              **rhd)
        self.console.addFact(rf)

    def get_resources(self):
        try:
            manager = self.pe.resources_manager
        except Exception:
            # Usually happens because there are no resources in the binary.
            return
        rmd = {}
        if manager.has_dialogs:
            rmd['dialogs'] = [
                json.loads(lief.to_json(x)) for x in manager.dialogs
            ]
        # if manager.has_icons:
        #   rmd['icons'] = [
        #       json.loads(lief.to_json(x)) for x in manager.icons
        #   ]
        if manager.has_manifest:
            rmd['manifest'] = manager.manifest
        if manager.has_type:
            rmd['type'] = [
                str(x).split(".")[-1] for x in manager.types_available
            ]
        if manager.has_version:
            vd = {}
            try:
                vd["key"] = manager.version.key
                vd["type"] = manager.version.type

                if manager.version.has_fixed_file_info:
                    ffi = manager.version.fixed_file_info
                    vd["fixed_file_info"] = json.loads(lief.to_json(ffi))
                if manager.version.has_var_file_info:
                    vfi = manager.version.var_file_info
                    vd["var_file_info"] = json.loads(lief.to_json(vfi))
                if manager.version.has_string_file_info:
                    # NOTE: This is currently horribly formatted. See:
                    # https://github.com/lief-project/LIEF/issues/256
                    # Looks to be fixed but not in a release yet.
                    sfi = manager.version.string_file_info
                    vd["string_file_info"] = json.loads(lief.to_json(sfi))
            except lief.read_out_of_bound:
                self.console.print("Out of bound error for resource!")
            rmd['version'] = vd
        rmd['languages'] = [
            str(x).split(".")[-1] for x in manager.langs_available
        ]
        rmd['sub_languages'] = [
            str(x).split(".")[-1] for x in manager.sublangs_available
        ]
        rf = PEResourceFact(parentObjects=[self.object_id],
                            parentFacts=[self.fact_id],
                            **rmd)

        self.console.addFact(rf)

        if self.resource_data and self.pe.has_resources:
            for res_dir in self.pe.resources.childs:
                for res_data in res_dir.childs:
                    res_id = res_data.id
                    for r in res_data.childs:
                        raw_res_data = bytes(r.content)
                        self.console.addObject(raw_res_data, metadata={
                                               'filename':
                                               '{}_resource_{}'.format(
                                                    self.obj.metadata.get(
                                                        'filename',
                                                        self.object_id),
                                                    hex(res_id))
                                               },
                                               parentObjects=[self.object_id],
                                               parentFacts=[self.fact_id,
                                                            rf.id],)

    def get_load_configuration(self):
        try:
            config = self.pe.load_configuration
        except Exception as e:
            # Usually because the PE doesn't have a load configuration
            self.console.print(e)
            return
        lcd = {
            "characteristics":
            self.format_dec.format(config.characteristics),
            "critical_section_default_timeout":
            self.format_dec.format(config.critical_section_default_timeout),
            "csd_version":
            self.format_hex.format(config.csd_version),
            "decommit_free_block_threshold":
            self.format_hex.format(config.decommit_free_block_threshold),
            "decommit_total_free_threshold":
            self.format_hex.format(config.decommit_total_free_threshold),
            "editlist":
            self.format_hex.format(config.editlist),
            "global_flags_clear":
            self.format_hex.format(config.global_flags_clear),
            "global_flags_set":
            self.format_hex.format(config.global_flags_set),
            "lock_prefix_table":
            self.format_hex.format(config.lock_prefix_table),
            "major_version":
            self.format_dec.format(config.major_version),
            "maximum_allocation_size":
            self.format_hex.format(config.maximum_allocation_size),
            "minor_version":
            self.format_dec.format(config.minor_version),
            "process_affinity_mask":
            self.format_hex.format(config.process_affinity_mask),
            "process_heap_flags":
            self.format_hex.format(config.process_heap_flags),
            "reserved1":
            self.format_hex.format(config.reserved1),
            "security_cookie":
            self.format_hex.format(config.security_cookie),
            "timedatestamp":
            self.format_dec.format(config.timedatestamp),
            "version":
            self.format_str.format(str(config.version).split(".")[-1]),
            "virtual_memory_threshold":
            self.format_hex.format(config.virtual_memory_threshold),
        }

        if isinstance(config, lief.PE.LoadConfigurationV0):
            lcd['se_handler_count'] = self.format_dec.format(
                config.se_handler_count)
            lcd['se_handler_table'] = self.format_hex.format(
                config.se_handler_table)

        if isinstance(config, lief.PE.LoadConfigurationV1):
            flags_str = " - ".join(
                map(lambda e: str(e).split(".")[-1],
                    config.guard_cf_flags_list))
            lcd['gcf_check_function_pointer'] = self.format_hex.format(
                config.guard_cf_check_function_pointer)
            lcd['gcf_dispatch_function_pointer'] = self.format_hex.format(
                config.guard_cf_dispatch_function_pointer)
            lcd['gcf_function_table'] = self.format_hex.format(
                config.guard_cf_function_table)
            lcd['gcf_function_count'] = self.format_dec.format(
                config.guard_cf_function_count)
            lcd['guard_flags'] = "{} (0x{:x})".format(flags_str,
                                                      int(config.guard_flags))

        if isinstance(config, lief.PE.LoadConfigurationV2):
            code_integrity = config.code_integrity
            cid = {
                "flags":
                self.format_dec.format(code_integrity.flags),
                "catalog":
                self.format_dec.format(code_integrity.catalog),
                "catalog_offset":
                self.format_hex.format(code_integrity.catalog_offset),
                "reserved":
                self.format_dec.format(code_integrity.reserved),
            }
            lcd['code_integrity'] = cid

        if isinstance(config, lief.PE.LoadConfigurationV3):
            lcd['guard_address_taken_iat_entry_count'] = self.format_hex.format(  # noqa: E501
                config.guard_address_taken_iat_entry_count)
            lcd['guard_address_taken_iat_entry_table'] = self.format_hex.format(  # noqa: E501
                config.guard_address_taken_iat_entry_table)
            lcd['guard_long_jump_target_count'] = self.format_hex.format(
                config.guard_long_jump_target_count)
            lcd['guard_long_jump_target_table'] = self.format_hex.format(
                config.guard_long_jump_target_table)

        if isinstance(config, lief.PE.LoadConfigurationV4):
            lcd['dynamic_value_reloc_table'] = self.format_hex.format(
                config.dynamic_value_reloc_table)
            lcd['hybrid_metadata_pointer'] = self.format_hex.format(
                config.hybrid_metadata_pointer)

        if isinstance(config, lief.PE.LoadConfigurationV5):
            lcd['dynamic_value_reloc_table_offset'] = self.format_hex.format(
                config.dynamic_value_reloctable_offset)
            lcd['dynamic_value_reloc_table_section'] = self.format_hex.format(
                config.dynamic_value_reloctable_section)
            lcd['grf_failure_routine'] = self.format_hex.format(
                config.guard_rf_failure_routine)
            lcd['grf_failure_routine_function_pointer'] = self.format_hex.format(  # noqa: E501
                config.guard_rf_failure_routine_function_pointer)

        if isinstance(config, lief.PE.LoadConfigurationV6):
            lcd['grf_verify_stackpointer_function_pointer'] = self.format_hex.format(  # noqa: E501
                config.guard_rf_verify_stackpointer_function_pointer)
            lcd['hotpatch_table_offset'] = self.format_hex.format(
                config.hotpatch_table_offset)

        if isinstance(config, lief.PE.LoadConfigurationV7):
            lcd['reserved3'] = self.format_hex.format(config.reserved3)

        lcf = PELoadConfigurationFact(parentObjects=[self.object_id],
                                      parentFacts=[self.fact_id],
                                      **lcd)
        self.console.addFact(lcf)

    def get_ctor(self):
        try:
            for idx, f in enumerate(self.pe.ctor_functions):
                cd = {
                    "address": self.format_hex.format(f.address),
                    "idx": self.format_dec.format(idx),
                    "name": self.format_str.format(f.name),
                }
                cf = PEConstructorFunctionFact(parentObjects=[self.object_id],
                                               parentFacts=[self.fact_id],
                                               **cd)
                self.console.addFact(cf)
        except Exception:
            return

    def get_exception_functions(self):
        try:
            for idx, f in enumerate(self.pe.exception_functions):
                ed = {
                    "address": self.format_hex.format(f.address),
                    "idx": self.format_dec.format(idx),
                    "name": self.format_str.format(f.name),
                }
                ef = PEExceptionFunctionFact(parentObjects=[self.object_id],
                                             parentFacts=[self.fact_id],
                                             **ed)
                self.console.addFact(ef)
        except Exception:
            return

    def get_functions(self):
        try:
            for idx, f in enumerate(self.pe.functions):
                fd = {
                    "address": self.format_hex.format(f.address),
                    "idx": self.format_dec.format(idx),
                    "name": self.format_str.format(f.name),
                    "size": self.format_dec.format(f.size),
                }
                ff = PEFunctionFact(parentObjects=[self.object_id],
                                    parentFacts=[self.fact_id],
                                    **fd)
                self.console.addFact(ff)
        except Exception:
            return
