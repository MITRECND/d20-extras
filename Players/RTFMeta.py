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

from d20.Manual.Facts import (OLE2LinkFact, RTFObjectFact,
                              MalformedRTFObjectFact, EquationEditorFact)
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)

from oletools import (oleobj, rtfobj)

import os


@registerPlayer(
    name="RTFMeta",
    description=("Get RTF info on an object and add Facts to the table."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['mimetype'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False})
    )
)
class RTFMetaPlayer(PlayerTemplate):

    interesting_mts = [
        "text/rtf",
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
        if factObj.mimetype not in self.interesting_mts:
            return

        self.fact_id = factObj.id
        self.object_id = factObj.parentObjects[0]
        self.obj = self.console.getObject(self.object_id)

        obj_data = self.obj.data
        if rtfobj.is_rtf(obj_data):
            rtfp = rtfobj.RtfObjParser(obj_data)
        else:
            self.console.print(
                "Found RTF file by mimetype but not detected by rtfobj.")
            return
        rtfp.parse()
        # Add objects to table
        # Much of this is taken from rtfobj's internal processing function:
        # https://github.com/decalage2/oletools/blob/master/oletools/rtfobj.py
        for o in rtfp.objects:
            filename = "Unknown"
            if o.is_ole:
                format_id = o.format_id
                if format_id == oleobj.OleObject.TYPE_EMBEDDED:
                    format_type = "Embedded"
                elif format_id == oleobj.OleObject.TYPE_LINKED:
                    format_type = "Linked"
                else:
                    format_type = "Unknown"

                class_name = o.class_name
                if class_name == b'OLE2Link':
                    possible_exploit = True
                    # exploit_desc = "OLE2Link exploit"
                    exf = OLE2LinkFact
                elif class_name.lower() == b'equation.3':
                    possible_exploit = True
                    # exploit_desc = "Equation Editor Exploit"
                    exf = EquationEditorFact
                else:
                    possible_exploit = None

                size = o.oledata_size

                if o.is_package:
                    try:
                        filename = o.filename
                    except Exception:
                        pass
                    try:
                        src_path = o.src_path
                    except Exception:
                        src_path = None
                    try:
                        temp_path = o.temp_path
                    except Exception:
                        temp_path = None
                    if filename and temp_path:
                        _, temp_ext = os.path.splitext(temp_path)
                        _, file_ext = os.path.splitext(filename)
                        if temp_ext != file_ext:
                            modified_file_extension = True
                        else:
                            modified_file_extension = False
                        if (rtfobj.re_executable_extensions.match(temp_ext)
                                or rtfobj.re_executable_extensions.match(
                                    file_ext)):
                            executable_file = True
                        else:
                            executable_file = False

                clsid = str(o.clsid)
                cls_desc = str(o.clsid_desc)

                rtfd = {
                    'format_id': format_id,
                    'format_type': format_type,
                    'class_name': class_name,
                    'size': size,
                    'is_package': o.is_package,
                    'clsid': clsid,
                    'cls_desc': cls_desc,
                }
                if o.is_package:
                    rtfd['filename'] = filename
                    rtfd['src_path'] = src_path
                    rtfd['temp_path'] = temp_path
                    if filename and temp_path:
                        rtfd[
                            'modified_file_extension'] = modified_file_extension  # noqa: E501
                        rtfd['executable_file'] = executable_file

                rtf_fact = RTFObjectFact(parentObjects=[self.object_id],
                                         parentFacts=[self.fact_id],
                                         **rtfd)

                self.console.addFact(rtf_fact)

                if o.is_package:
                    od = o.olepkgdata
                elif o.is_ole and size is not None:
                    od = o.oledata
                else:
                    od = o.rawdata
                oid = self.console.addObject(
                    od,
                    metadata={'filename': filename},
                    parentObjects=[self.object_id],
                    parentFacts=[rtf_fact.id],
                )

                if possible_exploit:
                    ex_fact = exf(
                        parentObjects=[oid],
                        parentFacts=[rtf_fact.id],
                        ole_class_name=class_name,
                    )
                    self.console.addHyp(ex_fact)
            else:
                self.console.print("Malformed OLE object found.")

                if o.start is None or \
                        len(o.rawdata) == 0:
                    self.console.print("Unable to process malformed object!")
                    return

                rtfd = {
                        'size': len(o.rawdata),
                        'index': o.start,
                        }

                mal_rtf_obj_fact = MalformedRTFObjectFact(
                        parentObjects=[self.object_id],
                        parentFacts=[self.fact_id],
                        **rtfd)

                self.console.addFact(mal_rtf_obj_fact)

                self.console.addObject(
                    o.rawdata,
                    metadata={
                        'filename':
                        '{}_malformed_rtf_obj_{}'.format(
                            self.obj.metadata.get(
                                'filename', self.object_id), hex(o.start))
                    },
                    parentObjects=[self.object_id],
                    parentFacts=[self.fact_id],
                )
