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

from d20.Manual.Facts import PDFFact
from d20.Manual.Options import Arguments
from d20.Manual.Templates import (PlayerTemplate, registerPlayer)

from pdfrw import PdfReader

import pdfrw


@registerPlayer(
    name="PDFMeta",
    description=("Parse a PDF object and add Facts to the table."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    interests=['mimetype'],
    options=Arguments(
        ("disable", {'type': bool, 'default': False})
    )
)
class PDFMetaPlayer(PlayerTemplate):

    interesting_mts = [
        "application/pdf",
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

        try:
            pdf = PdfReader(self.obj.onDisk)
            pdfd = {}
            pdfd['keys'] = pdf.keys()  # list
            pdfd['root_keys'] = pdf.Root.keys()  # list
            if pdf.Info:
                pdfd['info'] = pdf.Info
            else:
                pdfd['info'] = {}
            pdfd['num_pages'] = len(pdf.pages)  # int
            pages = []
            for page in pdf.pages:
                pd = {}
                pd['contents'] = page.Contents
                # Remove circular references
                cpage = page.copy()
                clean_page = self.remove_circular_refs(cpage)
                pd['raw'] = clean_page
                # NOTE: If `page.Contents` has a `Filter` of `FlateDecode, the
                # stream will need to be decoded, which can be done by:
                # pdfrw.uncompress.uncompress([page.Contents]). Now the
                # page.Contents.stream will be decoded.
                try:
                    if page.Contents.Filter == '/FlateDecode':
                        pdfrw.uncompress.uncompress([page.Contents])
                except Exception:
                    pass
                pd['stream'] = page.Contents.stream
                # Hack to flatten the page and hunt for interesting keys.
                # - Octal Encoding is usually prefaced with a /JS
                nl = self.walk(page)
                for n in nl:
                    if n[0] == '/JS':
                        js = n[1].replace('(', '').replace(')', '')
                        decoded = js.encode().decode('unicode_escape')
                        pd['octal_decode'] = decoded
                pages.append(pd)

            pdfd['pages'] = pages

            pdffact = PDFFact(
                parentObjects=[self.object_id],
                parentFacts=[self.fact_id],
                **pdfd,
            )
            self.console.addFact(pdffact)
            return
        except Exception as e:
            raise RuntimeError(e)

    def walk(self, node, nl=None):
        ''' Flatten a complex dictionary into a list of lists with
            each key/value pair '''
        if nl is None:
            nl = []
        for k, v in node.items():
            if isinstance(v, pdfrw.objects.pdfdict.PdfDict):
                self.walk(v, nl)
            else:
                if v == node:
                    v = "Discarded due to recursion"
                    node[k] = v
                nl.append([k, v])
        return nl

    def remove_circular_refs(self, ob, _seen=None):
        if _seen is None:
            _seen = set()
        if id(ob) in _seen:
            # circular reference, remove it.
            return None
        _seen.add(id(ob))
        res = ob
        if isinstance(ob, dict):
            res = {
                self.remove_circular_refs(
                    k, _seen): self.remove_circular_refs(v, _seen)
                for k, v in ob.items()
            }
        elif isinstance(ob, (list, tuple, set, frozenset)):
            res = type(ob)(self.remove_circular_refs(v, _seen) for v in ob)
        # remove id again; only *nested* references count
        _seen.remove(id(ob))
        return res
