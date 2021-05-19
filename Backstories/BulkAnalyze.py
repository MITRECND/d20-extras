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

from d20.Manual.Options import Arguments
from d20.Manual.Templates import (BackStoryTemplate, registerBackStory)

import os


@registerBackStory(
    name="BulkAnalyze",
    description=("Searches the provided directory for the files",
                 " to analyze. Uses the BulkAnalyzeFact."),
    creator="Mike Goffin",
    version="0.1",
    engine_version="0.1",
    default_weight=1,
    options=Arguments(
        ("test", {'type': bool, 'default': False})
    ),
    category="bulk_analyze")
class BulkAnalyze(BackStoryTemplate):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # If we have options, they would go here
        self.test = self.options.get("test", False)

    def handleFact(self, **kwargs):

        # This should be the BulkAnalyzeFact
        factObj = kwargs['fact']

        # Did we get a Fact we can handle?
        if factObj.factType != 'bulk_analyze' or not factObj.enable:
            return

        directory = factObj.directory
        recursive = factObj.recursive

        self.dir_listing(directory, recursive=recursive)

        # Break so other backstories in the category
        # don't run
        return True

    def dir_listing(self, directory, recursive=False):
        for s in os.scandir(directory):
            if s.is_file():
                with open(s.path, 'rb') as new_obj:
                    data = new_obj.read()
                    self.console.addObject(
                        data,
                        metadata={
                            'filename': s.name,
                            'filepath': directory
                        },
                    )
            elif s.is_dir() and recursive:
                self.dir_listing(s.path)
