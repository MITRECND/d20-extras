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

from d20.Actions import registerAction
from d20.Manual.Options import Arguments

import libarchive.public
import rarfile
import zipfile


@registerAction(
    name="unzip",
    description="Utility to unzip data.",
    options=Arguments(
        ("password", {'type': str, 'default': None})
    )
)
class Unzip(object):
    '''Class for supporting unzip Actions.'''

    def __init__(self, **kwargs):
        self.password = self.options.get('password', None)
        return

    def unzip(self, obj, password=None):
        '''Unzip an object'''

        if not password:
            password = self.password

        try:
            zf = zipfile.ZipFile(obj.stream)
            if password:
                zf.setpassword(bytes(password, 'utf-8'))
            nl = zf.namelist()
            files_unzipped = []
            for n in nl:
                data = zf.read(n)
                result = {
                    'data': data,
                    'name': n,
                }
                files_unzipped.append(result)
        except Exception as e:
            raise RuntimeError(e)
        return files_unzipped


@registerAction(
    name="unrar",
    description="Utility to unrar data.",
    options=Arguments(
        ("password", {'type': str, 'default': None})
    )
)
class Unrar(object):
    '''Class for supporting unrar Actions.'''

    def __init__(self, **kwargs):
        self.password = self.options.get('password', None)
        return

    def unrar(self, obj, password=None):
        '''Unrar an object'''

        if not password:
            password = self.password

        try:
            rf = rarfile.RarFile(obj.onDisk)
            if rf.needs_password():
                rf.setpassword(bytes(password, 'utf-8'))
            nl = rf.namelist()
            files_unrarred = []
            for n in nl:
                if n.startswith('*'):
                    pass
                else:
                    data = rf.read(n)
                    result = {
                        'data': data,
                        'name': n,
                    }
                    files_unrarred.append(result)
        except Exception as e:
            raise RuntimeError(e)
        return files_unrarred


@registerAction(
    name="un7z",
    description="Utility to un7z data.",
    options=Arguments(
        ("password", {'type': str, 'default': None})
    )
)
class Un7z(object):
    '''Class for supporting 7z Actions.'''

    def __init__(self, **kwargs):
        self.password = self.options.get('password', None)
        return

    def un7z(self, obj, password=None):
        '''Un7z an object'''

        if not password:
            password = self.password

        try:
            files_un7zd = []
            with libarchive.public.memory_reader(obj.data) as e:
                for entry in e:
                    data = b''.join(entry.get_blocks())
                    result = {
                        'data': data,
                        'name': str(entry),
                    }
                    files_un7zd.append(result)
        except Exception as e:
            raise RuntimeError(e)
        return files_un7zd
