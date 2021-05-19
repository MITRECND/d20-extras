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

from d20.Manual.Facts.Fields import (BytesField, StringField, StrOrBytesField)


@registerFact('string')
class AsciiStringFact(Fact):
    """A fact for adding an ascii string to the table"""
    _type_ = 'ascii_string'
    value = StrOrBytesField()


@registerFact('string')
class UnicodeStringFact(Fact):
    """A fact for adding a unicode string to the table"""
    _type_ = 'unicode_string'
    value = StrOrBytesField()


@registerFact('string')
class StackStringFact(Fact):
    """A fact for adding a stack string to the table"""
    _type_ = 'stack_string'
    value = StrOrBytesField()


@registerFact()
class ShellCodeFact(Fact):
    """ShellCodeFact"""
    _type_ = 'shellcode'
    value = BytesField()


@registerFact()
class B64Fact(Fact):
    _type_ = 'b64'
    value = StringField()
    decoded = StrOrBytesField()


@registerFact()
class DateFact(Fact):
    _type_ = 'date'
    value = StringField()


@registerFact()
class DomainFact(Fact):
    _type_ = 'domain'
    value = StringField()


@registerFact()
class EmailAddressFact(Fact):
    _type_ = 'email_address'
    value = StringField()


@registerFact()
class FilenameFact(Fact):
    _type_ = 'filename'
    value = StringField()


@registerFact()
class FilepathFact(Fact):
    _type_ = 'filepath'
    value = StringField()


@registerFact('ip_address')
class IPv4Fact(Fact):
    _type_ = 'ipv4'
    value = StringField()


@registerFact('ip_address')
class IPv6Fact(Fact):
    _type_ = 'ipv6'
    value = StringField()


@registerFact()
class MacAddressFact(Fact):
    _type_ = 'mac_address'
    value = StringField()


@registerFact()
class URIFact(Fact):
    _type_ = 'uri'
    value = StringField()
