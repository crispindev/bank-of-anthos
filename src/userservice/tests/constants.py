# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Example constants used in tests
"""

from datetime import datetime

TIMESTAMP_FORMAT = '%Y-%m-%d'
EXAMPLE_USER_REQUEST = {
    'username': 'jdoe',
    'password': 'pwd',
    'password-repeat': 'pwd',
    'firstname': 'John',
    'lastname': 'Doe',
    'birthday': '2000-01-01',
    'timezone': 'GMT+1',
    'address': '1600 Amphitheatre Parkway',
    'state': 'CA',
    'zip': '94043',
    'ssn': '123',
}
EXAMPLE_USER = {
    'accountid': '123',
    'username': 'jdoe',
    'passhash': b'hjfsrf#jrsfj',
    'firstname': 'John',
    'lastname': 'Doe',
    'birthday': datetime.strptime('2000-01-01', TIMESTAMP_FORMAT).date(),
    'timezone': 'GMT+1',
    'address': '1600 Amphitheatre Parkway',
    'state': 'CA',
    'zip': '94043',
    'ssn': '123',
}
EXAMPLE_TOKEN = 'foo-token'
