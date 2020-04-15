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
Tests for userservice
"""

import random
import unittest
from unittest.mock import patch, mock_open

from sqlalchemy.exc import SQLAlchemyError

from userservice.userservice import create_app
from userservice.tests.constants import EXAMPLE_USER_REQUEST, EXAMPLE_USER, EXAMPLE_TOKEN


class TestUserservice(unittest.TestCase):
    """
    Tests cases for userservice
    """

    def setUp(self):
        """Setup Flask TestClient and mock userdatabase"""
        # mock opening files
        with patch('userservice.userservice.open', mock_open(read_data='foo')):
            # mock env vars
            with patch(
                'os.environ',
                {
                    'VERSION': '1',
                    'TOKEN_EXPIRY_SECONDS': '1',
                    'PRIVATE_KEY': '1',
                    'PUB_KEY_PATH': '1',
                },
            ):
                # mock db module as MagicMock, context manager handles cleanup
                with patch('userservice.userservice.UserDb') as mock_db:
                    self.mocked_db = mock_db
                    # get create flask app
                    self.flask_app = create_app()
                    # set testing config
                    self.flask_app.config['TESTING'] = True
                    # create test client
                    self.test_app = self.flask_app.test_client()

    def test_version_endpoint(self):
        """test if correct version is returned"""
        # generate a version
        version = str(random.randint(1, 9))
        # set version in Flask config
        self.flask_app.config['VERSION'] = version
        # send get request to test client
        response = self.test_app.get('/version')
        # assert both versions are equal
        self.assertEqual(response.data, version.encode())

    def test_ready_endpoint(self):
        """test if correct response is returned from readiness probe"""
        response = self.test_app.get('/ready')
        self.assertEqual(response.data, b'ok')

    def test_create_user(self):
        """test creating a new user who does not exist in the DB"""
        # mock return value of get_user which checks if user exists as None
        self.mocked_db.return_value.get_user.return_value = None
        # create example user request
        example_user_request = EXAMPLE_USER_REQUEST.copy()
        example_user_request['username'] = 'foo'
        # send request to test client
        response = self.test_app.post('/users', data=example_user_request)
        # assert 201 response code
        self.assertEqual(response.status_code, 201)

    def test_create_user_existing(self):
        """test creating a new user who already exists in the DB"""
        # mock return value of get_user which checks if user exists
        self.mocked_db.return_value.get_user.return_value = {}
        example_user_request = EXAMPLE_USER_REQUEST.copy()
        # create example user request
        example_user_request['username'] = 'foo'
        # send request to test client
        response = self.test_app.post('/users', data=example_user_request)
        # assert 409 response code
        self.assertEqual(response.status_code, 409)
        # assert we get correct error message
        self.assertEqual(
            response.json['msg'], 'user {} already exists'.format(example_user_request['username'])
        )

    def test_create_user_sql_error(self):
        """test creating a new user but throws SQL error when trying to add"""
        # mock return value of get_user which checks if user exists as None
        self.mocked_db.return_value.get_user.return_value = None
        # mock return value of add_user to throw SQLAlchemyError
        self.mocked_db.return_value.add_user.side_effect = SQLAlchemyError()
        # create example user request
        example_user = EXAMPLE_USER_REQUEST.copy()
        example_user['username'] = 'foo'
        # send request to test client
        response = self.test_app.post('/users', data=example_user)
        # assert 500 response code
        self.assertEqual(response.status_code, 500)
        # assert we get correct error message
        self.assertEqual(response.json['msg'], 'failed to create user')

    def test_create_user_malformed(self):
        """test creating a new user without required keys"""
        # create example user request
        example_user = EXAMPLE_USER_REQUEST.copy()
        # remove a required field
        example_user.pop('username')
        # send request to test client
        response = self.test_app.post('/users', data=example_user)
        # assert 400 response code
        self.assertEqual(response.status_code, 400)
        # assert we get correct error message
        self.assertEqual(response.json['msg'], 'missing required field(s)')

    def test_create_user_malformed_empty(self):
        """test creating a new user with empty value for required key"""
        # create example user request
        example_user = EXAMPLE_USER_REQUEST.copy()
        # set empty value for required key
        example_user['username'] = ''
        # send request to test client
        response = self.test_app.post('/users', data=example_user)
        # assert 400 response code
        self.assertEqual(response.status_code, 400)
        # assert we get correct error message
        self.assertEqual(response.json['msg'], 'missing value for input field(s)')

    def test_create_user_mismatch_password(self):
        """test creating a new user with empty value for required key"""
        # create example user request
        example_user = EXAMPLE_USER_REQUEST.copy()
        # set mismatch values for password and password-repeat
        example_user['password'] = 'foo'
        example_user['password-repeat'] = 'bar'
        # send request to test client
        response = self.test_app.post('/users', data=example_user)
        # assert 400 response code
        self.assertEqual(response.status_code, 400)
        # assert we get correct error message
        self.assertEqual(response.json['msg'], 'passwords do not match')

    # mock check pw to return true to simulate correct password
    @patch('bcrypt.checkpw', return_value=True)
    @patch('jwt.encode', return_value=EXAMPLE_TOKEN.encode())
    def test_login(self, _mock_checkpw, _mock_jwt):
        """test logging in with existing user"""
        # create example user request
        example_user = EXAMPLE_USER.copy()
        example_user_request = EXAMPLE_USER_REQUEST.copy()
        self.mocked_db.return_value.get_user.return_value = example_user
        # send request to test client
        response = self.test_app.get('/login', query_string=example_user_request)
        # assert 200 response
        self.assertEqual(response.status_code, 200)
        # assert we get a json response with just token key
        self.assertEqual(list(response.json.keys()), ['token'])
        # assert token is example token
        self.assertEqual(response.json['token'], EXAMPLE_TOKEN)

    # mock check pw to return false
    @patch('bcrypt.checkpw', return_value=False)
    def test_login_invalid_password(self, _mock_checkpw):
        """test logging in with existing user"""
        # create example user request
        example_user = EXAMPLE_USER.copy()
        example_user_request = EXAMPLE_USER_REQUEST.copy()
        self.mocked_db.return_value.get_user.return_value = example_user
        response = self.test_app.get('/login', query_string=example_user_request)
        # assert 401 response
        self.assertEqual(response.status_code, 401)
        # assert we get correct error message
        self.assertEqual(response.json['msg'], 'invalid login')

    def test_login_non_existent_user(self):
        """test logging in with a user that does not exist"""
        # mock return value of get_user which checks if user exists as None
        self.mocked_db.return_value.get_user.return_value = None
        # example user request
        example_user_request = EXAMPLE_USER_REQUEST.copy()
        example_user_request['username'] = 'foo'
        # send request to test client
        response = self.test_app.get('/login', query_string=example_user_request)
        # assert 404 response
        self.assertEqual(response.status_code, 404)
        # assert we get correct error message
        self.assertEqual(
            response.json['msg'], 'user {} does not exist'.format(example_user_request['username'])
        )
