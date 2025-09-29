# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import unittest
from unittest.mock import patch, mock_open, MagicMock
import os

# Import the functions and logger to be tested
from services.ui_state_manager import load_all_data, _save_data, store_bulk_values, logger, _get_db_file_path

class TestUIStateManager(unittest.TestCase):

    @patch('services.ui_state_manager._get_db_file_path', return_value='dummy/path/ui_state.json')
    def test_load_all_data_file_not_found(self, mock_get_path):
        """
        Test that load_all_data returns an empty dict if the file does not exist.
        """
        with patch('os.path.exists', return_value=False):
            result = load_all_data()
            self.assertEqual(result, {})

    @patch('services.ui_state_manager._get_db_file_path', return_value='dummy/path/ui_state.json')
    def test_load_all_data_file_is_empty(self, mock_get_path):
        """
        Test that load_all_data returns an empty dict if the file is empty.
        """
        with patch('os.path.exists', return_value=True), \
             patch('os.path.getsize', return_value=0):
            result = load_all_data()
            self.assertEqual(result, {})

    @patch('services.ui_state_manager._get_db_file_path', return_value='dummy/path/ui_state.json')
    def test_load_all_data_success(self, mock_get_path):
        """
        Test successful loading and parsing of a valid JSON file.
        """
        mock_json_content = '{"key1": "value1", "key2": 42}'
        m = mock_open(read_data=mock_json_content)
        
        with patch('os.path.exists', return_value=True), \
             patch('os.path.getsize', return_value=len(mock_json_content)), \
             patch('builtins.open', m):
            
            result = load_all_data()
            expected = {"key1": "value1", "key2": 42}
            self.assertEqual(result, expected)
            # Ensure the file was opened for reading
            m.assert_called_once_with('dummy/path/ui_state.json', 'r')

    @patch('services.ui_state_manager._get_db_file_path', return_value='dummy/path/ui_state.json')
    def test_load_all_data_json_decode_error(self, mock_get_path):
        """
        Test that load_all_data returns an empty dict for a corrupted JSON file.
        """
        mock_corrupted_content = '{"key1": "value1", "key2":}' # Invalid JSON
        m = mock_open(read_data=mock_corrupted_content)
        
        with patch('os.path.exists', return_value=True), \
             patch('os.path.getsize', return_value=len(mock_corrupted_content)), \
             patch('builtins.open', m), \
             self.assertLogs(logger, level='WARNING') as cm: # Capture log output
            
            result = load_all_data()
            self.assertEqual(result, {})
            # Check if the correct warning was logged
            self.assertIn("is corrupted or not valid JSON", cm.output[0])

    @patch('services.ui_state_manager._get_db_file_path', return_value='dummy/path/ui_state.json')
    def test_load_all_data_io_error(self, mock_get_path):
        """
        Test that load_all_data returns an empty dict and logs an error on IOError.
        """
        m = mock_open()
        m.side_effect = IOError("File read error")

        with patch('os.path.exists', return_value=True), \
             patch('os.path.getsize', return_value=100), \
             patch('builtins.open', m), \
             self.assertLogs(logger, level='ERROR') as cm:
            
            result = load_all_data()
            self.assertEqual(result, {})
            self.assertIn("Error reading UI state file", cm.output[0])

    @patch('services.ui_state_manager._get_db_file_path', return_value='dummy/path/ui_state.json')
    def test_save_data_success(self, mock_get_path):
        """
        Test that _save_data correctly writes data to a file.
        """
        m = mock_open()
        data_to_save = {"user": "test", "is_active": True}
        
        with patch('builtins.open', m):
            _save_data(data_to_save)
            
            # Check that the file was opened in write mode
            m.assert_called_once_with('dummy/path/ui_state.json', 'w')
            
            # json.dump with an indent calls write multiple times.
            # We can get the handle from the mock and check the full content written.
            handle = m()
            written_content = "".join(call.args[0] for call in handle.write.call_args_list)
            expected_json_string = json.dumps(data_to_save, indent=4)
            self.assertEqual(written_content, expected_json_string)

    @patch('services.ui_state_manager._get_db_file_path', return_value='dummy/path/ui_state.json')
    def test_save_data_io_error(self, mock_get_path):
        """
        Test that _save_data raises an IOError if writing fails.
        """
        m = mock_open()
        # Configure the mock to raise an IOError when opened
        m.side_effect = IOError("Permission denied")

        with patch('builtins.open', m), \
             self.assertRaises(IOError):
            _save_data({"key": "value"})

    @patch('services.ui_state_manager._save_data')
    @patch('services.ui_state_manager.load_all_data')
    def test_store_bulk_values_updates_data(self, mock_load_data, mock_save_data):
        """
        Test that store_bulk_values correctly loads, updates, and saves data.
        """
        # Arrange: mock the initial data loaded from the file
        initial_data = {"existing_key": "old_value", "another_key": 123}
        mock_load_data.return_value = initial_data

        # The new items to be stored
        items_to_store = {"new_key": "new_value", "existing_key": "updated_value"}
        
        # Act: call the function we are testing
        store_bulk_values(items_to_store)

        # Assert
        # 1. Ensure load_all_data was called
        mock_load_data.assert_called_once()
        
        # 2. Ensure _save_data was called with the correctly merged dictionary
        expected_data_to_save = {
            "existing_key": "updated_value", 
            "another_key": 123,
            "new_key": "new_value"
        }
        mock_save_data.assert_called_once_with(expected_data_to_save)

    def test_get_db_file_path_constructs_correctly(self):
        """
        Test that _get_db_file_path returns the correct path.
        """
        # This test is somewhat dependent on the project structure.
        # It assumes the 'backend' directory is one level up from the 'services' directory.
        expected_path_fragment = os.path.join('onix-installer', 'backend', 'ui_state.json')
        
        actual_path = _get_db_file_path()
        
        # Instead of asserting the full absolute path (which can be brittle),
        # we check if the constructed path ends with the expected structure.
        self.assertTrue(actual_path.endswith(expected_path_fragment))


if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)