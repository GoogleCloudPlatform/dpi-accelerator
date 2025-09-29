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

# your_project/tests/configs_tests/test_tf_config_generator.py
import unittest
import os
import sys
import logging
from unittest.mock import patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from core.models import InfraDeploymentRequest, DeploymentType

from config import tf_config_generator


class TestTerraformConfigGenerator(unittest.TestCase):

    def setUp(self):
        self.patcher_tf_dir = patch('config.tf_config_generator.TERRAFORM_DIRECTORY', '/mock/tf_output_dir')
        self.patcher_template_dir = patch('config.tf_config_generator.TEMPLATE_DIRECTORY', '/mock/templates_base')

        self.mock_tf_dir = self.patcher_tf_dir.start()
        self.mock_template_dir = self.patcher_template_dir.start()

        # Reset logger handlers
        self.original_handlers = tf_config_generator.logger.handlers[:]
        tf_config_generator.logger.handlers = []
        tf_config_generator.logger.propagate = False
        tf_config_generator.logger.setLevel(logging.NOTSET)

    def tearDown(self):
        # Stop all patchers
        self.patcher_tf_dir.stop()
        self.patcher_template_dir.stop()

        # Restore logger state
        tf_config_generator.logger.handlers = self.original_handlers
        tf_config_generator.logger.propagate = True

    @patch('config.tf_config_generator.write_file_content')
    @patch('config.tf_config_generator.render_jinja_template')
    @patch('os.path.join', side_effect=os.path.join) # Use real os.path.join unless specific mocks are needed
    def test_generate_config_success_small(self, mock_os_path_join, mock_render_template, mock_write_file):
        """
        Test successful generation of Terraform config for 'small' deployment type.
        """
        mock_render_template.return_value = "main_config_content"

        req = InfraDeploymentRequest(
            project_id="test-proj",
            region="us-west1",
            app_name="my-app",
            type=DeploymentType.SMALL,
            components={
                "bap": True,
                "gateway": False,
                "registry": True
            }
        )

        tf_config_generator.generate_config(req)

        # Expected Jinja2 context
        expected_jinja_context = {
            "project_id": "test-proj",
            "region": "us-west1",
            "suffix": "my-app",
            "deployment_size": "small",
            "provision_adapter_infra": True, # BAP is True
            "provision_gateway_infra": False, # GATEWAY is False
            "provision_registry_infra": True, # REGISTRY is True
        }

        # Expected paths for mocking os.path.join (relative to patched constants)
        expected_template_source_dir = os.path.join(self.mock_template_dir, "tf_configs")
        expected_output_tfvars_path = os.path.join(self.mock_tf_dir, "generated-terraform.tfvars")

        # Assert render_jinja_template was called correctly
        mock_render_template.assert_called_once_with(
            template_dir=expected_template_source_dir,
            template_name="main_tfvars.tfvars.j2",
            context=expected_jinja_context
        )

        # Assert write_file_content was called with merged content
        mock_write_file.assert_called_once_with(expected_output_tfvars_path, "main_config_content")

    @patch('config.tf_config_generator.write_file_content')
    @patch('config.tf_config_generator.render_jinja_template')
    @patch('os.path.join', side_effect=os.path.join)
    def test_generate_config_success_medium_no_bap_bpp(self, mock_os_path_join, mock_render_template, mock_write_file):
        """
        Test successful generation for 'medium' type with no BAP/BPP components.
        """
        mock_render_template.return_value = "main_config_content_medium"

        req = InfraDeploymentRequest(
            project_id="test-medium",
            region="us-east1",
            app_name="my-app-medium",
            type=DeploymentType.MEDIUM,
            components={
                "bap": False,
                "bpp": False,
                "gateway": True,
                "registry": False
            }
        )
        tf_config_generator.generate_config(req)

        expected_jinja_context = {
            "project_id": "test-medium",
            "region": "us-east1",
            "suffix": "my-app-medium",
            "deployment_size": "medium",
            "provision_adapter_infra": False, # Both BAP and BPP are False
            "provision_gateway_infra": True,
            "provision_registry_infra": False,
        }

        mock_render_template.assert_called_once_with(
            template_dir=os.path.join(self.mock_template_dir, "tf_configs"),
            template_name="main_tfvars.tfvars.j2",
            context=expected_jinja_context
        )
        mock_write_file.assert_called_once_with(
            os.path.join(self.mock_tf_dir, "generated-terraform.tfvars"),
            "main_config_content_medium"
        )

    @patch('config.tf_config_generator.write_file_content', side_effect=IOError("Disk full"))
    @patch('config.tf_config_generator.render_jinja_template', return_value="main_config_content")
    @patch('os.path.join', side_effect=os.path.join)
    @patch('config.tf_config_generator.logger')
    def test_generate_config_write_error(self, mock_logger, mock_os_path_join, mock_render_template, mock_write_file):
        """
        Test error handling when writing the merged tfvars file fails.
        """
        req = InfraDeploymentRequest(
            project_id="test-proj-write",
            region="us-west1",
            app_name="my-app-write",
            type=DeploymentType.SMALL,
            components={}
        )

        with self.assertRaisesRegex(IOError, "Disk full"):
            tf_config_generator.generate_config(req)

        mock_render_template.assert_called_once()
        mock_write_file.assert_called_once()
        mock_logger.error.assert_called_once()

    @patch('config.tf_config_generator.render_jinja_template', side_effect=Exception("Jinja Error"))
    @patch('config.tf_config_generator.logger')
    @patch('config.tf_config_generator.write_file_content')
    def test_generate_config_template_render_error(self, mock_write_file, mock_logger, mock_render_template):
        """
        Test error handling when rendering the main template fails.
        """
        req = InfraDeploymentRequest(
            project_id="test-proj-render",
            region="us-west1",
            app_name="my-app-render",
            type=DeploymentType.SMALL,
            components={}
        )

        with self.assertRaisesRegex(Exception, "Jinja Error"):
            tf_config_generator.generate_config(req)

        mock_render_template.assert_called_once()
        mock_logger.error.assert_called_once()
        self.assertFalse(mock_write_file.called)


if __name__ == '__main__':
    unittest.main()