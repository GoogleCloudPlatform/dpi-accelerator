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

import unittest
import asyncio
import json
import os
import logging
import re
from unittest.mock import MagicMock, AsyncMock, patch, call

import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from core.models import InfraDeploymentRequest, AppDeploymentRequest, DeploymentType, RegistryConfig, DomainConfig
import core.utils as utils  # Import utils to allow its original function to be called

import config.app_config_generator as app_config
import services.deployment_manager as dm


class TestDeploymentManager(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.patcher_infra_script_path = patch('services.deployment_manager.INFRA_SCRIPT_PATH', '/mock/infra_script.sh')
        self.patcher_app_script_path = patch('services.deployment_manager.APP_SCRIPT_PATH', '/mock/app_script.sh')
        self.patcher_terraform_directory = patch('services.deployment_manager.TERRAFORM_DIRECTORY', '/mock/terraform_dir')

        self.mock_infra_script_path = self.patcher_infra_script_path.start()
        self.mock_app_script_path = self.patcher_app_script_path.start()
        self.mock_terraform_directory = self.patcher_terraform_directory.start()

        self.patcher_tf_config_generator = patch('services.deployment_manager.tf_config')
        self.patcher_app_config_generator = patch('services.deployment_manager.app_config')

        self.mock_tf_config = self.patcher_tf_config_generator.start()
        self.mock_app_config = self.patcher_app_config_generator.start()

        self.mock_logger = patch('services.deployment_manager.logger').start()
        self.mock_logger.handlers = []
        self.mock_logger.propagate = False
        self.mock_logger.setLevel(logging.NOTSET)

        self.mock_websocket = AsyncMock()
        self.mock_websocket.send_text = AsyncMock()

        # Common dummy data for AppDeploymentRequest to satisfy Pydantic.
        self.dummy_registry_config = RegistryConfig(
            server_url="http://mock-registry.com",
            subscriber_id="mock_subscriber_id",
            key_id="mock_key_id"
        )
        self.dummy_domain_config = DomainConfig(
            domainType="mock_type",
            baseDomain="mock.com",
            dnsZone="mock-zone"
        )
        self.dummy_registry_url = "http://mock-registry-url.com"


    def tearDown(self):
        patch.stopall()

    @patch('asyncio.create_subprocess_exec')
    @patch('builtins.open', new_callable=MagicMock)
    @patch('json.load', return_value={"output_key": {"value": "output_value"}})
    # Removed: @patch('core.utils.stream_subprocess_output')
    async def test_run_infra_deployment_success(self, mock_json_load, mock_open, mock_create_subprocess_exec):
        mock_process = AsyncMock()
        mock_process.stdout = AsyncMock() # Added to simulate stdout for the actual stream_subprocess_output
        mock_process.stdout.readline.side_effect = [b"Infra log 1\n", b"Infra log 2\n", b""] # Added for actual stream_subprocess_output
        mock_process.wait.return_value = 0
        mock_create_subprocess_exec.return_value = mock_process

        config_request = InfraDeploymentRequest(
            project_id="test-proj", region="us-central1", app_name="test-app",
            type=DeploymentType.SMALL, components={"bap": True}
        )

        await dm.run_infra_deployment(config_request, self.mock_websocket)

        self.mock_tf_config.generate_config.assert_called_once_with(config_request)
        mock_create_subprocess_exec.assert_called_once_with(
            '/bin/bash', self.mock_infra_script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=self.mock_terraform_directory
        )
        # Removed assert for mock_stream_subprocess_output as it's no longer mocked
        self.assertEqual(self.mock_websocket.send_text.call_count, 6) # 3 info + 2 log + 1 success (now that logs are simulated)

        expected_messages = [
            json.dumps({"type": "info", "message": "Generating Terraform configurations..."}),
            json.dumps({"type": "info", "message": "Terraform configurations generated successfully."}),
            json.dumps({"type": "info", "message": "Executing infrastructure deployment script..."}),
            json.dumps({"type": "log", "action": "infra_deploy_log", "message": "Infra log 1"}),
            json.dumps({"type": "log", "action": "infra_deploy_log", "message": "Infra log 2"}),
            json.dumps({"type": "success", "message": {"output_key": {"value": "output_value"}}}),
        ]
        
        for msg in expected_messages:
            self.mock_websocket.send_text.assert_any_call(msg)

        mock_open.assert_called_once_with(os.path.join(self.mock_terraform_directory, "outputs.json"), "r")
        mock_json_load.assert_called_once()
        self.mock_logger.info.assert_any_call("Terraform configurations generated successfully.")
        self.mock_logger.info.assert_any_call("Successfully sent outputs.json content to client.")

    async def test_run_infra_deployment_config_generation_failure(self):
        self.mock_tf_config.generate_config.side_effect = Exception("Config error")

        config_request = InfraDeploymentRequest(
            project_id="test-proj", region="us-central1", app_name="test-app",
            type=DeploymentType.SMALL, components={"bap": True}
        )

        await dm.run_infra_deployment(config_request, self.mock_websocket)

        self.mock_tf_config.generate_config.assert_called_once_with(config_request)
        self.assertEqual(self.mock_websocket.send_text.call_count, 2) # 1 info + 1 error
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "info", "message": "Generating Terraform configurations..."}))
        self.mock_websocket.send_text.assert_called_with(json.dumps({"type": "error", "message": "Failed to generate Terraform configurations: Config error"}))
        self.mock_logger.error.assert_called_once()
        
        mock_create_subprocess_exec_in_this_test = patch('asyncio.create_subprocess_exec').start()
        mock_create_subprocess_exec_in_this_test.assert_not_called()
        patch('asyncio.create_subprocess_exec').stop()

    @patch('asyncio.create_subprocess_exec', side_effect=FileNotFoundError("Script not found"))
    async def test_run_infra_deployment_script_not_found(self, mock_create_subprocess_exec):
        config_request = InfraDeploymentRequest(
            project_id="test-proj", region="us-central1", app_name="test-app",
            type=DeploymentType.SMALL, components={"bap": True}
        )

        await dm.run_infra_deployment(config_request, self.mock_websocket)

        self.mock_tf_config.generate_config.assert_called_once()
        mock_create_subprocess_exec.assert_called_once()
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "info", "message": "Executing infrastructure deployment script..."}))
        self.mock_websocket.send_text.assert_called_with(json.dumps({"type": "error", "message": f"Infrastructure deployment script not found at: {self.mock_infra_script_path}"}))
        self.mock_logger.error.assert_called_once()


    @patch('asyncio.create_subprocess_exec')
    @patch('builtins.open')
    # Removed: @patch('core.utils.stream_subprocess_output')
    async def test_run_infra_deployment_script_execution_failure(self, mock_open, mock_create_subprocess_exec):
        mock_process = AsyncMock()
        mock_process.stdout = AsyncMock() # Added for actual stream_subprocess_output
        mock_process.stdout.readline.side_effect = [b"Infra log error\n", b""] # Added for actual stream_subprocess_output
        mock_process.wait.return_value = 1
        mock_create_subprocess_exec.return_value = mock_process

        config_request = InfraDeploymentRequest(
            project_id="test-proj", region="us-central1", app_name="test-app",
            type=DeploymentType.SMALL, components={"bap": True}
        )

        await dm.run_infra_deployment(config_request, self.mock_websocket)

        self.mock_tf_config.generate_config.assert_called_once()
        mock_create_subprocess_exec.assert_called_once()
        # Removed assert for mock_stream_subprocess_output
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "log", "action": "infra_deploy_log", "message": "Infra log error"})) # Added expected log messages
        self.mock_websocket.send_text.assert_called_with(json.dumps({"type": "error", "message": "Script failed with exit code: 1"}))
        mock_open.assert_not_called()

    @patch('asyncio.create_subprocess_exec')
    @patch('builtins.open', side_effect=FileNotFoundError("Outputs JSON not found"))
    # Removed: @patch('core.utils.stream_subprocess_output')
    async def test_run_infra_deployment_outputs_json_not_found(self, mock_open, mock_create_subprocess_exec):
        mock_process = AsyncMock()
        mock_process.stdout = AsyncMock() # Added for actual stream_subprocess_output
        mock_process.stdout.readline.side_effect = [b"Infra log\n", b""] # Added for actual stream_subprocess_output
        mock_process.wait.return_value = 0
        mock_create_subprocess_exec.return_value = mock_process

        config_request = InfraDeploymentRequest(
            project_id="test-proj", region="us-central1", app_name="test-app",
            type=DeploymentType.SMALL, components={"bap": True}
        )

        await dm.run_infra_deployment(config_request, self.mock_websocket)

        self.mock_tf_config.generate_config.assert_called_once()
        mock_create_subprocess_exec.assert_called_once()
        # Removed assert for mock_stream_subprocess_output
        mock_open.assert_called_once_with(os.path.join(self.mock_terraform_directory, "outputs.json"), "r")
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "log", "action": "infra_deploy_log", "message": "Infra log"})) # Added expected log messages
        self.mock_websocket.send_text.assert_called_with(json.dumps({"type": "error", "message": f"Error: outputs.json not found at {os.path.join(self.mock_terraform_directory, 'outputs.json')}"}))
        self.mock_logger.error.assert_called_once()

    @patch('asyncio.create_subprocess_exec')
    @patch('builtins.open', new_callable=MagicMock)
    @patch('json.load', side_effect=json.JSONDecodeError("Invalid JSON", doc="{}", pos=1))
    # Removed: @patch('core.utils.stream_subprocess_output')
    async def test_run_infra_deployment_outputs_json_decode_error(self, mock_json_load, mock_open, mock_create_subprocess_exec):
        mock_process = AsyncMock()
        mock_process.stdout = AsyncMock() # Added for actual stream_subprocess_output
        mock_process.stdout.readline.side_effect = [b"Infra log\n", b""] # Added for actual stream_subprocess_output
        mock_process.wait.return_value = 0
        mock_create_subprocess_exec.return_value = mock_process

        config_request = InfraDeploymentRequest(
            project_id="test-proj", region="us-central1", app_name="test-app",
            type=DeploymentType.SMALL, components={"bap": True}
        )

        await dm.run_infra_deployment(config_request, self.mock_websocket)

        self.mock_tf_config.generate_config.assert_called_once()
        mock_create_subprocess_exec.assert_called_once()
        # Removed assert for mock_stream_subprocess_output
        mock_open.assert_called_once_with(os.path.join(self.mock_terraform_directory, "outputs.json"), "r")
        mock_json_load.assert_called_once()
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "log", "action": "infra_deploy_log", "message": "Infra log"})) # Added expected log messages
        self.mock_websocket.send_text.assert_called_with(json.dumps({"type": "error", "message": f"Error: Could not decode outputs.json at {os.path.join(self.mock_terraform_directory, 'outputs.json')}"}))
        self.mock_logger.error.assert_called_once()

    @patch('asyncio.create_subprocess_exec', side_effect=Exception("Unexpected error"))
    async def test_run_infra_deployment_general_exception_during_subprocess(self, mock_create_subprocess_exec):
        config_request = InfraDeploymentRequest(
            project_id="test-proj", region="us-central1", app_name="test-app",
            type=DeploymentType.SMALL, components={"bap": True}
        )

        await dm.run_infra_deployment(config_request, self.mock_websocket)

        self.mock_tf_config.generate_config.assert_called_once()
        mock_create_subprocess_exec.assert_called_once()
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "info", "message": "Executing infrastructure deployment script..."}))
        self.mock_websocket.send_text.assert_called_with(json.dumps({"type": "error", "message": "An error occurred during infrastructure deployment: Unexpected error"}))
        self.mock_logger.exception.assert_called_once()

    @patch('services.deployment_manager._get_services_to_deploy', return_value=["adapter", "registry"])
    @patch('asyncio.create_subprocess_exec')
    # Removed: @patch('core.utils.stream_subprocess_output')
    async def test_run_app_deployment_success(self, mock_create_subprocess_exec, mock_get_services_to_deploy):
        mock_process = AsyncMock()
        mock_process.stdout = AsyncMock() # Added for actual stream_subprocess_output
        mock_process.stdout.readline.side_effect = [b"App log 1\n", b"App log 2\n", b""] # Added for actual stream_subprocess_output
        mock_process.wait.return_value = 0
        mock_create_subprocess_exec.return_value = mock_process

        self.mock_app_config.get_deployment_environment_variables.return_value = {"TEST_ENV_VAR": "value"}
        self.mock_app_config.generate_logs_explorer_urls.return_value = {"adapter": "adapter-logs-url", "registry": "registry-logs-url"}
        self.mock_app_config.extract_final_urls.return_value = {"adapter": "https://adapter.com", "registry": "https://registry.com"}


        app_req = AppDeploymentRequest(
            app_name="test-app",
            components={"bap": True, "registry": True},
            domain_names={"app": "my-app.com", "adapter": "adapter.com", "registry": "registry.com"},
            image_urls={"bap": "repo/bap:v1"},
            registry_url=self.dummy_registry_url,
            registry_config=self.dummy_registry_config,
            domain_config=self.dummy_domain_config
        )

        await dm.run_app_deployment(app_req, self.mock_websocket)

        self.mock_app_config.generate_app_configs.assert_called_once_with(app_req)
        mock_get_services_to_deploy.assert_called_once_with(app_req)
        self.mock_app_config.get_deployment_environment_variables.assert_called_once_with(app_req, ["adapter", "registry"])
        
        args, kwargs = mock_create_subprocess_exec.call_args
        self.assertEqual(args[0], '/bin/bash')
        self.assertEqual(args[1], self.mock_app_script_path)
        self.assertEqual(kwargs['cwd'], self.mock_terraform_directory)
        self.assertIn("TEST_ENV_VAR", kwargs['env'])
        self.assertEqual(kwargs['env']['TEST_ENV_VAR'], "value")
        self.assertIn("PATH", kwargs['env'])

        # Removed assert for mock_stream_subprocess_output
        self.assertEqual(self.mock_websocket.send_text.call_count, 6) # 3 info + 2 log + 1 success

        expected_success_message = json.dumps({
            "type": "success",
            "action": "app_deploy_complete",
            "message": "Application deployment successful!",
            "data": {
                "service_urls": {"adapter": "https://adapter.com", "registry": "https://registry.com"},
                "services_deployed": ["adapter", "registry"],
                "logs_explorer_urls": {"adapter": "adapter-logs-url", "registry": "registry-logs-url"},
            }
        })
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "info", "message": "Generating application configurations..."}))
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "info", "message": "Application configurations generated successfully."}))
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "info", "message": "Executing application deployment script..."}))
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "log", "action": "app_deploy_log", "message": "App log 1"})) # Added expected log messages
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "log", "action": "app_deploy_log", "message": "App log 2"})) # Added expected log messages
        self.mock_websocket.send_text.assert_called_with(expected_success_message)

        self.mock_app_config.generate_logs_explorer_urls.assert_called_once_with(["adapter", "registry"])
        self.mock_app_config.extract_final_urls.assert_called_once_with(app_req.domain_names, ["adapter", "registry"])
        self.mock_logger.info.assert_any_call("Environment variables for app script prepared.")
        self.mock_logger.info.assert_any_call("Application configuration YAMLs generated successfully.")
        self.mock_logger.info.assert_any_call(expected_success_message)


    async def test_run_app_deployment_config_generation_failure(self):
        self.mock_app_config.generate_app_configs.side_effect = FileNotFoundError("App config template missing")

        app_req = AppDeploymentRequest(
            app_name="test-app",
            components={"bap": True}, domain_names={}, image_urls={},
            registry_url=self.dummy_registry_url,
            registry_config=self.dummy_registry_config,
            domain_config=self.dummy_domain_config
        )

        await dm.run_app_deployment(app_req, self.mock_websocket)

        self.mock_app_config.generate_app_configs.assert_called_once_with(app_req)
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "info", "message": "Generating application configurations..."}))
        self.mock_websocket.send_text.assert_called_with(json.dumps({
            "type": "error",
            "action": "app_config_error",
            "message": "Error generating application configs: Required outputs.json not found or script not found: App config template missing. Ensure infrastructure is deployed."
        }))
        self.mock_logger.error.assert_called_once()
        self.mock_app_config.get_deployment_environment_variables.assert_not_called()

    @patch('services.deployment_manager._get_services_to_deploy', return_value=["adapter"])
    @patch('asyncio.create_subprocess_exec')
    # Removed: @patch('core.utils.stream_subprocess_output')
    async def test_run_app_deployment_script_execution_failure(self, mock_create_subprocess_exec, mock_get_services_to_deploy):
        mock_process = AsyncMock()
        mock_process.stdout = AsyncMock() # Added for actual stream_subprocess_output
        mock_process.stdout.readline.side_effect = [b"App log error\n", b""] # Added for actual stream_subprocess_output
        mock_process.wait.return_value = 1
        mock_create_subprocess_exec.return_value = mock_process

        self.mock_app_config.get_deployment_environment_variables.return_value = {}

        app_req = AppDeploymentRequest(
            app_name="test-app",
            components={"bap": True}, domain_names={}, image_urls={},
            registry_url=self.dummy_registry_url,
            registry_config=self.dummy_registry_config,
            domain_config=self.dummy_domain_config
        )

        await dm.run_app_deployment(app_req, self.mock_websocket)

        self.mock_app_config.generate_app_configs.assert_called_once()
        mock_get_services_to_deploy.assert_called_once_with(app_req)
        self.mock_app_config.get_deployment_environment_variables.assert_called_once_with(app_req, ["adapter"])
        mock_create_subprocess_exec.assert_called_once()
        # Removed assert for mock_stream_subprocess_output
        self.mock_websocket.send_text.assert_any_call(json.dumps({"type": "log", "action": "app_deploy_log", "message": "App log error"})) # Added expected log messages
        self.mock_websocket.send_text.assert_called_with(json.dumps({
            "type": "error",
            "action": "app_deploy_failed",
            "message": "Application deployment script failed with exit code: 1. Check logs above for details."
        }))

    @patch('services.deployment_manager._get_services_to_deploy', return_value=["adapter"])
    @patch('asyncio.create_subprocess_exec', side_effect=Exception("Unexpected app process error"))
    async def test_run_app_deployment_general_exception(self, mock_create_subprocess_exec, mock_get_services_to_deploy):
        app_req = AppDeploymentRequest(
            app_name="test-app",
            components={"bap": True}, domain_names={}, image_urls={},
            registry_url=self.dummy_registry_url,
            registry_config=self.dummy_registry_config,
            domain_config=self.dummy_domain_config
        )

        await dm.run_app_deployment(app_req, self.mock_websocket)

        self.mock_app_config.generate_app_configs.assert_called_once()
        mock_get_services_to_deploy.assert_called_once_with(app_req)
        self.mock_app_config.get_deployment_environment_variables.assert_called_once_with(app_req, ["adapter"])
        mock_create_subprocess_exec.assert_called_once()
        self.mock_websocket.send_text.assert_called_with(json.dumps({
            "type": "error",
            "action": "app_deploy_exception",
            "message": "An unexpected error occurred during app deployment: Unexpected app process error"
        }))
        self.mock_logger.exception.assert_called_once()

    @patch('services.deployment_manager.app_config.should_deploy_subscriber')
    def test_get_services_to_deploy_all_components(self, mock_should_deploy_subscriber):
        mock_should_deploy_subscriber.return_value = True # For this test case, subscriber should be deployed if components imply it
        app_req = AppDeploymentRequest(
            app_name="test-app",
            components={
                "bap": True,
                "bpp": True,
                "gateway": True,
                "registry": True
            },
            domain_names={}, image_urls={},
            registry_url=self.dummy_registry_url,
            registry_config=self.dummy_registry_config,
            domain_config=self.dummy_domain_config
        )
        # Assuming the logic in app_config.should_deploy_subscriber is based on bap, bpp, gateway
        # If 'bap' or 'bpp' or 'gateway' are True, then should_deploy_subscriber is True
        # For 'all_components' case, it would be True.
        expected_services = ["adapter", "gateway", "registry", "registry_admin", "subscriber"]
        self.assertEqual(dm._get_services_to_deploy(app_req), sorted(expected_services))
        mock_should_deploy_subscriber.assert_called_once_with(app_req.components)


    @patch('services.deployment_manager.app_config.should_deploy_subscriber')
    def test_get_services_to_deploy_bap_only(self, mock_should_deploy_subscriber):
        mock_should_deploy_subscriber.return_value = True # 'bap' implies subscriber
        app_req = AppDeploymentRequest(
            app_name="test-app",
            components={
                "bap": True,
                "bpp": False,
                "gateway": False,
                "registry": False
            },
            domain_names={}, image_urls={},
            registry_url=self.dummy_registry_url,
            registry_config=self.dummy_registry_config,
            domain_config=self.dummy_domain_config
        )
        expected_services = ["adapter", "subscriber"]
        self.assertEqual(dm._get_services_to_deploy(app_req), sorted(expected_services))
        mock_should_deploy_subscriber.assert_called_once_with(app_req.components)

    @patch('services.deployment_manager.app_config.should_deploy_subscriber')
    def test_get_services_to_deploy_registry_only(self, mock_should_deploy_subscriber):
        mock_should_deploy_subscriber.return_value = False # 'registry' alone does NOT imply subscriber
        app_req = AppDeploymentRequest(
            app_name="test-app",
            components={
                "bap": False,
                "bpp": False,
                "gateway": False,
                "registry": True
            },
            domain_names={}, image_urls={},
            registry_url=self.dummy_registry_url,
            registry_config=self.dummy_registry_config,
            domain_config=self.dummy_domain_config
        )
        expected_services = ["registry", "registry_admin"]
        self.assertEqual(dm._get_services_to_deploy(app_req), sorted(expected_services))
        mock_should_deploy_subscriber.assert_called_once_with(app_req.components)


    @patch('services.deployment_manager.app_config.should_deploy_subscriber')
    def test_get_services_to_deploy_no_components(self, mock_should_deploy_subscriber):
        mock_should_deploy_subscriber.return_value = False # No relevant components implies no subscriber
        app_req = AppDeploymentRequest(
            app_name="test-app",
            components={},
            domain_names={}, image_urls={},
            registry_url=self.dummy_registry_url,
            registry_config=self.dummy_registry_config,
            domain_config=self.dummy_domain_config
        )
        expected_services = []
        self.assertEqual(dm._get_services_to_deploy(app_req), sorted(expected_services))
        mock_should_deploy_subscriber.assert_called_once_with(app_req.components)
