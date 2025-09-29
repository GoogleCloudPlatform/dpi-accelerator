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
import os
import sys
import logging
from unittest.mock import patch, MagicMock, call

import urllib

# Add the project root to sys.path for proper imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from core.models import (
    AppDeploymentRequest,
    DeploymentType,
    AdapterConfig,
    RegistryConfig,
    GatewayConfig,
    DomainConfig
)

from config import app_config_generator


class TestAppConfigGenerator(unittest.TestCase):

    def setUp(self):
        self.patcher_tf_dir = patch('config.app_config_generator.TERRAFORM_DIRECTORY', '/mock/tf_output')
        self.patcher_template_dir = patch('config.app_config_generator.TEMPLATE_DIRECTORY', '/mock/templates')
        self.patcher_generated_configs_dir = patch('config.app_config_generator.GENERATED_CONFIGS_DIR', '/mock/generated_app_configs')
        
        self.patcher_adapter_template = patch('config.app_config_generator.ADAPTER_CONFIG_TEMPLATE_NAME', 'mock_adapter.yaml.j2')
        self.patcher_registry_template = patch('config.app_config_generator.REGISTRY_CONFIG_TEMPLATE_NAME', 'mock_registry.yaml.j2')
        self.patcher_gateway_template = patch('config.app_config_generator.GATEWAY_CONFIG_TEMPLATE_NAME', 'mock_gateway.yaml.j2')
        self.patcher_subscriber_template = patch('config.app_config_generator.SUBSCRIBER_CONFIG_TEMPLATE_NAME', 'mock_subscriber.yaml.j2')
        self.patcher_registry_admin_template = patch('config.app_config_generator.REGISTRY_ADMIN_CONFIG_TEMPLATE_NAME', 'mock_registry-admin.yaml.j2')
        self.patcher_tfvars_template = patch('config.app_config_generator.TFVARS_TEMPLATE_NAME', 'mock_p2.tfvars.j2')


        self.mock_tf_dir = self.patcher_tf_dir.start()
        self.mock_template_dir = self.patcher_template_dir.start()
        self.mock_generated_configs_dir = self.patcher_generated_configs_dir.start()

        self.mock_adapter_template = self.patcher_adapter_template.start()
        self.mock_registry_template = self.patcher_registry_template.start()
        self.mock_gateway_template = self.patcher_gateway_template.start()
        self.mock_subscriber_template = self.patcher_subscriber_template.start()
        self.mock_registry_admin_template = self.patcher_registry_admin_template.start()
        self.mock_tfvars_template = self.patcher_tfvars_template.start()

        # Reset logger handlers and capture logs
        self.mock_logger = patch('config.app_config_generator.logger').start()
        self.mock_logger.handlers = [] # Clear handlers to prevent actual logging output during tests
        self.mock_logger.propagate = False
        self.mock_logger.setLevel(logging.NOTSET) # Ensure all levels are captured

        # Define default infra outputs to be used by mocks when needed
        self.default_infra_outputs = {
            "project_id": "default-project",
            "cluster_name": "default-cluster",
            "cluster_region": "default-region",
            "redis_instance_ip": "1.2.3.4",
            "onix_topic_name": "onix-topic",
            "adapter_topic_name": "adapter-topic",
            "database_user_sa_email": "db-user@example.gserviceaccount.com",
            "registry_admin_database_user_sa_email": "reg-admin@example.gserviceaccount.com",
            "registry_database_name": "reg-db",
            "registry_db_connection_name": "reg-conn",
            "config_bucket_name": "config-bucket",
            "url_map": "mock-url-map",
            "global_ip_address": "35.35.35.35",
        }


    def tearDown(self):
        # Stop all patchers
        self.patcher_tf_dir.stop()
        self.patcher_template_dir.stop()
        self.patcher_generated_configs_dir.stop()
        self.patcher_adapter_template.stop()
        self.patcher_registry_template.stop()
        self.patcher_gateway_template.stop()
        self.patcher_subscriber_template.stop()
        self.patcher_registry_admin_template.stop()
        self.patcher_tfvars_template.stop()

        # Stop the logger patch
        patch.stopall()

    def test_should_deploy_adapter(self):
        self.assertTrue(app_config_generator._should_deploy_adapter({"bap": True}))
        self.assertTrue(app_config_generator._should_deploy_adapter({"bpp": True}))
        self.assertTrue(app_config_generator._should_deploy_adapter({"bap": True, "bpp": True}))
        self.assertFalse(app_config_generator._should_deploy_adapter({"gateway": True}))
        self.assertFalse(app_config_generator._should_deploy_adapter({}))

    def testshould_deploy_subscriber(self):
        self.assertTrue(app_config_generator.should_deploy_subscriber({"bap": True}))
        self.assertTrue(app_config_generator.should_deploy_subscriber({"bpp": True}))
        self.assertTrue(app_config_generator.should_deploy_subscriber({"gateway": True}))
        self.assertTrue(app_config_generator.should_deploy_subscriber({"bap": True, "bpp": True, "gateway": True}))
        self.assertFalse(app_config_generator.should_deploy_subscriber({"registry": True}))
        self.assertFalse(app_config_generator.should_deploy_subscriber({}))

    @patch('config.app_config_generator.utils.read_json_file', return_value={
        "project_id": {"value": "test-project"},
        "cluster_region": {"value": "test-region"},
        "redis_instance_ip": {"value": "1.2.3.4"},
        "onix_topic_name": {"value": "onix-topic"},
        "adapter_topic_name": {"value": "adapter-topic"},
        "database_user_sa_email": {"value": "db-user@example.gserviceaccount.com"},
        "registry_admin_database_user_sa_email": {"value": "reg-admin@example.gserviceaccount.com"},
        "registry_database_name": {"value": "reg-db"},
        "registry_db_connection_name": {"value": "reg-conn"},
        "config_bucket_name": {"value": "config-bucket"},
        "url_map": {"value": "mock-url-map"},
        "global_ip_address": {"value": "35.35.35.35"},
    })

    @patch('os.path.join', side_effect=os.path.join)
    def test_load_infrastructure_outputs_success(self, mock_os_path_join, mock_read_json_file):
        """
        Test successful loading of infrastructure outputs.
        """
        expected_path = os.path.join(self.mock_tf_dir, "outputs.json")
        result = app_config_generator._load_infrastructure_outputs(self.mock_tf_dir)

        mock_read_json_file.assert_called_once_with(expected_path)
        self.assertEqual(result, {
            "project_id": "test-project",
            "cluster_region": "test-region",
            "redis_instance_ip": "1.2.3.4",
            "onix_topic_name": "onix-topic",
            "adapter_topic_name": "adapter-topic",
            "database_user_sa_email": "db-user@example.gserviceaccount.com",
            "registry_admin_database_user_sa_email": "reg-admin@example.gserviceaccount.com",
            "registry_database_name": "reg-db",
            "registry_db_connection_name": "reg-conn",
            "config_bucket_name": "config-bucket",
            "url_map": "mock-url-map",
            "global_ip_address": "35.35.35.35",
        })
        self.mock_logger.info.assert_any_call(f"Loading infrastructure outputs from {expected_path}")
        self.mock_logger.info.assert_any_call("Infrastructure outputs loaded successfully.")

    @patch('config.app_config_generator.utils.read_json_file', side_effect=FileNotFoundError("Outputs not found"))
    @patch('os.path.join', side_effect=os.path.join)
    def test_load_infrastructure_outputs_file_not_found(self, mock_os_path_join, mock_read_json_file):
        """
        Test error handling when infrastructure outputs file is not found.
        """
        expected_path = os.path.join(self.mock_tf_dir, "outputs.json")
        with self.assertRaisesRegex(FileNotFoundError, "Outputs not found"):
            app_config_generator._load_infrastructure_outputs(self.mock_tf_dir)
        
        mock_read_json_file.assert_called_once_with(expected_path)
        self.mock_logger.error.assert_called_once()
        self.mock_logger.info.assert_any_call(f"Loading infrastructure outputs from {expected_path}")


    @patch('config.app_config_generator.utils.read_json_file', side_effect=ValueError("Invalid JSON"))
    @patch('os.path.join', side_effect=os.path.join)
    def test_load_infrastructure_outputs_decode_error(self, mock_os_path_join, mock_read_json_file):
        """
        Test error handling when infrastructure outputs JSON is invalid.
        """
        expected_path = os.path.join(self.mock_tf_dir, "outputs.json")
        with self.assertRaisesRegex(ValueError, "Invalid JSON"):
            app_config_generator._load_infrastructure_outputs(self.mock_tf_dir)
        
        mock_read_json_file.assert_called_once_with(expected_path)
        self.mock_logger.error.assert_called_once()
        self.mock_logger.info.assert_any_call(f"Loading infrastructure outputs from {expected_path}")


    @patch('config.app_config_generator.utils.read_json_file', side_effect=RuntimeError("Simulated unexpected error"))
    @patch('os.path.join', side_effect=os.path.join)
    def test_load_infrastructure_outputs_unexpected_error(self, mock_os_path_join, mock_read_json_file):
        """
        Test error handling when an unexpected generic error occurs
        while loading infrastructure outputs.
        """
        expected_path = os.path.join(self.mock_tf_dir, "outputs.json")
        with self.assertRaisesRegex(RuntimeError, "Simulated unexpected error"):
            app_config_generator._load_infrastructure_outputs(self.mock_tf_dir)
        
        mock_read_json_file.assert_called_once_with(expected_path)
        # Verify that logger.exception was called
        self.mock_logger.exception.assert_called_once()
        self.assertIn("An unexpected error occurred while loading infrastructure outputs", 
                        self.mock_logger.exception.call_args[0][0])
        self.mock_logger.info.assert_any_call(f"Loading infrastructure outputs from {expected_path}")


    def test_prepare_template_context(self):
        """
        Test that the Jinja2 context is prepared correctly, including SA email stripping.
        """
        app_req = AppDeploymentRequest(
            app_name="test-app",
            components={"bap": True, "bpp": False, "gateway": True, "registry": False}, # Using string keys
            domain_names={
                "auth_domain": "auth.example.com",
                "adapter": "adapter.example.com",
                "gateway": "gateway.example.com",
                "registry": "registry.example.com"
            },
            image_urls={"adapter": "some-repo/adapter:1.0"},
            registry_url="http://reg.example.com",
            adapter_config=AdapterConfig(enable_schema_validation=True),
            registry_config=RegistryConfig(subscriber_id="test_sub", key_id="test_key", enable_auto_approver=True),
            gateway_config=GatewayConfig(subscriber_id="test_gateway_sub"),
            domain_config=DomainConfig(baseDomain="example.com", domainType="google_domain", dnsZone="example-zone")
        )
        infra_outputs = {
            "project_id": "infra-proj",
            "cluster_region": "infra-region",
            "redis_instance_ip": "10.0.0.1",
            "onix_topic_name": "onix-t",
            "adapter_topic_name": "adapter-t",
            "database_user_sa_email": "user@my-proj.iam.gserviceaccount.com",
            "registry_admin_database_user_sa_email": "admin@my-proj.iam.gserviceaccount.com",
            "registry_database_name": "reg-db",
            "registry_db_connection_name": "reg-conn",
            "config_bucket_name": "config-bucket-name",
            "url_map": "mock-url-map-id",
            "global_ip_address": "35.35.35.35",
        }

        context = app_config_generator._prepare_template_context(app_req, infra_outputs)

        self.assertEqual(context["project_id"], "infra-proj")
        self.assertEqual(context["cluster_region"], "infra-region")
        self.assertEqual(context["redis_instance_ip"], "10.0.0.1")
        self.assertEqual(context["onix_topic_name"], "onix-t")
        self.assertEqual(context["adapter_topic_name"], "adapter-t")
        self.assertEqual(context["database_user_sa_email"], "user@my-proj.iam")
        self.assertEqual(context["registry_admin_database_user_sa_email"], "admin@my-proj.iam")
        self.assertEqual(context["registry_url"], "http://reg.example.com/")
        self.assertEqual(context["domains"], {
                "auth_domain": "auth.example.com",
                "adapter": "adapter.example.com",
                "gateway": "gateway.example.com",
                "registry": "registry.example.com"
            })

        self.assertEqual(context["adapter"], app_req.adapter_config.model_dump())
        self.assertEqual(context["registry"], app_req.registry_config.model_dump())
        self.assertEqual(context["gateway"], app_req.gateway_config.model_dump())

        self.assertTrue(context["deploy_bap"])
        self.assertFalse(context["deploy_bpp"])
        self.assertTrue(context["enable_subscriber"])
        self.assertTrue(context["enable_auto_approver"])
        self.assertEqual(context["url_map"], "mock-url-map-id")
        self.assertTrue(context["is_google_domain"])
        self.assertEqual(context["domain_name"], "example.com")
        self.assertEqual(context["dns_zone"], "example-zone")
        self.assertEqual(context["global_ip_address"], "35.35.35.35")
        self.assertIn("adapter.example.com", context["domain_list"])
        self.assertIn("gateway.example.com", context["domain_list"])

    @patch('config.app_config_generator.os.makedirs')
    @patch('config.app_config_generator.utils.write_file_content')
    @patch('config.app_config_generator.utils.render_jinja_template', return_value="rendered_content")
    @patch('config.app_config_generator._prepare_template_context', return_value={"mock_context": True})
    @patch('config.app_config_generator._load_infrastructure_outputs', return_value={
        "project_id": "test-project", "cluster_name": "test-cluster", "cluster_region": "us-central1",
        "redis_instance_ip": "1.2.3.4", "onix_topic_name": "onix-topic", "adapter_topic_name": "adapter-topic",
        "database_user_sa_email": "db-user@example.gserviceaccount.com", "registry_admin_database_user_sa_email": "reg-admin@example.gserviceaccount.com",
        "registry_database_name": "reg-db", "registry_db_connection_name": "reg-conn", "config_bucket_name": "config-bucket",
        "url_map": "mock-url-map", "global_ip_address": "35.35.35.35",
    })
    @patch('os.path.join', side_effect=os.path.join)
    def test_generate_app_configs_all_components(self, mock_os_path_join, mock_load_infra, mock_prepare_context, mock_render, mock_write_file, mock_makedirs):
        """
        Test generation of app configs when all components that create config files are enabled.
        """
        req = AppDeploymentRequest(
            app_name="test-app",
            components={
                "bap": True,
                "bpp": True,
                "gateway": True,
                "registry": True
            },
            domain_names={},
            image_urls={},
            registry_url="http://mock-reg.com",
            registry_config=RegistryConfig(subscriber_id="sub_id", key_id="key_id"),
            domain_config=DomainConfig(baseDomain="example.com", domainType="google_domain", dnsZone="example-zone")
        )

        app_config_generator.generate_app_configs(req)

        mock_load_infra.assert_called_once_with(self.mock_tf_dir)
        mock_prepare_context.assert_called_once_with(req, mock_load_infra.return_value)
        mock_makedirs.assert_called_once_with(self.mock_generated_configs_dir, exist_ok=True)

        expected_template_source_dir = os.path.join(self.mock_template_dir, 'configs')
        
        expected_render_calls_configs = [
            call(template_dir=expected_template_source_dir, template_name=self.mock_adapter_template, context={"mock_context": True}),
            call(template_dir=expected_template_source_dir, template_name=self.mock_gateway_template, context={"mock_context": True}),
            call(template_dir=expected_template_source_dir, template_name=self.mock_subscriber_template, context={"mock_context": True}),
            call(template_dir=expected_template_source_dir, template_name=self.mock_registry_template, context={"mock_context": True}),
            call(template_dir=expected_template_source_dir, template_name=self.mock_registry_admin_template, context={"mock_context": True}),
        ]
        
        # Test for tfvars template as well
        tf_template_source_dir = os.path.join(self.mock_template_dir, 'tf_configs')
        expected_render_calls_tfvars = [
            call(template_dir=tf_template_source_dir, template_name=self.mock_tfvars_template, context={"mock_context": True}),
        ]

        all_expected_render_calls = sorted(expected_render_calls_configs + expected_render_calls_tfvars, key=lambda c: str(c))
        actual_render_calls = sorted(mock_render.call_args_list, key=lambda c: str(c))
        self.assertEqual(actual_render_calls, all_expected_render_calls)
        self.assertEqual(mock_render.call_count, 6) # 5 app configs + 1 tfvars

        expected_write_calls_configs = [
            call(os.path.join(self.mock_generated_configs_dir, self.mock_adapter_template.replace('.j2', '')), "rendered_content"),
            call(os.path.join(self.mock_generated_configs_dir, self.mock_gateway_template.replace('.j2', '')), "rendered_content"),
            call(os.path.join(self.mock_generated_configs_dir, self.mock_subscriber_template.replace('.j2', '')), "rendered_content"),
            call(os.path.join(self.mock_generated_configs_dir, self.mock_registry_template.replace('.j2', '')), "rendered_content"),
            call(os.path.join(self.mock_generated_configs_dir, self.mock_registry_admin_template.replace('.j2', '')), "rendered_content"),
        ]

        tf_vars_output_dir = os.path.join(self.mock_tf_dir, 'phase2')
        expected_write_calls_tfvars = [
            call(os.path.join(tf_vars_output_dir, self.mock_tfvars_template.replace('.j2', '')), "rendered_content"),
        ]

        all_expected_write_calls = sorted(expected_write_calls_configs + expected_write_calls_tfvars, key=lambda c: str(c))
        actual_write_calls = sorted(mock_write_file.call_args_list, key=lambda c: str(c))
        self.assertEqual(actual_write_calls, all_expected_write_calls)
        self.assertEqual(mock_write_file.call_count, 6)


    @patch('config.app_config_generator.os.makedirs')
    @patch('config.app_config_generator.utils.write_file_content')
    @patch('config.app_config_generator.utils.render_jinja_template', return_value="rendered_content")
    @patch('config.app_config_generator._prepare_template_context', return_value={"mock_context": True})
    @patch('config.app_config_generator._load_infrastructure_outputs', return_value={
        "project_id": "test-project", "cluster_name": "test-cluster", "cluster_region": "us-central1",
        "redis_instance_ip": "1.2.3.4", "onix_topic_name": "onix-topic", "adapter_topic_name": "adapter-topic",
        "database_user_sa_email": "db-user@example.gserviceaccount.com", "registry_admin_database_user_sa_email": "reg-admin@example.gserviceaccount.com",
        "registry_database_name": "reg-db", "registry_db_connection_name": "reg-conn", "config_bucket_name": "config-bucket",
        "url_map": "mock-url-map", "global_ip_address": "35.35.35.35",
    })
    @patch('os.path.join', side_effect=os.path.join)
    def test_generate_app_configs_only_registry(self, mock_os_path_join, mock_load_infra, mock_prepare_context, mock_render, mock_write_file, mock_makedirs):
        """
        Test generation of app configs when only registry component is enabled.
        """
        req = AppDeploymentRequest(
            app_name="test-app",
            components={
                "registry": True
            },
            domain_names={},
            image_urls={},
            registry_url="http://mock-reg.com",
            registry_config=RegistryConfig(subscriber_id="sub_id", key_id="key_id"),
            domain_config=DomainConfig(baseDomain="example.com", domainType="google_domain", dnsZone="example-zone")
        )

        app_config_generator.generate_app_configs(req)

        mock_load_infra.assert_called_once()
        mock_prepare_context.assert_called_once()
        mock_makedirs.assert_called_once()

        expected_template_source_dir = os.path.join(self.mock_template_dir, 'configs')
        expected_render_calls_configs = [
            call(template_dir=expected_template_source_dir, template_name=self.mock_registry_template, context={"mock_context": True}),
            call(template_dir=expected_template_source_dir, template_name=self.mock_registry_admin_template, context={"mock_context": True}),
        ]

        tf_template_source_dir = os.path.join(self.mock_template_dir, 'tf_configs')
        expected_render_calls_tfvars = [
            call(template_dir=tf_template_source_dir, template_name=self.mock_tfvars_template, context={"mock_context": True}),
        ]

        all_expected_render_calls = sorted(expected_render_calls_configs + expected_render_calls_tfvars, key=lambda c: str(c))
        actual_render_calls = sorted(mock_render.call_args_list, key=lambda c: str(c))
        self.assertEqual(actual_render_calls, all_expected_render_calls)
        self.assertEqual(mock_render.call_count, 3) # Registry, Registry-Admin, and tfvars

        expected_write_calls_configs = [
            call(os.path.join(self.mock_generated_configs_dir, self.mock_registry_template.replace('.j2', '')), "rendered_content"),
            call(os.path.join(self.mock_generated_configs_dir, self.mock_registry_admin_template.replace('.j2', '')), "rendered_content"),
        ]

        tf_vars_output_dir = os.path.join(self.mock_tf_dir, 'phase2')
        expected_write_calls_tfvars = [
            call(os.path.join(tf_vars_output_dir, self.mock_tfvars_template.replace('.j2', '')), "rendered_content"),
        ]

        all_expected_write_calls = sorted(expected_write_calls_configs + expected_write_calls_tfvars, key=lambda c: str(c))
        actual_write_calls = sorted(mock_write_file.call_args_list, key=lambda c: str(c))
        self.assertEqual(actual_write_calls, all_expected_write_calls)
        self.assertEqual(mock_write_file.call_count, 3) # Registry, Registry-Admin, and tfvars


    @patch('config.app_config_generator.os.makedirs')
    @patch('config.app_config_generator.utils.write_file_content')
    @patch('config.app_config_generator.utils.render_jinja_template', side_effect=FileNotFoundError("Missing J2"))
    @patch('config.app_config_generator._prepare_template_context', return_value={"mock_context": True})
    @patch('config.app_config_generator._load_infrastructure_outputs', return_value={
        "project_id": "test-project", "cluster_name": "test-cluster", "cluster_region": "us-central1",
        "redis_instance_ip": "1.2.3.4", "onix_topic_name": "onix-topic", "adapter_topic_name": "adapter-topic",
        "database_user_sa_email": "db-user@example.gserviceaccount.com", "registry_admin_database_user_sa_email": "reg-admin@example.gserviceaccount.com",
        "registry_database_name": "reg-db", "registry_db_connection_name": "reg-conn", "config_bucket_name": "config-bucket",
        "url_map": "mock-url-map", "global_ip_address": "35.35.35.35",
    })
    @patch('os.path.join', side_effect=os.path.join)
    def test_generate_app_configs_template_error_propagates(self, mock_os_path_join, mock_load_infra, mock_prepare_context, mock_render, mock_write_file, mock_makedirs):
        """
        Test that FileNotFoundError during template rendering is caught and re-raised.
        """
        req = AppDeploymentRequest(
            app_name="test-app",
            components={"bap": True},
            domain_names={},
            image_urls={},
            registry_url="http://mock-reg.com",
            registry_config=RegistryConfig(subscriber_id="sub_id", key_id="key_id"),
            domain_config=DomainConfig(baseDomain="example.com", domainType="google_domain", dnsZone="example-zone")
        )

        with self.assertRaisesRegex(FileNotFoundError, "Missing J2"):
            app_config_generator.generate_app_configs(req)
        
        mock_render.assert_called_once()
        self.mock_logger.error.assert_called_once()
        mock_write_file.assert_not_called()

    @patch('config.app_config_generator.os.makedirs')
    @patch('config.app_config_generator.utils.write_file_content', side_effect=IOError("No disk space"))
    @patch('config.app_config_generator.utils.render_jinja_template', return_value="content")
    @patch('config.app_config_generator._prepare_template_context', return_value={"mock_context": True})
    @patch('config.app_config_generator._load_infrastructure_outputs', return_value={
        "project_id": "test-project", "cluster_name": "test-cluster", "cluster_region": "us-central1",
        "redis_instance_ip": "1.2.3.4", "onix_topic_name": "onix-topic", "adapter_topic_name": "adapter-topic",
        "database_user_sa_email": "db-user@example.gserviceaccount.com", "registry_admin_database_user_sa_email": "reg-admin@example.gserviceaccount.com",
        "registry_database_name": "reg-db", "registry_db_connection_name": "reg-conn", "config_bucket_name": "config-bucket",
        "url_map": "mock-url-map", "global_ip_address": "35.35.35.35",
    })
    @patch('os.path.join', side_effect=os.path.join)
    def test_generate_app_configs_write_error_propagates(self, mock_os_path_join, mock_load_infra, mock_prepare_context, mock_render, mock_write_file, mock_makedirs):
        """
        Test that IOError during file writing is caught and re-raised.
        """
        req = AppDeploymentRequest(
            app_name="test-app",
            components={"gateway": True},
            domain_names={},
            image_urls={},
            registry_url="http://mock-reg.com",
            registry_config=RegistryConfig(subscriber_id="sub_id", key_id="key_id"),
            domain_config=DomainConfig(baseDomain="example.com", domainType="google_domain", dnsZone="example-zone")
        )

        with self.assertRaisesRegex(IOError, "No disk space"):
            app_config_generator.generate_app_configs(req)
        
        mock_render.assert_called_once()
        mock_write_file.assert_called_once()
        self.mock_logger.error.assert_called_once()

    @patch('config.app_config_generator._should_deploy_adapter', return_value=True)
    @patch('config.app_config_generator.should_deploy_subscriber', return_value=True)
    def test_get_deployment_environment_variables_all_components(self, mockshould_deploy_subscriber, mock_should_deploy_adapter):
        """
        Test that all relevant environment variables are generated correctly for all components.
        """
        req = AppDeploymentRequest(
            app_name="test-app",
            components={
                "bap": True,
                "bpp": True,
                "gateway": True,
                "registry": True
            },
            domain_names={
                "adapter": "adapter.example.com",
                "gateway": "gateway.example.com",
                "registry": "registry.example.com",
                "subscriber": "subscriber.example.com"
            },
            image_urls={
                "adapter": "repo/adapter:latest",
                "registry": "repo/registry:v2",
                "gateway": "repo/gateway:1.0",
                "subscriber": "repo/subscriber:1.0"
            },
            registry_url="http://mock-reg.com",
            registry_config=RegistryConfig(subscriber_id="sub_id", key_id="key_id"),
            domain_config=DomainConfig(baseDomain="example.com", domainType="google_domain", dnsZone="example-zone")
        )

        # Call with an explicit list of services to deploy
        services_to_deploy = ["adapter", "gateway", "registry", "registry-admin", "subscriber"]
        env_vars = app_config_generator.get_deployment_environment_variables(req, services_to_deploy)

        self.assertIn("DEPLOY_SERVICES", env_vars)
        # Components should be sorted alphabetically: adapter, gateway, registry, registry-admin, subscriber
        self.assertEqual(env_vars["DEPLOY_SERVICES"], "adapter,gateway,registry,registry-admin,subscriber")

        self.assertIn("ADAPTER_DOMAIN", env_vars)
        self.assertEqual(env_vars["ADAPTER_DOMAIN"], "adapter.example.com")
        self.assertIn("GATEWAY_DOMAIN", env_vars)
        self.assertEqual(env_vars["GATEWAY_DOMAIN"], "gateway.example.com")
        self.assertIn("REGISTRY_DOMAIN", env_vars)
        self.assertEqual(env_vars["REGISTRY_DOMAIN"], "registry.example.com")
        self.assertIn("SUBSCRIBER_DOMAIN", env_vars)
        self.assertEqual(env_vars["SUBSCRIBER_DOMAIN"], "subscriber.example.com")


        self.assertIn("ADAPTER_IMAGE_URL", env_vars)
        self.assertEqual(env_vars["ADAPTER_IMAGE_URL"], "repo/adapter:latest")
        self.assertIn("REGISTRY_IMAGE_URL", env_vars)
        self.assertEqual(env_vars["REGISTRY_IMAGE_URL"], "repo/registry:v2")
        self.assertIn("GATEWAY_IMAGE_URL", env_vars)
        self.assertEqual(env_vars["GATEWAY_IMAGE_URL"], "repo/gateway:1.0")
        self.assertIn("SUBSCRIBER_IMAGE_URL", env_vars)
        self.assertEqual(env_vars["SUBSCRIBER_IMAGE_URL"], "repo/subscriber:1.0")

        self.assertEqual(env_vars["ENABLE_SCHEMA_VALIDATION"], "false")
        self.assertEqual(len(env_vars), 10) # DEPLOY_SERVICES + 4 Domains + 4 Image URLs + 1 validation flag


    def test_get_deployment_environment_variables_no_components(self):
        """
        Test environment variables when no deployable components are selected.
        """
        req = AppDeploymentRequest(
            app_name="test-app",
            components={},
            domain_names={},
            image_urls={},
            registry_url="http://mock-reg.com",
            registry_config=RegistryConfig(subscriber_id="sub_id", key_id="key_id"),
            domain_config=DomainConfig(baseDomain="example.com", domainType="google_domain", dnsZone="example-zone")
        )
        services_to_deploy = []
        env_vars = app_config_generator.get_deployment_environment_variables(req, services_to_deploy)
        self.assertEqual(env_vars["DEPLOY_SERVICES"], "")
        self.assertEqual(env_vars["ENABLE_SCHEMA_VALIDATION"], "false")
        self.assertEqual(len(env_vars), 2)

    @patch('config.app_config_generator._should_deploy_adapter', return_value=True)
    @patch('config.app_config_generator.should_deploy_subscriber', return_value=True)
    def test_get_deployment_environment_variables_specific_components(self, mockshould_deploy_subscriber, mock_should_deploy_adapter):
        """
        Test environment variables for a subset of components.
        """
        req = AppDeploymentRequest(
            app_name="test-app",
            components={
                "registry": True,
                "bap": True
            },
            domain_names={
                "registry": "reg.example.com",
                "adapter": "adapter.example.com"
            },
            image_urls={
                "registry": "repo/reg:1.0"
            },
            registry_url="http://mock-reg.com",
            registry_config=RegistryConfig(subscriber_id="sub_id", key_id="key_id"),
            domain_config=DomainConfig(baseDomain="example.com", domainType="google_domain", dnsZone="example-zone")
        )
        services_to_deploy = ["adapter", "registry", "registry-admin", "subscriber"]
        env_vars = app_config_generator.get_deployment_environment_variables(req, services_to_deploy)
        
        self.assertEqual(env_vars["DEPLOY_SERVICES"], "adapter,registry,registry-admin,subscriber")
        self.assertEqual(env_vars["REGISTRY_DOMAIN"], "reg.example.com")
        self.assertEqual(env_vars["ADAPTER_DOMAIN"], "adapter.example.com")
        self.assertEqual(env_vars["REGISTRY_IMAGE_URL"], "repo/reg:1.0")
        self.assertEqual(env_vars["ENABLE_SCHEMA_VALIDATION"], "false")
        self.assertEqual(len(env_vars), 5) # DEPLOY_SERVICES + 2 Domains + 1 Image URL + 1 validation flag

    def test_get_deployment_environment_variables_schema_validation_enabled(self):
        """
        Test that ENABLE_SCHEMA_VALIDATION is set to 'true' when enabled in the request.
        """
        req = AppDeploymentRequest(
            app_name="test-app",
            components={"bap": True},
            domain_names={},
            image_urls={},
            registry_url="http://mock-reg.com",
            adapter_config=AdapterConfig(enable_schema_validation=True),
            registry_config=RegistryConfig(subscriber_id="sub_id", key_id="key_id"),
            domain_config=DomainConfig(baseDomain="example.com", domainType="google_domain", dnsZone="example-zone")
        )
        services_to_deploy = ["adapter"]
        env_vars = app_config_generator.get_deployment_environment_variables(req, services_to_deploy)
        self.assertEqual(env_vars["ENABLE_SCHEMA_VALIDATION"], "true")

    @patch('os.path.join', side_effect=os.path.join)
    @patch('config.app_config_generator.utils.read_yaml_file')
    def test_extract_final_urls_with_adapter_modules(self, mock_read_yaml_file, mock_os_path_join):
        """
        Test extracting final URLs, including adapter modules from a mocked adapter.yaml.
        """
        mock_read_yaml_file.return_value = {
            'modules': [
                {'name': 'module1', 'path': '/api/v1/module1'},
                {'name': 'module2', 'path': 'api/v2/module2'},
            ]
        }
        
        domain_names = {
            "adapter": "adapter.example.com",
            "registry": "registry.example.com"
        }
        services = ["adapter", "registry"]

        expected_urls = {
            "adapter": "https://adapter.example.com",
            "adapter_module1": "https://adapter.example.com/api/v1/module1",
            "adapter_module2": "https://adapter.example.com/api/v2/module2",
            "registry": "https://registry.example.com"
        }

        result_urls = app_config_generator.extract_final_urls(domain_names, services)
        self.assertEqual(result_urls, expected_urls)
        mock_read_yaml_file.assert_called_once_with(os.path.join(self.mock_generated_configs_dir, "adapter.yaml"))

        adapter_specific_urls_in_log = {
            "adapter": "https://adapter.example.com",
            "adapter_module1": "https://adapter.example.com/api/v1/module1",
            "adapter_module2": "https://adapter.example.com/api/v2/module2",
        }
        self.mock_logger.debug.assert_any_call(f"Extracted adapter paths from '{os.path.join(self.mock_generated_configs_dir, 'adapter.yaml')}': {adapter_specific_urls_in_log}")


    @patch('os.path.join', side_effect=os.path.join)
    @patch('config.app_config_generator.utils.read_yaml_file', side_effect=FileNotFoundError)
    def test_extract_final_urls_adapter_config_not_found(self, mock_read_yaml_file, mock_os_path_join):
        """
        Test extracting final URLs when adapter.yaml is not found.
        It should fall back to just the base adapter URL.
        """
        domain_names = {
            "adapter": "adapter.example.com",
            "gateway": "gateway.example.com"
        }
        services = ["adapter", "gateway"]

        expected_urls = {
            "adapter": "https://adapter.example.com",
            "gateway": "https://gateway.example.com"
        }

        result_urls = app_config_generator.extract_final_urls(domain_names, services)
        self.assertEqual(result_urls, expected_urls)
        mock_read_yaml_file.assert_called_once_with(os.path.join(self.mock_generated_configs_dir, "adapter.yaml"))
        self.mock_logger.warning.assert_called_with(
            f"Application config YAML for adapter not found at '{os.path.join(self.mock_generated_configs_dir, 'adapter.yaml')}'. Skipping adapter module data extraction."
        )

    @patch('os.path.join', side_effect=os.path.join)
    @patch('config.app_config_generator.utils.read_yaml_file', side_effect=ValueError("Bad YAML"))
    def test_extract_final_urls_adapter_config_invalid_yaml(self, mock_read_yaml_file, mock_os_path_join):
        """
        Test extracting final URLs when adapter.yaml is invalid.
        It should fall back to just the base adapter URL and log an error.
        """
        domain_names = {
            "adapter": "adapter.example.com"
        }
        services = ["adapter"]

        expected_urls = {
            "adapter": "https://adapter.example.com"
        }

        result_urls = app_config_generator.extract_final_urls(domain_names, services)
        self.assertEqual(result_urls, expected_urls)
        mock_read_yaml_file.assert_called_once_with(os.path.join(self.mock_generated_configs_dir, "adapter.yaml"))
        self.mock_logger.error.assert_called_with(
            f"Error parsing application config YAML from '{os.path.join(self.mock_generated_configs_dir, 'adapter.yaml')}': Bad YAML. Skipping adapter module data extraction."
        )

    @patch('os.path.join', side_effect=os.path.join)
    @patch('config.app_config_generator.utils.read_yaml_file', return_value={'not_modules': []})
    def test_extract_final_urls_adapter_config_no_modules_key(self, mock_read_yaml_file, mock_os_path_join):
        """
        Test extracting final URLs when adapter.yaml exists but lacks the 'modules' key.
        """
        domain_names = {"adapter": "adapter.example.com"}
        services = ["adapter"]
        expected_urls = {"adapter": "https://adapter.example.com"}

        result_urls = app_config_generator.extract_final_urls(domain_names, services)
        self.assertEqual(result_urls, expected_urls)
        self.mock_logger.warning.assert_called_once_with(
            f"'modules' key not found or not a list in '{os.path.join(self.mock_generated_configs_dir, 'adapter.yaml')}'. Cannot extract adapter module paths."
        )

    @patch('os.path.join', side_effect=os.path.join)
    @patch('config.app_config_generator.utils.read_yaml_file', return_value={'modules': [{'name': 'm1', 'path': '/p1'}, 'invalid_module']})
    def test_extract_final_urls_adapter_config_invalid_module_entry(self, mock_read_yaml_file, mock_os_path_join):
        """
        Test extracting final URLs when adapter.yaml has invalid module entries.
        It should still process valid ones and skip invalid.
        """
        domain_names = {"adapter": "adapter.example.com"}
        services = ["adapter"]
        expected_urls = {
            "adapter": "https://adapter.example.com",
            "adapter_m1": "https://adapter.example.com/p1"
        }

        result_urls = app_config_generator.extract_final_urls(domain_names, services)
        self.assertEqual(result_urls, expected_urls)


    def test_extract_final_urls_no_domain_found(self):
        """
        Test extract_final_urls when a domain for a service is not found.
        It should skip that service and log a warning.
        """
        domain_names = {"registry": "registry.example.com"}
        services = ["adapter", "registry"]

        expected_urls = {"registry": "https://registry.example.com"}
        result_urls = app_config_generator.extract_final_urls(domain_names, services)

        self.assertEqual(result_urls, expected_urls)
        self.mock_logger.warning.assert_any_call(
            "Domain not found for service 'adapter'. Skipping URL extraction for this service."
        )
        self.mock_logger.debug.assert_any_call("Domain names provided: {'registry': 'registry.example.com'}")
        self.mock_logger.debug.assert_any_call("Generated URL for registry: https://registry.example.com")

    @patch('urllib.parse.quote', side_effect=urllib.parse.quote)
    @patch('config.app_config_generator._load_infrastructure_outputs')
    def test_generate_logs_explorer_urls_success(self, mock_load_infra, mock_quote):
        """
        Test successful generation of Cloud Logs Explorer URLs.
        """
        mock_load_infra.return_value = {
            "project_id": "test-project-id",
            "cluster_name": "test-cluster",
            "cluster_region": "us-central1",
        }
        services = ["adapter", "registry", "my_custom_service"]
        
        expected_logs_explorer_urls = {
            'adapter': 'https://console.cloud.google.com/logs/query;query=resource.type%3D%22k8s_container%22%0Aresource.labels.cluster_name%3D%22test-cluster%22%0Aresource.labels.location%3D%22us-central1%22%0Aresource.labels.container_name%3D%22onix-adapter%22;?project=test-project-id',
            'registry': 'https://console.cloud.google.com/logs/query;query=resource.type%3D%22k8s_container%22%0Aresource.labels.cluster_name%3D%22test-cluster%22%0Aresource.labels.location%3D%22us-central1%22%0Aresource.labels.container_name%3D%22onix-registry%22;?project=test-project-id',
            'my_custom_service': 'https://console.cloud.google.com/logs/query;query=resource.type%3D%22k8s_container%22%0Aresource.labels.cluster_name%3D%22test-cluster%22%0Aresource.labels.location%3D%22us-central1%22%0Aresource.labels.container_name%3D%22onix-my-custom-service%22;?project=test-project-id'
        }

        result_urls = app_config_generator.generate_logs_explorer_urls(services)

        self.assertEqual(result_urls, expected_logs_explorer_urls)
        mock_load_infra.assert_called_once_with(self.mock_tf_dir)

        self.mock_logger.info.assert_any_call("Generating Logs Explorer URLs for services...")
        self.mock_logger.info.assert_any_call("Generated Logs Explorer URLs.")
        self.assertEqual(mock_quote.call_count, 3)


    @patch('config.app_config_generator._load_infrastructure_outputs', side_effect=Exception("Infra load failed"))
    def test_generate_logs_explorer_urls_infra_load_failure(self, mock_load_infra):
        """
        Test that generate_logs_explorer_urls handles infrastructure loading failures gracefully.
        It should return an empty dict and log a warning.
        """
        services = ["adapter"]
        
        result_urls = app_config_generator.generate_logs_explorer_urls(services)

        self.assertEqual(result_urls, {})
        mock_load_infra.assert_called_once_with(self.mock_tf_dir)
        self.mock_logger.warning.assert_called_once()
        self.assertIn("An error occurred while generating Logs Explorer URLs", self.mock_logger.warning.call_args[0][0])
        self.mock_logger.info.assert_any_call("Generating Logs Explorer URLs for services...")
        self.mock_logger.info.assert_any_call("Generated Logs Explorer URLs.")


    @patch('config.app_config_generator._load_infrastructure_outputs')
    def test_generate_logs_explorer_urls_empty_services(self, mock_load_infra):
        """
        Test generating URLs with an empty list of services.
        """
        mock_load_infra.return_value = {
            "project_id": "test-project-id",
            "cluster_name": "test-cluster",
            "cluster_region": "us-central1",
        }
        services = []
        
        result_urls = app_config_generator.generate_logs_explorer_urls(services)

        self.assertEqual(result_urls, {})
        mock_load_infra.assert_called_once_with(self.mock_tf_dir)
        self.mock_logger.info.assert_any_call("Generating Logs Explorer URLs for services...")
        self.mock_logger.info.assert_any_call("Generated Logs Explorer URLs.")


if __name__ == '__main__':
    unittest.main()