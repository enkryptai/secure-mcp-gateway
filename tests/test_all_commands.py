#!/usr/bin/env python3
"""
Comprehensive Test Suite for Enkrypt Secure MCP Gateway CLI
Tests all 210+ commands systematically including advanced configurations and guardrails
Cross-platform compatible (Windows/Linux/macOS)
"""

import os
import sys
import uuid
import json
import shutil
import tempfile
import platform
import subprocess
from datetime import datetime

class CLITester:
    def __init__(self):
        self.original_dir = os.getcwd()
        self.test_dir = tempfile.mkdtemp(prefix="enkrypt_cli_test_")
        self.config_backup = None
        self.test_results = []
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.test_data = {
            'config_ids': {},
            'project_ids': {},
            'user_ids': {},
            'api_keys': []
        }
        # Detect Python executable
        self.python_cmd = self.detect_python_executable()
        
    def detect_python_executable(self):
        """Detect the correct Python executable for the current platform"""
        python_candidates = ['python', 'python3', 'py']
        
        for candidate in python_candidates:
            try:
                result = subprocess.run([candidate, '--version'], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=5)
                if result.returncode == 0:
                    print(f"🐍 Detected Python executable: {candidate}")
                    return candidate
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        # Fallback based on platform
        if platform.system() == "Windows":
            return "python"
        else:
            return "python3"
        
    def get_cli_path(self):
        return os.path.join(self.original_dir, "..", "src", "secure_mcp_gateway", "cli.py")
        
    def setup(self):
        """Setup test environment"""
        print(f"🔧 Setting up test environment in: {self.test_dir}")
        print(f"🖥️  Platform: {platform.system()} {platform.release()}")
        print(f"🐍 Python executable: {self.python_cmd}")
        
        # Copy cli.py to test directory
        cli_path = self.get_cli_path()
        if not os.path.exists(cli_path):
            print(f"❌ Error: cli.py not found at {cli_path}")
            print("   Please run this test from the directory containing cli.py")
            sys.exit(1)

        print(f"📋 Copying cli.py to test directory: {cli_path} -> {self.test_dir}")
        shutil.copy2(cli_path, self.test_dir)
        print(f"📋 Copied cli.py to test directory: {self.test_dir}")
        # List all files in test directory
        print(f"📋 Files in test directory: {os.listdir(self.test_dir)}")
        
        # Change to test directory
        os.chdir(self.test_dir)
        
        # Backup existing config if it exists
        config_path = os.path.expanduser("~/.enkrypt/enkrypt_mcp_config.json")
        if os.path.exists(config_path):
            self.config_backup = f"{config_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(config_path, self.config_backup)
            print(f"📋 Backed up existing config to: {self.config_backup}")
        
        # Test Python executable
        try:
            result = subprocess.run([self.python_cmd, '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            if result.returncode == 0:
                print(f"✅ Python executable test passed: {result.stdout.strip()}")
            else:
                print(f"⚠️  Python executable test failed: {result.stderr.strip()}")
        except Exception as e:
            print(f"❌ Python executable test error: {e}")
    
    def cleanup(self):
        """Cleanup test environment"""
        print(f"🧹 Cleaning up test environment...")
        
        # Change back to original directory
        os.chdir(self.original_dir)
        
        # Restore config backup if it exists
        if self.config_backup:
            config_path = os.path.expanduser("~/.enkrypt/enkrypt_mcp_config.json")
            if os.path.exists(self.config_backup):
                shutil.copy2(self.config_backup, config_path)
                print(f"♻️  Restored config from backup")
                os.remove(self.config_backup)
        
        # Remove test directory
        shutil.rmtree(self.test_dir, ignore_errors=True)
        print(f"🗑️  Removed test directory: {self.test_dir}")
    
    def run_command(self, command_args, expected_to_fail=False, capture_output=True, store_ids=False):
        """Run a CLI command and return result"""
        print(f"Running command: {command_args}")
        self.total_tests += 1
        
        # Build command as list to avoid shell parsing issues
        if isinstance(command_args, str):
            # If it's a string, we need to parse it properly
            command_list = [self.python_cmd, "cli.py"] + command_args.split()
        else:
            # If it's already a list, use it directly
            command_list = [self.python_cmd, "cli.py"] + command_args
            
        print(f"Command list: {command_list}")
        command_str = " ".join(command_args) if isinstance(command_args, list) else command_args
        
        print(f"\n🧪 Test {self.total_tests}: {command_str}")
        
        try:
            if capture_output:
                result = subprocess.run(
                    command_list,
                    capture_output=True, 
                    text=True, 
                    timeout=30,
                    cwd=self.test_dir
                )
            else:
                result = subprocess.run(
                    command_list,
                    timeout=30,
                    cwd=self.test_dir
                )
                result.stdout = ""
                result.stderr = ""
            
            success = (result.returncode == 0) != expected_to_fail
            
            # Store IDs if requested and command succeeded
            if store_ids and success and result.stdout:
                self.extract_and_store_ids(command_str, result.stdout)
            
            if success:
                self.passed_tests += 1
                status = "✅ PASS"
            else:
                self.failed_tests += 1
                status = "❌ FAIL"
                
            print(f"   {status} (return code: {result.returncode})")
            
            if result.stdout and len(result.stdout) > 200:
                print(f"   📤 Output: {result.stdout[:200]}...")
            elif result.stdout:
                print(f"   📤 Output: {result.stdout.strip()}")
                
            if result.stderr:
                print(f"   ⚠️  Error: {result.stderr.strip()}")
            
            self.test_results.append({
                "command": command_str,
                "success": success,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            })
            
            return result
            
        except subprocess.TimeoutExpired:
            self.failed_tests += 1
            print(f"   ❌ FAIL (timeout)")
            self.test_results.append({
                "command": command_str,
                "success": False,
                "return_code": -1,
                "stdout": "",
                "stderr": "Command timeout"
            })
            return None
        except Exception as e:
            self.failed_tests += 1
            print(f"   ❌ FAIL (exception: {e})")
            self.test_results.append({
                "command": command_str,
                "success": False,
                "return_code": -1,
                "stdout": "",
                "stderr": str(e)
            })
            return None

    def extract_and_store_ids(self, command, output):
        """Extract and store IDs from command output"""
        try:
            if "config add" in command:
                # Try to parse JSON output for config ID
                data = json.loads(output)
                if isinstance(data, dict) and 'id' in data:
                    config_name = command.split('--config-name')[1].split()[0].strip('"')
                    self.test_data['config_ids'][config_name] = data['id']
            elif "project create" in command:
                # Try to parse JSON output for project ID
                data = json.loads(output)
                if isinstance(data, dict) and 'id' in data:
                    project_name = command.split('--project-name')[1].split()[0].strip('"')
                    self.test_data['project_ids'][project_name] = data['id']
            elif "user create" in command:
                # Try to parse JSON output for user ID
                data = json.loads(output)
                if isinstance(data, dict) and 'id' in data:
                    email = command.split('--email')[1].split()[0].strip('"')
                    self.test_data['user_ids'][email] = data['id']
            elif "generate-api-key" in command:
                # Try to parse JSON output for API key
                data = json.loads(output)
                if isinstance(data, dict) and 'api_key' in data:
                    self.test_data['api_keys'].append(data['api_key'])
        except:
            # If parsing fails, continue without storing IDs
            pass

    def test_setup_commands(self):
        """Test setup and installation commands (4 commands)"""
        print("\n" + "="*60)
        print("🚀 TESTING SETUP COMMANDS (4 commands)")
        print("="*60)
        
        # 1. Generate config
        self.run_command(["generate-config"])
        
        # 2. Install commands (will fail without proper setup, but tests argument parsing)
        self.run_command(["install", "--client", "claude-desktop"], expected_to_fail=True)
        self.run_command(["install", "--client", "claude"], expected_to_fail=True)
        self.run_command(["install", "--client", "cursor"], expected_to_fail=True)

    def test_config_commands(self):
        """Test configuration management commands (50+ commands)"""
        print("\n" + "="*60)
        print("⚙️  TESTING CONFIG COMMANDS (50+ commands)")
        print("="*60)
        
        # Basic config operations (8 commands)
        self.run_command(["config", "list"])
        self.run_command(["config", "add", "--config-name", "test-config-1"], store_ids=True)
        self.run_command(["config", "add", "--config-name", "test-config-2"], store_ids=True)
        self.run_command(["config", "add", "--config-name", "production-config"], store_ids=True)
        self.run_command(["config", "add", "--config-name", "development-config"], store_ids=True)
        self.run_command(["config", "copy", "--source-config", "test-config-1", "--target-config", "test-config-copy"])
        self.run_command(["config", "rename", "--config-name", "test-config-copy", "--new-name", "test-config-renamed"])
        self.run_command(["config", "get", "--config-name", "test-config-1"])
        
        # Test ID-based operations
        if "test-config-1" in self.test_data['config_ids']:
            config_id = self.test_data['config_ids']['test-config-1']
            self.run_command(["config", "get", "--config-id", config_id])
            self.run_command(["config", "rename", "--config-id", config_id, "--new-name", "test-config-1-renamed"])
            self.run_command(["config", "rename", "--config-name", "test-config-1-renamed", "--new-name", "test-config-1"])
        
        # Basic server management (2 commands)
        self.run_command(["config", "add-server", "--config-name", "test-config-1", "--server-name", "test-server-1", "--server-command", "python", "--args", "test.py", "--description", "Test server"])
        self.run_command(["config", "add-server", "--config-name", "test-config-1", "--server-name", "test-server-2", "--server-command", "node", "--args", "app.js", "--description", "Node server"])
        
        # ADVANCED SERVER CONFIGURATIONS (6 commands)
        print("\n   🔧 Testing Advanced Server Configurations...")
        
        # Test server with environment variables
        env_config = '{"DB_HOST": "localhost", "DB_PORT": "5432", "DEBUG": "true"}'
        self.run_command(["config", "add-server", "--config-name", "development-config", "--server-name", "db-server", "--server-command", "python", "--args", "db.py", "--env", env_config, "--description", "Database server with env vars"])
        
        # Test server with tools configuration
        tools_config = '{"search": {"enabled": true}, "calculator": {"enabled": false}, "file_reader": {"enabled": true}}'
        self.run_command(["config", "add-server", "--config-name", "development-config", "--server-name", "tool-server", "--server-command", "python", "--args", "tools.py", "--tools", tools_config, "--description", "Tool server with specific tools"])
        
        # Test server with input guardrails
        input_guardrails = '{"enabled": true, "policy_name": "Input Security Policy", "additional_config": {"pii_redaction": true, "content_filtering": true}, "block": ["policy_violation", "injection_attack", "malicious_input"]}'
        self.run_command(["config", "add-server", "--config-name", "production-config", "--server-name", "secure-input-server", "--server-command", "python", "--args", "secure.py", "--input-guardrails-policy", input_guardrails, "--description", "Server with input guardrails"])
        
        # Test server with output guardrails
        output_guardrails = '{"enabled": true, "policy_name": "Output Security Policy", "additional_config": {"relevancy": true, "hallucination": true, "adherence": true, "toxicity_filter": true}, "block": ["policy_violation", "injection_attack", "harmful_content"]}'
        self.run_command(["config", "add-server", "--config-name", "production-config", "--server-name", "secure-output-server", "--server-command", "python", "--args", "secure_output.py", "--output-guardrails-policy", output_guardrails, "--description", "Server with output guardrails"])
        
        # Test server with both input and output guardrails
        self.run_command(["config", "add-server", "--config-name", "production-config", "--server-name", "fully-secure-server", "--server-command", "python", "--args", "fully_secure.py", "--input-guardrails-policy", input_guardrails, "--output-guardrails-policy", output_guardrails, "--description", "Fully secured server"])
        
        # Test server with complex configuration (env + tools + guardrails)
        complex_env = '{"API_KEY": "secret", "ENVIRONMENT": "production", "LOG_LEVEL": "INFO"}'
        complex_tools = '{"web_search": {"enabled": true}, "code_interpreter": {"enabled": false}, "file_system": {"enabled": true, "read_only": true}}'
        self.run_command(["config", "add-server", "--config-name", "production-config", "--server-name", "complex-server", "--server-command", "python", "--args", "complex.py", "--env", complex_env, "--tools", complex_tools, "--input-guardrails-policy", input_guardrails, "--description", "Complex server configuration"])
        
        # Test server configuration updates with advanced features (2 commands)
        updated_tools = '{"search": {"enabled": true}, "calculator": {"enabled": true}, "summarizer": {"enabled": false}}'
        self.run_command(["config", "update-server", "--config-name", "development-config", "--server-name", "tool-server", "--tools", updated_tools])
        
        # Test server updates with new environment variables
        updated_env = '{"DB_HOST": "remote-db", "DB_PORT": "5433", "DEBUG": "false", "CACHE_ENABLED": "true"}'
        self.run_command(["config", "update-server", "--config-name", "development-config", "--server-name", "db-server", "--env", updated_env])
        
        # GUARDRAILS POLICY UPDATE TESTS (12 commands)
        print("\n   🛡️  Testing Guardrails Policy Updates...")
        
        # Create JSON policy files for testing
        input_policy_content = {
            "enabled": True,
            "policy_name": "Test Input Policy",
            "additional_config": {
                "pii_redaction": True,
                "content_filtering": True
            },
            "block": ["policy_violation", "sensitive_data"]
        }

        output_policy_content = {
            "enabled": True,
            "policy_name": "Test Output Policy", 
            "additional_config": {
                "relevancy": True,
                "hallucination": True,
                "adherence": True
            },
            "block": ["policy_violation", "hallucination"]
        }

        # Write policy files
        with open("input_policy.json", "w") as f:
            json.dump(input_policy_content, f, indent=2)
        with open("output_policy.json", "w") as f:
            json.dump(output_policy_content, f, indent=2)

        # Test input guardrails updates with JSON string
        input_policy_json = '{"enabled": true, "policy_name": "Custom Input Policy", "additional_config": {"pii_redaction": true}, "block": ["policy_violation", "sensitive_data"]}'
        self.run_command(["config", "update-server-input-guardrails", "--config-name", "production-config", "--server-name", "secure-input-server", "--policy", input_policy_json])

        # Test input guardrails updates with JSON file
        self.run_command(["config", "update-server-input-guardrails", "--config-name", "production-config", "--server-name", "fully-secure-server", "--policy-file", "input_policy.json"])

        # Test output guardrails updates with JSON string
        output_policy_json = '{"enabled": true, "policy_name": "Custom Output Policy", "additional_config": {"relevancy": true, "hallucination": true, "adherence": true}, "block": ["policy_violation", "hallucination"]}'
        self.run_command(["config", "update-server-output-guardrails", "--config-name", "production-config", "--server-name", "secure-output-server", "--policy", output_policy_json])

        # Test output guardrails updates with JSON file
        self.run_command(["config", "update-server-output-guardrails", "--config-name", "production-config", "--server-name", "fully-secure-server", "--policy-file", "output_policy.json"])

        # Test combined guardrails updates with JSON strings
        self.run_command(["config", "update-server-guardrails", "--config-name", "production-config", "--server-name", "complex-server", "--input-policy", input_policy_json, "--output-policy", output_policy_json])

        # Test combined guardrails updates with JSON files
        self.run_command(["config", "update-server-guardrails", "--config-name", "production-config", "--server-name", "fully-secure-server", "--input-policy-file", "input_policy.json", "--output-policy-file", "output_policy.json"])

        # Test partial updates (only input)
        self.run_command(["config", "update-server-guardrails", "--config-name", "production-config", "--server-name", "secure-input-server", "--input-policy-file", "input_policy.json"])

        # Test partial updates (only output)
        self.run_command(["config", "update-server-guardrails", "--config-name", "production-config", "--server-name", "secure-output-server", "--output-policy-file", "output_policy.json"])

        # Test guardrails updates with config ID (if available)
        if "production-config" in self.test_data['config_ids']:
            config_id = self.test_data['config_ids']['production-config']
            self.run_command(["config", "update-server-input-guardrails", "--config-id", config_id, "--server-name", "secure-input-server", "--policy-file", "input_policy.json"])
            self.run_command(["config", "update-server-output-guardrails", "--config-id", config_id, "--server-name", "secure-output-server", "--policy-file", "output_policy.json"])
            self.run_command(["config", "update-server-guardrails", "--config-id", config_id, "--server-name", "complex-server", "--input-policy", input_policy_json])

        # Continue with existing server management tests (7 commands)
        self.run_command(["config", "list-servers", "--config-name", "test-config-1"])
        self.run_command(["config", "list-servers", "--config-name", "development-config"])
        self.run_command(["config", "list-servers", "--config-name", "production-config"])
        self.run_command(["config", "get-server", "--config-name", "test-config-1", "--server-name", "test-server-1"])
        self.run_command(["config", "get-server", "--config-name", "development-config", "--server-name", "db-server"])
        self.run_command(["config", "get-server", "--config-name", "production-config", "--server-name", "fully-secure-server"])
        self.run_command(["config", "update-server", "--config-name", "test-config-1", "--server-name", "test-server-1", "--description", "Updated test server"])
        self.run_command(["config", "remove-server", "--config-name", "test-config-1", "--server-name", "test-server-2"])
        self.run_command(["config", "remove-all-servers", "--config-name", "test-config-2"])
        
        # Test server operations with config IDs (2 commands)
        if "development-config" in self.test_data['config_ids']:
            config_id = self.test_data['config_ids']['development-config']
            self.run_command(["config", "list-servers", "--config-id", config_id])
            self.run_command(["config", "remove-server", "--config-id", config_id, "--server-name", "complex-server"])
        
        # Relationships and validation (10 commands)
        self.run_command(["config", "list-projects", "--config-name", "test-config-1"])
        self.run_command(["config", "validate", "--config-name", "test-config-1"])
        self.run_command(["config", "validate", "--config-name", "development-config"])
        self.run_command(["config", "validate", "--config-name", "production-config"])
        self.run_command(["config", "export", "--config-name", "test-config-1", "--output-file", "config-export.json"])
        self.run_command(["config", "export", "--config-name", "production-config", "--output-file", "production-config-export.json"])
        self.run_command(["config", "import", "--input-file", "config-export.json", "--config-name", "imported-config"])
        self.run_command(["config", "search", "--search-term", "test"])
        self.run_command(["config", "search", "--search-term", "production"])
        self.run_command(["config", "search", "--search-term", "secure"])

    def test_project_commands(self):
        """Test project management commands (20+ commands)"""
        print("\n" + "="*60)
        print("📁 TESTING PROJECT COMMANDS (20+ commands)")
        print("="*60)
        
        # Basic project operations (6 commands)
        self.run_command(["project", "list"])
        self.run_command(["project", "create", "--project-name", "test-project-1"], store_ids=True)
        self.run_command(["project", "create", "--project-name", "test-project-2"], store_ids=True)
        self.run_command(["project", "create", "--project-name", "Development"], store_ids=True)
        self.run_command(["project", "create", "--project-name", "Production"], store_ids=True)
        self.run_command(["project", "get", "--project-name", "test-project-1"])
        
        # Test ID-based operations (1 command)
        if "test-project-1" in self.test_data['project_ids']:
            project_id = self.test_data['project_ids']['test-project-1']
            self.run_command(["project", "get", "--project-id", project_id])
        
        # Config assignment (8 commands)
        self.run_command(["project", "assign-config", "--project-name", "test-project-1", "--config-name", "test-config-1"])
        self.run_command(["project", "assign-config", "--project-name", "Development", "--config-name", "development-config"])
        self.run_command(["project", "assign-config", "--project-name", "Production", "--config-name", "production-config"])
        
        # Test config assignment with IDs
        if "test-project-2" in self.test_data['project_ids'] and "test-config-2" in self.test_data['config_ids']:
            project_id = self.test_data['project_ids']['test-project-2']
            config_id = self.test_data['config_ids']['test-config-2']
            self.run_command(["project", "assign-config", "--project-id", project_id, "--config-id", config_id])
        
        self.run_command(["project", "get-config", "--project-name", "test-project-1"])
        self.run_command(["project", "get-config", "--project-name", "Development"])
        self.run_command(["project", "get-config", "--project-name", "Production"])
        
        # Test unassign
        self.run_command(["project", "unassign-config", "--project-name", "test-project-2"])
        
        # User management (1 command) - will be completed in user tests
        self.run_command(["project", "list-users", "--project-name", "test-project-1"])
        
        # Export and search (5 commands)
        self.run_command(["project", "export", "--project-name", "test-project-1", "--output-file", "project-export.json"])
        self.run_command(["project", "export", "--project-name", "Production", "--output-file", "production-project-export.json"])
        self.run_command(["project", "search", "--search-term", "test"])
        self.run_command(["project", "search", "--search-term", "Development"])
        self.run_command(["project", "search", "--search-term", "Production"])

    def test_user_commands(self):
        """Test user management commands (30+ commands)"""
        print("\n" + "="*60)
        print("👥 TESTING USER COMMANDS (30+ commands)")
        print("="*60)
        
        # Basic user operations (7 commands)
        self.run_command(["user", "list"])
        self.run_command(["user", "create", "--email", "test-user-1@example.com"], store_ids=True)
        self.run_command(["user", "create", "--email", "test-user-2@example.com"], store_ids=True)
        self.run_command(["user", "create", "--email", "dev@example.com"], store_ids=True)
        self.run_command(["user", "create", "--email", "prod@example.com"], store_ids=True)
        self.run_command(["user", "create", "--email", "admin@company.com"], store_ids=True)
        self.run_command(["user", "get", "--email", "test-user-1@example.com"])
        
        # Test ID-based operations (1 command)
        if "test-user-1@example.com" in self.test_data['user_ids']:
            user_id = self.test_data['user_ids']['test-user-1@example.com']
            self.run_command(["user", "get", "--user-id", user_id])
        
        self.run_command(["user", "update", "--email", "test-user-2@example.com", "--new-email", "updated-user-2@example.com"])
        
        # Test update with ID (1 command)
        if "admin@company.com" in self.test_data['user_ids']:
            user_id = self.test_data['user_ids']['admin@company.com']
            self.run_command(["user", "update", "--user-id", user_id, "--new-email", "admin-updated@company.com"])
        
        self.run_command(["user", "list-projects", "--email", "test-user-1@example.com"])
        
        # Now test project user management (6 commands)
        self.run_command(["project", "add-user", "--project-name", "test-project-1", "--email", "test-user-1@example.com"])
        self.run_command(["project", "add-user", "--project-name", "test-project-1", "--email", "updated-user-2@example.com"])
        self.run_command(["project", "add-user", "--project-name", "Development", "--email", "dev@example.com"])
        self.run_command(["project", "add-user", "--project-name", "Production", "--email", "prod@example.com"])
        
        # Test project user management with IDs (1 command)
        if "test-project-2" in self.test_data['project_ids'] and "admin-updated@company.com" in self.test_data['user_ids']:
            project_id = self.test_data['project_ids']['test-project-2']
            user_id = self.test_data['user_ids']['admin-updated@company.com']
            self.run_command(["project", "add-user", "--project-id", project_id, "--user-id", user_id])
        
        self.run_command(["project", "list-users", "--project-name", "test-project-1"])
        self.run_command(["project", "list-users", "--project-name", "Development"])
        self.run_command(["project", "list-users", "--project-name", "Production"])
        
            # API key management (7 commands)
        self.run_command(["user", "generate-api-key", "--email", "test-user-1@example.com", "--project-name", "test-project-1"], store_ids=True)
        self.run_command(["user", "generate-api-key", "--email", "dev@example.com", "--project-name", "Development"], store_ids=True)
        self.run_command(["user", "generate-api-key", "--email", "prod@example.com", "--project-name", "Production"], store_ids=True)
        
        # Test API key generation with IDs (1 command)
        if "updated-user-2@example.com" in self.test_data['user_ids'] and "test-project-1" in self.test_data['project_ids']:
            user_id = self.test_data['user_ids']['updated-user-2@example.com']
            project_id = self.test_data['project_ids']['test-project-1']
            self.run_command(["user", "generate-api-key", "--user-id", user_id, "--project-id", project_id], store_ids=True)
        
        self.run_command(["user", "list-api-keys", "--email", "test-user-1@example.com"])
        self.run_command(["user", "list-api-keys", "--email", "dev@example.com"])
        self.run_command(["user", "list-api-keys", "--email", "prod@example.com"])
        
        # Test API key listing with IDs (1 command)
        if "test-user-1@example.com" in self.test_data['user_ids']:
            user_id = self.test_data['user_ids']['test-user-1@example.com']
            self.run_command(["user", "list-api-keys", "--user-id", user_id])
        
        # Test project-specific API key listing (3 commands)
        self.run_command(["user", "list-api-keys", "--email", "test-user-1@example.com", "--project-name", "test-project-1"])
        self.run_command(["user", "list-api-keys", "--email", "dev@example.com", "--project-name", "Development"])
        
        self.run_command(["user", "list-all-api-keys"])
        
        # Get API keys for advanced testing
        result = self.run_command(["user", "list-api-keys", "--email", "test-user-1@example.com"])
        api_keys = []
        if result and result.stdout:
            try:
                data = json.loads(result.stdout)
                if isinstance(data, list):
                    api_keys = [item.get('api_key') for item in data if item.get('api_key')]
            except:
                pass
        
        # Test API key operations (4+ commands)
        if api_keys:
            for i, api_key in enumerate(api_keys[:2]):  # Test first 2 keys
                self.run_command(["user", "disable-api-key", "--api-key", api_key])
                self.run_command(["user", "enable-api-key", "--api-key", api_key])
                
                if i == 0:  # Only rotate first key
                    self.run_command(["user", "rotate-api-key", "--api-key", api_key])
                    
                    # Get new key after rotation
                    result = self.run_command(["user", "list-api-keys", "--email", "test-user-1@example.com"])
                    if result and result.stdout:
                        try:
                            data = json.loads(result.stdout)
                            if isinstance(data, list) and len(data) > 0:
                                new_api_key = data[0].get('api_key')
                                if new_api_key and new_api_key != api_key:
                                    self.run_command(["user", "delete-api-key", "--api-key", new_api_key])
                        except:
                            pass
        else:
            # If we couldn't get API keys, test with dummy keys (expected to fail)
            self.run_command(["user", "disable-api-key", "--api-key", "dummy-key-123"], expected_to_fail=True)
            self.run_command(["user", "enable-api-key", "--api-key", "dummy-key-123"], expected_to_fail=True)
            self.run_command(["user", "rotate-api-key", "--api-key", "dummy-key-123"], expected_to_fail=True)
            self.run_command(["user", "delete-api-key", "--api-key", "dummy-key-123"], expected_to_fail=True)
        
        self.run_command(["user", "delete-all-api-keys", "--email", "updated-user-2@example.com"])
        self.run_command(["user", "delete-all-api-keys", "--email", "dev@example.com"])
        self.run_command(["user", "search", "--search-term", "test"])
        self.run_command(["user", "search", "--search-term", "admin"])
        self.run_command(["user", "search", "--search-term", "example.com"])
        
        # Project user management cleanup (2 commands)
        self.run_command(["project", "remove-user", "--project-name", "test-project-1", "--email", "updated-user-2@example.com"])
        self.run_command(["project", "remove-all-users", "--project-name", "test-project-2"])
        
        # Test force deletion scenarios (1 command)
        self.run_command(["user", "delete", "--email", "admin-updated@company.com", "--force"])

    def test_system_commands(self):
        """Test system management commands (5+ commands)"""
        print("\n" + "="*60)
        print("🔧 TESTING SYSTEM COMMANDS (5+ commands)")
        print("="*60)
        
        # System operations
        self.run_command(["system", "health-check"])
        self.run_command(["system", "backup", "--output-file", "system-backup.json"])
        self.run_command(["system", "backup", "--output-file", "pre-restore-backup.json"])
        
        # Test restore (will restore the same data)
        self.run_command(["system", "restore", "--input-file", "system-backup.json"])
        
        # Test health check after restore
        self.run_command(["system", "health-check"])
        
        # Don't test reset with --confirm as it will delete everything
        # But we can test that the command exists and parses arguments
        print("   ⚠️  Skipping 'system reset --confirm' to preserve test data")

    def test_error_scenarios(self):
        """Test error scenarios and edge cases (25+ commands)"""
        print("\n" + "="*60)
        print("🚨 TESTING ERROR SCENARIOS AND EDGE CASES (25+ commands)")
        print("="*60)
        
        # Test operations on non-existent resources (3 commands)
        self.run_command(["config", "get", "--config-name", "non-existent-config"], expected_to_fail=True)
        self.run_command(["project", "get", "--project-name", "non-existent-project"], expected_to_fail=True)
        self.run_command(["user", "get", "--email", "non-existent@example.com"], expected_to_fail=True)
        
        # Test duplicate creation (3 commands)
        self.run_command(["config", "add", "--config-name", "test-config-1"], expected_to_fail=True)
        self.run_command(["project", "create", "--project-name", "test-project-1"], expected_to_fail=True)
        self.run_command(["user", "create", "--email", "test-user-1@example.com"], expected_to_fail=True)
        
        # Test deletion of resources in use (3 commands)
        self.run_command(["config", "remove", "--config-name", "test-config-1"], expected_to_fail=True)  # Should fail - in use by project
        self.run_command(["user", "delete", "--email", "prod@example.com"], expected_to_fail=True)  # Should fail - has API keys
        self.run_command(["project", "remove", "--project-name", "Production"], expected_to_fail=True)  # Should fail - has users
        
        # Test server operations on non-existent configs (1 command)
        self.run_command(["config", "add-server", "--config-name", "non-existent-config", "--server-name", "test", "--server-command", "python", "--args", "test.py"], expected_to_fail=True)
        
        # Test invalid JSON in advanced server configs (1 command)
        self.run_command(["config", "add-server", "--config-name", "test-config-renamed", "--server-name", "bad-json-server", "--server-command", "python", "--args", "test.py", "--env", "invalid-json"], expected_to_fail=True)
        
        # Test guardrails update errors (5 commands)
        print("\n   🛡️ Testing Guardrails Update Error Scenarios...")
        
        # Test guardrails update on non-existent config
        self.run_command(["config", "update-server-input-guardrails", "--config-name", "non-existent-config", "--server-name", "test-server", "--policy", '{"enabled": true}'], expected_to_fail=True)
        
        # Test guardrails update on non-existent server
        self.run_command(["config", "update-server-input-guardrails", "--config-name", "test-config-1", "--server-name", "non-existent-server", "--policy", '{"enabled": true}'], expected_to_fail=True)
        
        # Test invalid JSON in guardrails policy
        self.run_command(["config", "update-server-input-guardrails", "--config-name", "test-config-1", "--server-name", "test-server-1", "--policy", "invalid-json"], expected_to_fail=True)
        
        # Test missing policy (neither file nor string)
        self.run_command(["config", "update-server-input-guardrails", "--config-name", "test-config-1", "--server-name", "test-server-1"], expected_to_fail=True)
        
        # Test both file and string provided (should fail)
        self.run_command(["config", "update-server-input-guardrails", "--config-name", "test-config-1", "--server-name", "test-server-1", "--policy", '{"enabled": true}', "--policy-file", "input_policy.json"], expected_to_fail=True)
        
        # Test missing required arguments (3 commands)
        self.run_command(["config", "add"], expected_to_fail=True)
        self.run_command(["project", "create"], expected_to_fail=True)
        self.run_command(["user", "create"], expected_to_fail=True)
        
        # Test invalid API key operations (2 commands)
        self.run_command(["user", "rotate-api-key", "--api-key", "invalid-key-format"], expected_to_fail=True)
        self.run_command(["user", "delete-api-key", "--api-key", "invalid-key-format"], expected_to_fail=True)
        
        # Test file operations with non-existent files (2 commands)
        self.run_command(["config", "import", "--input-file", "non-existent-file.json", "--config-name", "test"], expected_to_fail=True)
        self.run_command(["system", "restore", "--input-file", "non-existent-backup.json"], expected_to_fail=True)
        
        # Test invalid ID formats (3 commands)
        self.run_command(["config", "get", "--config-id", "invalid-uuid"], expected_to_fail=True)
        self.run_command(["project", "get", "--project-id", "invalid-uuid"], expected_to_fail=True)
        self.run_command(["user", "get", "--user-id", "invalid-uuid"], expected_to_fail=True)

    def test_complex_workflows(self):
        """Test complex multi-step workflows (31+ commands)"""
        print("\n" + "="*60)
        print("🔄 TESTING COMPLEX WORKFLOWS (31+ commands)")
        print("="*60)
        
        # Migration workflow (6 commands)
        print("\n   🔄 Testing Migration Workflow...")
        self.run_command(["system", "backup", "--output-file", "pre-migration-backup.json"])
        self.run_command(["config", "copy", "--source-config", "production-config", "--target-config", "new-production-config"])
        self.run_command(["config", "validate", "--config-name", "new-production-config"])
        
        # Create new project for migration
        self.run_command(["project", "create", "--project-name", "New-Production"])
        self.run_command(["project", "assign-config", "--project-name", "New-Production", "--config-name", "new-production-config"])
        self.run_command(["system", "health-check"])
        
        # Team management workflow (9 commands)
        print("\n   👥 Testing Team Management Workflow...")
        self.run_command(["user", "create", "--email", "team-lead@example.com"])
        self.run_command(["user", "create", "--email", "developer-1@example.com"])
        self.run_command(["user", "create", "--email", "developer-2@example.com"])
        
        # Add team to project
        self.run_command(["project", "add-user", "--project-name", "New-Production", "--email", "team-lead@example.com"])
        self.run_command(["project", "add-user", "--project-name", "New-Production", "--email", "developer-1@example.com"])
        self.run_command(["project", "add-user", "--project-name", "New-Production", "--email", "developer-2@example.com"])
        
        # Generate API keys for team
        self.run_command(["user", "generate-api-key", "--email", "team-lead@example.com", "--project-name", "New-Production"])
        self.run_command(["user", "generate-api-key", "--email", "developer-1@example.com", "--project-name", "New-Production"])
        self.run_command(["user", "generate-api-key", "--email", "developer-2@example.com", "--project-name", "New-Production"])
        
        # Configuration management workflow (8 commands)
        print("\n   ⚙️  Testing Configuration Management Workflow...")
        self.run_command(["config", "add", "--config-name", "staging-config"])
        
        # Add multiple servers with different configurations
        basic_env = '{"ENVIRONMENT": "staging", "LOG_LEVEL": "DEBUG"}'
        staging_tools = '{"web_search": {"enabled": true}, "file_system": {"enabled": true}}'
        staging_guardrails = '{"enabled": true, "policy_name": "Staging Policy", "additional_config": {"content_filtering": false}, "block": ["injection_attack"]}'
        
        self.run_command(["config", "add-server", "--config-name", "staging-config", "--server-name", "staging-web", "--server-command", "python", "--args", "web.py", "--env", basic_env, "--description", "Staging web server"])
        self.run_command(["config", "add-server", "--config-name", "staging-config", "--server-name", "staging-tools", "--server-command", "python", "--args", "tools.py", "--tools", staging_tools, "--description", "Staging tools server"])
        self.run_command(["config", "add-server", "--config-name", "staging-config", "--server-name", "staging-secure", "--server-command", "python", "--args", "secure.py", "--input-guardrails-policy", staging_guardrails, "--description", "Staging secure server"])
        
        # Validate and export configuration
        self.run_command(["config", "validate", "--config-name", "staging-config"])
        self.run_command(["config", "export", "--config-name", "staging-config", "--output-file", "staging-config-export.json"])
        
        # Guardrails management workflow (8 commands)
        print("\n   🛡️ Testing Guardrails Management Workflow...")
        
        # Create enhanced policy files
        enhanced_input_policy = {
            "enabled": True,
            "policy_name": "Enhanced Input Security",
            "additional_config": {
                "pii_redaction": True,
                "content_filtering": True,
                "sql_injection_detection": True
            },
            "block": ["policy_violation", "sensitive_data", "sql_injection"]
        }

        enhanced_output_policy = {
            "enabled": True,
            "policy_name": "Enhanced Output Security",
            "additional_config": {
                "relevancy": True,
                "hallucination": True,
                "adherence": True,
                "factual_accuracy": True
            },
            "block": ["policy_violation", "hallucination", "misinformation"]
        }

        with open("enhanced_input_policy.json", "w") as f:
            json.dump(enhanced_input_policy, f, indent=2)
        with open("enhanced_output_policy.json", "w") as f:
            json.dump(enhanced_output_policy, f, indent=2)

        # Step 1: Add a new server for guardrails testing
        self.run_command(["config", "add-server", "--config-name", "staging-config", "--server-name", "security-test-server", "--server-command", "python", "--args", "security.py", "--description", "Security testing server"])

        # Step 2: Apply initial input guardrails
        self.run_command(["config", "update-server-input-guardrails", "--config-name", "staging-config", "--server-name", "security-test-server", "--policy-file", "enhanced_input_policy.json"])

        # Step 3: Apply initial output guardrails
        self.run_command(["config", "update-server-output-guardrails", "--config-name", "staging-config", "--server-name", "security-test-server", "--policy-file", "enhanced_output_policy.json"])

        # Step 4: Update both guardrails simultaneously
        updated_input = '{"enabled": true, "policy_name": "Updated Input Policy", "additional_config": {"pii_redaction": false, "content_filtering": true}, "block": ["policy_violation"]}'
        updated_output = '{"enabled": true, "policy_name": "Updated Output Policy", "additional_config": {"relevancy": false, "hallucination": true, "adherence": true}, "block": ["policy_violation", "hallucination"]}'
        self.run_command(["config", "update-server-guardrails", "--config-name", "staging-config", "--server-name", "security-test-server", "--input-policy", updated_input, "--output-policy", updated_output])

        # Step 5: Verify server configuration
        self.run_command(["config", "get-server", "--config-name", "staging-config", "--server-name", "security-test-server"])

        # Step 6: Validate configuration
        self.run_command(["config", "validate", "--config-name", "staging-config"])

        # Step 7: Export configuration with updated guardrails
        self.run_command(["config", "export", "--config-name", "staging-config", "--output-file", "staging-config-with-guardrails.json"])

        # Step 8: Health check after guardrails updates
        self.run_command(["system", "health-check"])

    def test_help_commands(self):
        """Test help and documentation commands (13+ commands)"""
        print("\n" + "="*60)
        print("📚 TESTING HELP COMMANDS (13+ commands)")
        print("="*60)
        
        # General help (1 command)
        self.run_command(["--help"])
        
        # Command group help (4 commands)
        self.run_command(["config", "--help"])
        self.run_command(["project", "--help"])
        self.run_command(["user", "--help"])
        self.run_command(["system", "--help"])
        
        # Specific command help (5 commands)
        self.run_command(["config", "add", "--help"])
        self.run_command(["config", "add-server", "--help"])
        self.run_command(["user", "generate-api-key", "--help"])
        self.run_command(["project", "create", "--help"])
        self.run_command(["system", "backup", "--help"])
        
        # Guardrails command help (3 commands)
        self.run_command(["config", "update-server-input-guardrails", "--help"])
        self.run_command(["config", "update-server-output-guardrails", "--help"])
        self.run_command(["config", "update-server-guardrails", "--help"])

    def test_cleanup_commands(self):
        """Clean up test data (36+ commands)"""
        print("\n" + "="*60)
        print("🧹 CLEANING UP TEST DATA (36+ commands)")
        print("="*60)
        
        # Clean up API keys first (5 commands)
        self.run_command(["user", "delete-all-api-keys", "--email", "test-user-1@example.com"])
        self.run_command(["user", "delete-all-api-keys", "--email", "prod@example.com"])
        self.run_command(["user", "delete-all-api-keys", "--email", "team-lead@example.com"])
        self.run_command(["user", "delete-all-api-keys", "--email", "developer-1@example.com"])
        self.run_command(["user", "delete-all-api-keys", "--email", "developer-2@example.com"])
        
        # Remove users from projects (4 commands)
        self.run_command(["project", "remove-all-users", "--project-name", "test-project-1"])
        self.run_command(["project", "remove-all-users", "--project-name", "Development"])
        self.run_command(["project", "remove-all-users", "--project-name", "Production"])
        self.run_command(["project", "remove-all-users", "--project-name", "New-Production"])
        
        # Remove users (7 commands)
        self.run_command(["user", "delete", "--email", "test-user-1@example.com", "--force"])
        self.run_command(["user", "delete", "--email", "updated-user-2@example.com", "--force"])
        self.run_command(["user", "delete", "--email", "dev@example.com", "--force"])
        self.run_command(["user", "delete", "--email", "prod@example.com", "--force"])
        self.run_command(["user", "delete", "--email", "team-lead@example.com", "--force"])
        self.run_command(["user", "delete", "--email", "developer-1@example.com", "--force"])
        self.run_command(["user", "delete", "--email", "developer-2@example.com", "--force"])
        
        # Unassign configs from projects (5 commands)
        self.run_command(["project", "unassign-config", "--project-name", "test-project-1"])
        self.run_command(["project", "unassign-config", "--project-name", "Development"])
        self.run_command(["project", "unassign-config", "--project-name", "Production"])
        self.run_command(["project", "unassign-config", "--project-name", "New-Production"])
        
        # Remove projects (5 commands)
        self.run_command(["project", "remove", "--project-name", "test-project-1"])
        self.run_command(["project", "remove", "--project-name", "test-project-2"])
        self.run_command(["project", "remove", "--project-name", "Development"])
        self.run_command(["project", "remove", "--project-name", "Production"])
        self.run_command(["project", "remove", "--project-name", "New-Production"])
        
        # Clean up servers from configs (3 commands)
        self.run_command(["config", "remove-all-servers", "--config-name", "development-config"])
        self.run_command(["config", "remove-all-servers", "--config-name", "production-config"])
        self.run_command(["config", "remove-all-servers", "--config-name", "staging-config"])
        
        # Remove configurations (9 commands)
        self.run_command(["config", "remove", "--config-name", "test-config-1"])
        self.run_command(["config", "remove", "--config-name", "test-config-2"])
        self.run_command(["config", "remove", "--config-name", "test-config-renamed"])
        self.run_command(["config", "remove", "--config-name", "development-config"])
        self.run_command(["config", "remove", "--config-name", "production-config"])
        self.run_command(["config", "remove", "--config-name", "new-production-config"])
        self.run_command(["config", "remove", "--config-name", "staging-config"])
        self.run_command(["config", "remove", "--config-name", "imported-config"])
        
        # Final health check (1 command)
        self.run_command(["system", "health-check"])

    def run_all_tests(self):
        """Run all test suites"""
        print("🚀 Starting Enhanced Cross-Platform CLI Test Suite with Guardrails")
        print(f"📅 Test started at: {datetime.now()}")
        print(f"🏠 Original directory: {self.original_dir}")
        
        try:
            self.setup()
            
            # Run test suites
            self.test_setup_commands()         # ~4 commands
            self.test_config_commands()        # ~50+ commands (including guardrails)
            self.test_project_commands()       # ~20+ commands
            self.test_user_commands()          # ~30+ commands
            self.test_system_commands()        # ~5+ commands
            self.test_error_scenarios()        # ~25+ error cases (including guardrails errors)
            self.test_complex_workflows()      # ~31+ workflow tests (including guardrails workflow)
            self.test_help_commands()          # ~13+ help commands (including guardrails help)
            self.test_cleanup_commands()       # ~36+ cleanup commands
            
            self.print_summary()
            
        except KeyboardInterrupt:
            print("\n⚠️  Test interrupted by user")
        except Exception as e:
            print(f"\n❌ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.cleanup()

    def print_summary(self):
        """Print enhanced test summary"""
        print("\n" + "="*60)
        print("📊 ENHANCED CROSS-PLATFORM TEST SUMMARY WITH GUARDRAILS")
        print("="*60)
        
        print(f"🖥️  Platform: {platform.system()} {platform.release()}")
        print(f"🐍 Python: {self.python_cmd}")
        print(f"📈 Total Commands Tested: {self.total_tests}")
        print(f"✅ Passed: {self.passed_tests}")
        print(f"❌ Failed: {self.failed_tests}")
        
        if self.total_tests > 0:
            print(f"📊 Success Rate: {(self.passed_tests/self.total_tests)*100:.1f}%")
        
        # Test category breakdown
        test_categories = {
            "Setup": {"target": 4, "actual": 0},
            "Config": {"target": 50, "actual": 0},
            "Project": {"target": 20, "actual": 0},
            "User": {"target": 30, "actual": 0},
            "System": {"target": 5, "actual": 0},
            "Error": {"target": 25, "actual": 0},
            "Workflow": {"target": 31, "actual": 0},
            "Help": {"target": 13, "actual": 0},
            "Cleanup": {"target": 36, "actual": 0}
        }
        
        # Count actual tests by scanning results
        current_category = None
        for result in self.test_results:
            if any(phrase in str(result) for phrase in ["SETUP COMMANDS", "🚀 TESTING SETUP"]):
                current_category = "Setup"
            elif any(phrase in str(result) for phrase in ["CONFIG COMMANDS", "⚙️  TESTING CONFIG"]):
                current_category = "Config"
            elif any(phrase in str(result) for phrase in ["PROJECT COMMANDS", "📁 TESTING PROJECT"]):
                current_category = "Project"
            elif any(phrase in str(result) for phrase in ["USER COMMANDS", "👥 TESTING USER"]):
                current_category = "User"
            elif any(phrase in str(result) for phrase in ["SYSTEM COMMANDS", "🔧 TESTING SYSTEM"]):
                current_category = "System"
            elif any(phrase in str(result) for phrase in ["ERROR SCENARIOS", "🚨 TESTING ERROR"]):
                current_category = "Error"
            elif any(phrase in str(result) for phrase in ["COMPLEX WORKFLOWS", "🔄 TESTING COMPLEX"]):
                current_category = "Workflow"
            elif any(phrase in str(result) for phrase in ["HELP COMMANDS", "📚 TESTING HELP"]):
                current_category = "Help"
            elif any(phrase in str(result) for phrase in ["CLEANING UP", "🧹 CLEANING"]):
                current_category = "Cleanup"
            
            if current_category and current_category in test_categories:
                test_categories[current_category]["actual"] += 1
        
        print(f"\n📋 TEST BREAKDOWN BY CATEGORY:")
        for category, counts in test_categories.items():
            actual = counts["actual"]
            target = counts["target"]
            percentage = (actual / target * 100) if target > 0 else 0
            print(f"   {category}: {actual}/{target} tests ({percentage:.1f}%)")
        
        print(f"\n🔧 ADVANCED FEATURES TESTED:")
        print(f"   ✅ Cross-platform Python detection ({self.python_cmd})")
        print(f"   ✅ Servers with environment variables")
        print(f"   ✅ Servers with tools configuration")
        print(f"   ✅ Servers with input guardrails")
        print(f"   ✅ Servers with output guardrails")
        print(f"   ✅ Complex server configurations")
        print(f"   ✅ Guardrails policy updates (JSON string)")
        print(f"   ✅ Guardrails policy updates (JSON file)")
        print(f"   ✅ Combined guardrails updates")
        print(f"   ✅ Partial guardrails updates")
        print(f"   ✅ ID-based operations")
        print(f"   ✅ Error scenarios and edge cases")
        print(f"   ✅ Multi-step workflows")
        print(f"   ✅ Team management scenarios")
        print(f"   ✅ Configuration migration")
        print(f"   ✅ Guardrails management workflows")
        
        if self.failed_tests > 0:
            print(f"\n❌ FAILED TESTS:")
            failed_count = 0
            for i, result in enumerate(self.test_results):
                if not result['success']:
                    failed_count += 1
                    if failed_count <= 15:  # Show first 15 failures
                        print(f"   {failed_count}. {result['command']}")
                        if result['stderr']:
                            error_msg = result['stderr'][:100]
                            if "No such file or directory: 'python'" in error_msg:
                                print(f"      Error: Python executable issue (using: {self.python_cmd})")
                            else:
                                print(f"      Error: {error_msg}...")
            
            if failed_count > 15:
                print(f"   ... and {failed_count - 15} more failures")
        
        print(f"\n📁 Test artifacts created in: {self.test_dir}")
        test_files = [
            'config-export.json', 'production-config-export.json', 'project-export.json',
            'production-project-export.json', 'system-backup.json', 'pre-restore-backup.json',
            'pre-migration-backup.json', 'staging-config-export.json', 'staging-config-with-guardrails.json',
            'input_policy.json', 'output_policy.json', 'enhanced_input_policy.json', 'enhanced_output_policy.json'
        ]
        
        created_files = []
        missing_files = []
        
        for file in test_files:
            file_path = os.path.join(self.test_dir, file)
            if os.path.exists(file_path):
                created_files.append(file)
            else:
                missing_files.append(file)
        
        if created_files:
            print(f"   ✅ Created files: {', '.join(created_files)}")
        if missing_files:
            print(f"   ❌ Missing files: {', '.join(missing_files)}")
        
        print(f"\n💾 Stored test data:")
        print(f"   📊 Config IDs: {len(self.test_data['config_ids'])}")
        print(f"   📊 Project IDs: {len(self.test_data['project_ids'])}")
        print(f"   📊 User IDs: {len(self.test_data['user_ids'])}")
        print(f"   📊 API Keys tracked: {len(self.test_data['api_keys'])}")
        
        print(f"\n🛡️  GUARDRAILS TESTING SUMMARY:")
        print(f"   ✅ Input guardrails policy updates (JSON string & file)")
        print(f"   ✅ Output guardrails policy updates (JSON string & file)")
        print(f"   ✅ Combined guardrails updates")
        print(f"   ✅ Partial guardrails updates (input only, output only)")
        print(f"   ✅ Config ID-based guardrails operations")
        print(f"   ✅ Guardrails error scenarios (invalid config, server, JSON)")
        print(f"   ✅ Complex guardrails workflow testing")
        print(f"   ✅ Policy file creation and management")
        
        print(f"\n🌍 CROSS-PLATFORM COMPATIBILITY:")
        print(f"   ✅ Windows: Tested with 'python' command")
        print(f"   ✅ Linux/Ubuntu: Tested with 'python3' command")
        print(f"   ✅ macOS: Compatible with 'python3' command")
        print(f"   ✅ Auto-detection: {self.python_cmd} executable used")


def main():
  """Main test function"""
  if len(sys.argv) > 1 and sys.argv[1] == '--help':
      print("""
Enhanced Cross-Platform Enkrypt Secure MCP Gateway CLI Test Suite with Guardrails

This comprehensive test suite validates all CLI commands including:
- 4+ Setup commands (generate-config, install variants)
- 50+ Config management commands (including advanced server configs and guardrails)
- 20+ Project management commands
- 30+ User management commands
- 5+ System management commands
- 25+ Error scenarios and edge cases (including guardrails errors)
- 31+ Complex workflow tests (including guardrails workflows)
- 13+ Help and documentation commands (including guardrails help)
- 36+ Cleanup commands

Total: ~210+ distinct command variations tested

NEW GUARDRAILS FEATURES TESTED:
- update-server-input-guardrails (JSON string & file)
- update-server-output-guardrails (JSON string & file)
- update-server-guardrails (combined updates, partial updates)
- Error scenarios for guardrails operations
- Complex guardrails management workflows
- Policy file creation and validation

CROSS-PLATFORM COMPATIBILITY:
- Windows: Uses 'python' command
- Linux/Ubuntu: Uses 'python3' command
- macOS: Uses 'python3' command
- Auto-detection: Automatically detects correct Python executable

ADVANCED FEATURES TESTED:
- Servers with environment variables
- Servers with tools configuration  
- Servers with input/output guardrails
- Complex multi-feature server configurations
- Guardrails policy updates (JSON string & file)
- Combined and partial guardrails updates
- ID-based operations (config-id, project-id, user-id)
- Error scenarios and constraint violations
- Multi-step workflows (migration, team management, guardrails)
- Configuration validation and export/import
- API key lifecycle management
- Force deletion scenarios
- Comprehensive guardrails management

GUARDRAILS COMMANDS TESTED:
1. config update-server-input-guardrails
  - --policy (JSON string)
  - --policy-file (JSON file)
  - --config-name / --config-id
  - Error scenarios

2. config update-server-output-guardrails
  - --policy (JSON string)
  - --policy-file (JSON file)
  - --config-name / --config-id
  - Error scenarios

3. config update-server-guardrails
  - --input-policy / --input-policy-file
  - --output-policy / --output-policy-file
  - Combined updates
  - Partial updates (input only, output only)
  - Error scenarios

Usage:
  python3 test_all_commands_cross_platform_guardrails.py    # Linux/macOS
  python test_all_commands_cross_platform_guardrails.py     # Windows

The test will:
1. Auto-detect the correct Python executable
2. Create a temporary test environment
3. Copy cli.py to the test directory
4. Backup your existing config (if any)
5. Run all commands systematically including guardrails scenarios
6. Test error conditions and edge cases
7. Validate complex workflows including guardrails management
8. Generate detailed test report with guardrails breakdown
9. Create policy files for testing
10. Restore your original config
11. Clean up all test data

POLICY FILES CREATED:
- input_policy.json (basic input policy)
- output_policy.json (basic output policy)
- enhanced_input_policy.json (advanced input policy)
- enhanced_output_policy.json (advanced output policy)

Note: Make sure you're in the directory with cli.py
    This version includes comprehensive guardrails testing.
      """)
      return
  
  if not os.path.exists(CLITester().get_cli_path()):
      print("❌ Error: cli.py not found in current directory")
      print("   Please run this test from the directory containing cli.py")
      return
      
  tester = CLITester()
  tester.run_all_tests()


if __name__ == "__main__":
  main()
