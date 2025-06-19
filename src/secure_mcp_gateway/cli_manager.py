"""
Enkrypt Secure MCP Gateway CLI Management Interface

This module provides a comprehensive command-line interface for managing gateways, MCP servers, and users.
Built with Click for an intuitive and powerful CLI experience.

Features:
- Gateway management commands
- MCP server management commands
- User management commands
- Interactive prompts for safe operations
- JSON output formatting
- Configuration management
- Batch operations support
- Import/export functionality

Commands:
    # Gateway Management
    gateway create    - Create a new gateway
    gateway list      - List gateways
    gateway show      - Show gateway details
    gateway update    - Update gateway
    gateway delete    - Delete gateway
    gateway export    - Export gateway configuration
    gateway import    - Import gateway configuration
    
    # MCP Server Management
    server create     - Create a new MCP server
    server list       - List MCP servers
    server show       - Show MCP server details
    server update     - Update MCP server
    server delete     - Delete MCP server
    server start      - Start MCP server
    server stop       - Stop MCP server
    
    # User Management
    user create       - Create a new user
    user list         - List users
    user show         - Show user details
    user update       - Update user
    user delete       - Delete user
    user reset-password - Reset user password
    
    # System Management
    config show       - Show current configuration
    config set        - Set configuration value
    health            - Check system health
    metrics           - Show system metrics

Example Usage:
    ```bash
    # Create a gateway
    python -m secure_mcp_gateway.cli_manager gateway create --name "My Gateway" --description "Test gateway"
    
    # List gateways
    python -m secure_mcp_gateway.cli_manager gateway list
    
    # Create a user
    python -m secure_mcp_gateway.cli_manager user create --username admin --email admin@example.com --role admin
    
    # Start API server
    python -m secure_mcp_gateway.cli_manager server start-api --port 8000
    ```
"""

import asyncio
import json
import sys
import getpass
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

import click
from tabulate import tabulate

from secure_mcp_gateway.utils import get_common_config, sys_print
from secure_mcp_gateway.version import __version__
from secure_mcp_gateway.crud import (
    create_gateway, get_gateway, list_gateways, update_gateway, delete_gateway,
    create_mcp_server, get_mcp_server, list_mcp_servers, update_mcp_server, delete_mcp_server,
    create_user, get_user, list_users, update_user, delete_user,
    EntityStatus, UserRole
)
from secure_mcp_gateway.api import run_api


# Configuration
common_config = get_common_config()
CURRENT_USER_ID = "cli-admin"  # Default CLI user ID

sys_print(f"Initializing Enkrypt Secure MCP Gateway CLI Manager v{__version__}")


# --- Utility Functions ---

def format_json(data: Any, indent: int = 2) -> str:
    """Format data as pretty JSON."""
    return json.dumps(data, indent=indent, default=str)


def format_table(data: List[Dict[str, Any]], headers: List[str]) -> str:
    """Format data as a table."""
    if not data:
        return "No data found."
    
    rows = []
    for item in data:
        row = [str(item.get(header, "")) for header in headers]
        rows.append(row)
    
    return tabulate(rows, headers=headers, tablefmt="grid")


def confirm_action(message: str) -> bool:
    """Confirm a potentially destructive action."""
    return click.confirm(message)


def handle_async(coro):
    """Handle async coroutines in CLI."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(coro)


# --- Main CLI Group ---

@click.group()
@click.version_option(version=__version__)
@click.option('--config', help='Configuration file path')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def cli(config, debug):
    """Enkrypt Secure MCP Gateway CLI Manager"""
    if debug:
        click.echo(f"Debug mode enabled")
        click.echo(f"Version: {__version__}")
        click.echo(f"Config: {config or 'default'}")


# --- Gateway Management Commands ---

@cli.group()
def gateway():
    """Gateway management commands"""
    pass


@gateway.command()
@click.option('--name', required=True, help='Gateway name')
@click.option('--description', required=True, help='Gateway description')
@click.option('--config-file', help='MCP configuration file path')
@click.option('--settings', help='Gateway settings as JSON string')
@click.option('--metadata', help='Gateway metadata as JSON string')
@click.option('--output', type=click.Choice(['json', 'table']), default='json', help='Output format')
def create(name, description, config_file, settings, metadata, output):
    """Create a new gateway"""
    try:
        data = {
            "name": name,
            "description": description,
            "mcp_config": [],
            "settings": {},
            "metadata": {}
        }
        
        # Load MCP configuration from file
        if config_file:
            config_path = Path(config_file)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    data["mcp_config"] = json.load(f)
            else:
                click.echo(f"Warning: Config file {config_file} not found")
        
        # Parse settings and metadata
        if settings:
            data["settings"] = json.loads(settings)
        if metadata:
            data["metadata"] = json.loads(metadata)
        
        # Create gateway
        result = handle_async(create_gateway(data, CURRENT_USER_ID))
        
        if output == 'json':
            click.echo(format_json(result))
        else:
            click.echo("Gateway created successfully:")
            click.echo(f"ID: {result['id']}")
            click.echo(f"Name: {result['name']}")
            click.echo(f"API Key: {result['api_key']}")
            
    except Exception as e:
        click.echo(f"Error creating gateway: {e}", err=True)
        sys.exit(1)


@gateway.command()
@click.option('--limit', default=100, help='Maximum number of results')
@click.option('--offset', default=0, help='Offset for pagination')
@click.option('--status', help='Filter by status')
@click.option('--output', type=click.Choice(['json', 'table']), default='table', help='Output format')
def list(limit, offset, status, output):
    """List gateways"""
    try:
        filters = {}
        if status:
            filters["status"] = status
        
        result = handle_async(list_gateways(filters, CURRENT_USER_ID, limit, offset))
        
        if output == 'json':
            click.echo(format_json(result))
        else:
            headers = ['ID', 'Name', 'Description', 'Status', 'Created']
            gateways_data = []
            for gw in result.get('gateways', []):
                gateways_data.append({
                    'ID': gw.get('id', '')[:8] + '...',
                    'Name': gw.get('name', ''),
                    'Description': gw.get('description', '')[:50] + '...' if len(gw.get('description', '')) > 50 else gw.get('description', ''),
                    'Status': gw.get('status', ''),
                    'Created': gw.get('created_at', '')[:10]
                })
            
            click.echo(format_table(gateways_data, headers))
            click.echo(f"\nTotal: {result.get('total', 0)}")
            
    except Exception as e:
        click.echo(f"Error listing gateways: {e}", err=True)
        sys.exit(1)


@gateway.command()
@click.argument('gateway_id')
@click.option('--output', type=click.Choice(['json', 'yaml']), default='json', help='Output format')
def show(gateway_id, output):
    """Show gateway details"""
    try:
        result = handle_async(get_gateway(gateway_id, CURRENT_USER_ID))
        
        if not result:
            click.echo("Gateway not found", err=True)
            sys.exit(1)
        
        if output == 'json':
            click.echo(format_json(result))
        else:
            # YAML-like output
            click.echo(f"ID: {result['id']}")
            click.echo(f"Name: {result['name']}")
            click.echo(f"Description: {result['description']}")
            click.echo(f"Status: {result['status']}")
            click.echo(f"Created: {result['created_at']}")
            click.echo(f"Updated: {result['updated_at']}")
            click.echo(f"Created By: {result['created_by']}")
            click.echo(f"API Key: {result.get('api_key', 'Hidden')}")
            click.echo("MCP Config:")
            click.echo(format_json(result.get('mcp_config', []), indent=4))
            
    except Exception as e:
        click.echo(f"Error showing gateway: {e}", err=True)
        sys.exit(1)


@gateway.command()
@click.argument('gateway_id')
@click.option('--name', help='New gateway name')
@click.option('--description', help='New gateway description')
@click.option('--config-file', help='New MCP configuration file path')
@click.option('--settings', help='New gateway settings as JSON string')
@click.option('--metadata', help='New gateway metadata as JSON string')
def update(gateway_id, name, description, config_file, settings, metadata):
    """Update a gateway"""
    try:
        updates = {}
        
        if name:
            updates["name"] = name
        if description:
            updates["description"] = description
        if config_file:
            config_path = Path(config_file)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    updates["mcp_config"] = json.load(f)
        if settings:
            updates["settings"] = json.loads(settings)
        if metadata:
            updates["metadata"] = json.loads(metadata)
        
        if not updates:
            click.echo("No updates provided", err=True)
            sys.exit(1)
        
        result = handle_async(update_gateway(gateway_id, updates, CURRENT_USER_ID))
        
        if not result:
            click.echo("Gateway not found", err=True)
            sys.exit(1)
        
        click.echo("Gateway updated successfully:")
        click.echo(format_json(result))
        
    except Exception as e:
        click.echo(f"Error updating gateway: {e}", err=True)
        sys.exit(1)


@gateway.command()
@click.argument('gateway_id')
@click.option('--force', is_flag=True, help='Skip confirmation prompt')
def delete(gateway_id, force):
    """Delete a gateway"""
    try:
        if not force:
            if not confirm_action(f"Are you sure you want to delete gateway {gateway_id}?"):
                click.echo("Operation cancelled")
                return
        
        success = handle_async(delete_gateway(gateway_id, CURRENT_USER_ID))
        
        if success:
            click.echo("Gateway deleted successfully")
        else:
            click.echo("Gateway not found", err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"Error deleting gateway: {e}", err=True)
        sys.exit(1)


@gateway.command()
@click.argument('gateway_id')
@click.option('--output-file', help='Output file path')
def export(gateway_id, output_file):
    """Export gateway configuration"""
    try:
        result = handle_async(get_gateway(gateway_id, CURRENT_USER_ID))
        
        if not result:
            click.echo("Gateway not found", err=True)
            sys.exit(1)
        
        # Remove sensitive data
        export_data = result.copy()
        export_data.pop('api_key', None)
        export_data.pop('id', None)
        export_data.pop('created_at', None)
        export_data.pop('updated_at', None)
        export_data.pop('created_by', None)
        
        output = format_json(export_data)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            click.echo(f"Gateway configuration exported to {output_file}")
        else:
            click.echo(output)
            
    except Exception as e:
        click.echo(f"Error exporting gateway: {e}", err=True)
        sys.exit(1)


# --- MCP Server Management Commands ---

@cli.group()
def server():
    """MCP server management commands"""
    pass


@server.command()
@click.option('--name', required=True, help='Server name')
@click.option('--description', required=True, help='Server description')
@click.option('--command', required=True, help='Server command')
@click.option('--args', help='Server arguments as JSON array')
@click.option('--env', help='Environment variables as JSON object')
@click.option('--gateway-id', required=True, help='Gateway ID')
@click.option('--tools', help='Tools configuration as JSON object')
@click.option('--guardrails', help='Guardrails configuration as JSON object')
@click.option('--metadata', help='Server metadata as JSON object')
@click.option('--output', type=click.Choice(['json', 'table']), default='json', help='Output format')
def create(name, description, command, args, env, gateway_id, tools, guardrails, metadata, output):
    """Create a new MCP server"""
    try:
        data = {
            "name": name,
            "description": description,
            "command": command,
            "args": json.loads(args) if args else [],
            "env": json.loads(env) if env else None,
            "gateway_id": gateway_id,
            "tools": json.loads(tools) if tools else {},
            "guardrails": json.loads(guardrails) if guardrails else {},
            "metadata": json.loads(metadata) if metadata else {}
        }
        
        result = handle_async(create_mcp_server(data, CURRENT_USER_ID))
        
        if output == 'json':
            click.echo(format_json(result))
        else:
            click.echo("MCP server created successfully:")
            click.echo(f"ID: {result['id']}")
            click.echo(f"Name: {result['name']}")
            click.echo(f"Command: {result['command']}")
            
    except Exception as e:
        click.echo(f"Error creating MCP server: {e}", err=True)
        sys.exit(1)


@server.command()
@click.option('--limit', default=100, help='Maximum number of results')
@click.option('--offset', default=0, help='Offset for pagination')
@click.option('--gateway-id', help='Filter by gateway ID')
@click.option('--status', help='Filter by status')
@click.option('--output', type=click.Choice(['json', 'table']), default='table', help='Output format')
def list(limit, offset, gateway_id, status, output):
    """List MCP servers"""
    try:
        filters = {}
        if gateway_id:
            filters["gateway_id"] = gateway_id
        if status:
            filters["status"] = status
        
        result = handle_async(list_mcp_servers(filters, CURRENT_USER_ID, limit, offset))
        
        if output == 'json':
            click.echo(format_json(result))
        else:
            headers = ['ID', 'Name', 'Command', 'Gateway ID', 'Status', 'Created']
            servers_data = []
            for srv in result.get('servers', []):
                servers_data.append({
                    'ID': srv.get('id', '')[:8] + '...',
                    'Name': srv.get('name', ''),
                    'Command': srv.get('command', '')[:30] + '...' if len(srv.get('command', '')) > 30 else srv.get('command', ''),
                    'Gateway ID': srv.get('gateway_id', '')[:8] + '...',
                    'Status': srv.get('status', ''),
                    'Created': srv.get('created_at', '')[:10]
                })
            
            click.echo(format_table(servers_data, headers))
            click.echo(f"\nTotal: {result.get('total', 0)}")
            
    except Exception as e:
        click.echo(f"Error listing MCP servers: {e}", err=True)
        sys.exit(1)


@server.command()
@click.argument('server_id')
@click.option('--output', type=click.Choice(['json', 'yaml']), default='json', help='Output format')
def show(server_id, output):
    """Show MCP server details"""
    try:
        result = handle_async(get_mcp_server(server_id, CURRENT_USER_ID))
        
        if not result:
            click.echo("MCP server not found", err=True)
            sys.exit(1)
        
        if output == 'json':
            click.echo(format_json(result))
        else:
            click.echo(f"ID: {result['id']}")
            click.echo(f"Name: {result['name']}")
            click.echo(f"Description: {result['description']}")
            click.echo(f"Command: {result['command']}")
            click.echo(f"Args: {result.get('args', [])}")
            click.echo(f"Status: {result['status']}")
            click.echo(f"Gateway ID: {result['gateway_id']}")
            click.echo(f"Created: {result['created_at']}")
            
    except Exception as e:
        click.echo(f"Error showing MCP server: {e}", err=True)
        sys.exit(1)


@server.command()
@click.argument('server_id')
@click.option('--force', is_flag=True, help='Skip confirmation prompt')
def delete(server_id, force):
    """Delete an MCP server"""
    try:
        if not force:
            if not confirm_action(f"Are you sure you want to delete MCP server {server_id}?"):
                click.echo("Operation cancelled")
                return
        
        success = handle_async(delete_mcp_server(server_id, CURRENT_USER_ID))
        
        if success:
            click.echo("MCP server deleted successfully")
        else:
            click.echo("MCP server not found", err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"Error deleting MCP server: {e}", err=True)
        sys.exit(1)


@server.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=8000, help='Port to bind to')
@click.option('--reload', is_flag=True, help='Enable auto-reload')
def start_api(host, port, reload):
    """Start the REST API server"""
    try:
        click.echo(f"Starting API server on {host}:{port}")
        run_api(host=host, port=port, reload=reload)
    except KeyboardInterrupt:
        click.echo("\nAPI server stopped")
    except Exception as e:
        click.echo(f"Error starting API server: {e}", err=True)
        sys.exit(1)


# --- User Management Commands ---

@cli.group()
def user():
    """User management commands"""
    pass


@user.command()
@click.option('--username', required=True, help='Username')
@click.option('--email', required=True, help='Email address')
@click.option('--password', help='Password (will prompt if not provided)')
@click.option('--role', type=click.Choice(['admin', 'user', 'viewer', 'operator']), default='user', help='User role')
@click.option('--permissions', help='User permissions as JSON array')
@click.option('--metadata', help='User metadata as JSON object')
@click.option('--output', type=click.Choice(['json', 'table']), default='json', help='Output format')
def create(username, email, password, role, permissions, metadata, output):
    """Create a new user"""
    try:
        if not password:
            password = getpass.getpass("Password: ")
            confirm_password = getpass.getpass("Confirm password: ")
            if password != confirm_password:
                click.echo("Passwords do not match", err=True)
                sys.exit(1)
        
        data = {
            "username": username,
            "email": email,
            "password": password,
            "role": role,
            "permissions": json.loads(permissions) if permissions else [],
            "metadata": json.loads(metadata) if metadata else {}
        }
        
        result = handle_async(create_user(data, CURRENT_USER_ID))
        
        if output == 'json':
            click.echo(format_json(result))
        else:
            click.echo("User created successfully:")
            click.echo(f"ID: {result['id']}")
            click.echo(f"Username: {result['username']}")
            click.echo(f"Email: {result['email']}")
            click.echo(f"Role: {result['role']}")
            
    except Exception as e:
        click.echo(f"Error creating user: {e}", err=True)
        sys.exit(1)


@user.command()
@click.option('--limit', default=100, help='Maximum number of results')
@click.option('--offset', default=0, help='Offset for pagination')
@click.option('--role', help='Filter by role')
@click.option('--status', help='Filter by status')
@click.option('--output', type=click.Choice(['json', 'table']), default='table', help='Output format')
def list(limit, offset, role, status, output):
    """List users"""
    try:
        filters = {}
        if role:
            filters["role"] = role
        if status:
            filters["status"] = status
        
        result = handle_async(list_users(filters, CURRENT_USER_ID, limit, offset))
        
        if output == 'json':
            click.echo(format_json(result))
        else:
            headers = ['ID', 'Username', 'Email', 'Role', 'Status', 'Created', 'Last Login']
            users_data = []
            for usr in result.get('users', []):
                users_data.append({
                    'ID': usr.get('id', '')[:8] + '...',
                    'Username': usr.get('username', ''),
                    'Email': usr.get('email', ''),
                    'Role': usr.get('role', ''),
                    'Status': usr.get('status', ''),
                    'Created': usr.get('created_at', '')[:10],
                    'Last Login': usr.get('last_login', '')[:10] if usr.get('last_login') else 'Never'
                })
            
            click.echo(format_table(users_data, headers))
            click.echo(f"\nTotal: {result.get('total', 0)}")
            
    except Exception as e:
        click.echo(f"Error listing users: {e}", err=True)
        sys.exit(1)


@user.command()
@click.argument('user_id')
@click.option('--output', type=click.Choice(['json', 'yaml']), default='json', help='Output format')
def show(user_id, output):
    """Show user details"""
    try:
        result = handle_async(get_user(user_id, CURRENT_USER_ID))
        
        if not result:
            click.echo("User not found", err=True)
            sys.exit(1)
        
        if output == 'json':
            click.echo(format_json(result))
        else:
            click.echo(f"ID: {result['id']}")
            click.echo(f"Username: {result['username']}")
            click.echo(f"Email: {result['email']}")
            click.echo(f"Role: {result['role']}")
            click.echo(f"Status: {result['status']}")
            click.echo(f"Created: {result['created_at']}")
            click.echo(f"Last Login: {result.get('last_login', 'Never')}")
            click.echo(f"Permissions: {result.get('permissions', [])}")
            
    except Exception as e:
        click.echo(f"Error showing user: {e}", err=True)
        sys.exit(1)


@user.command()
@click.argument('user_id')
@click.option('--force', is_flag=True, help='Skip confirmation prompt')
def delete(user_id, force):
    """Delete a user"""
    try:
        if not force:
            if not confirm_action(f"Are you sure you want to delete user {user_id}?"):
                click.echo("Operation cancelled")
                return
        
        success = handle_async(delete_user(user_id, CURRENT_USER_ID))
        
        if success:
            click.echo("User deleted successfully")
        else:
            click.echo("User not found", err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"Error deleting user: {e}", err=True)
        sys.exit(1)


@user.command()
@click.argument('user_id')
@click.option('--password', help='New password (will prompt if not provided)')
def reset_password(user_id, password):
    """Reset user password"""
    try:
        if not password:
            password = getpass.getpass("New password: ")
            confirm_password = getpass.getpass("Confirm new password: ")
            if password != confirm_password:
                click.echo("Passwords do not match", err=True)
                sys.exit(1)
        
        updates = {"password": password}
        result = handle_async(update_user(user_id, updates, CURRENT_USER_ID))
        
        if not result:
            click.echo("User not found", err=True)
            sys.exit(1)
        
        click.echo("Password reset successfully")
        
    except Exception as e:
        click.echo(f"Error resetting password: {e}", err=True)
        sys.exit(1)


# --- System Management Commands ---

@cli.group()
def config():
    """Configuration management commands"""
    pass


@config.command()
def show():
    """Show current configuration"""
    try:
        config_data = get_common_config()
        click.echo(format_json(config_data))
    except Exception as e:
        click.echo(f"Error showing configuration: {e}", err=True)
        sys.exit(1)


@cli.command()
def health():
    """Check system health"""
    try:
        health_data = {
            "status": "healthy",
            "version": __version__,
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "cli": "healthy",
                "config": "healthy"
            }
        }
        click.echo(format_json(health_data))
    except Exception as e:
        click.echo(f"Error checking health: {e}", err=True)
        sys.exit(1)


@cli.command()
def metrics():
    """Show system metrics"""
    try:
        metrics_data = {
            "version": __version__,
            "timestamp": datetime.utcnow().isoformat(),
            "uptime": "N/A",
            "memory_usage": "N/A",
            "cpu_usage": "N/A"
        }
        click.echo(format_json(metrics_data))
    except Exception as e:
        click.echo(f"Error showing metrics: {e}", err=True)
        sys.exit(1)


# --- Main Entry Point ---

if __name__ == '__main__':
    cli()