# Guardrail Plugin System - Complete Documentation

## Table of Contents

1. [Overview](#overview)
2. [Changes Made](#changes-made)
3. [Current System Architecture](#current-system-architecture)
4. [Plugin Integration Guide](#plugin-integration-guide)
5. [Configuration Reference](#configuration-reference)
6. [Examples](#examples)
7. [Troubleshooting](#troubleshooting)

---

## Overview

The Enkrypt MCP Gateway now features a **pluggable guardrail system** that allows you to:

- Use multiple guardrail providers (Enkrypt, OpenAI, AWS, custom)
- Mix and match different providers for different servers
- Create custom guardrails easily
- Maintain full backward compatibility with existing configurations

### Key Benefits

✅ **Extensible** - Add new providers without modifying core code
✅ **SOLID Principles** - Clean, maintainable architecture
✅ **Type-Safe** - Full type hints and protocols
✅ **Backward Compatible** - Existing configs work unchanged
✅ **Production-Ready** - Comprehensive error handling

---

## Changes Made

### 1. New Plugin System Architecture

#### **Files Created:**

```
src/secure_mcp_gateway/plugins/guardrails/
├── __init__.py                    # Public API exports
├── base.py                        # Core interfaces (SOLID)
├── enkrypt_provider.py            # Enkrypt implementation
├── example_providers.py           # Example implementations
├── config_manager.py              # Configuration management
└── usage_guide.py                 # Complete usage examples
```

#### **Files Modified:**

**`gateway.py`:**
- Added guardrail plugin system initialization
- Loads providers from configuration
- Registers providers with the manager
- Sets global `GUARDRAIL_MANAGER` for services

**`services/guardrail_service.py`:**
- Added plugin-aware methods (`check_input_guardrails`, `check_output_guardrails`)
- Maintains backward compatibility with legacy methods
- Uses lazy imports to avoid circular dependencies

**`plugins/guardrails/config_manager.py`:**
- Flexible initialization accepting both config dict and API key string
- Automatic provider registration
- Configuration validation

### 2. Code Changes Summary

#### **gateway.py Changes:**

**Before:**
```python
# Guardrails were hardcoded to Enkrypt only
 from secure_mcp_gateway.services.guardrails.guardrail_service import guardrail_service
```

**After:**
```python
# Plugin system with multiple providers
from secure_mcp_gateway.plugins.guardrails import (
    initialize_guardrail_system,
    get_guardrail_config_manager,
)

# Initialize system
initialize_guardrail_system(common_config)
guardrail_manager = get_guardrail_config_manager()

# Register additional providers from config
plugin_config = common_config.get("guardrail_plugins", {})
if plugin_config.get("enabled", False):
    for provider_config in plugin_config.get("providers", []):
        # Load and register each provider
        provider = create_provider(provider_config)
        guardrail_manager.register_provider(provider)

# Store globally
guardrail_service.GUARDRAIL_MANAGER = guardrail_manager
```

#### **guardrail_service.py Changes:**

**Before:**
```python
# Only Enkrypt API calls
def call_guardrail_async(self, text, blocks, policy_name):
    # Call Enkrypt API directly
```

**After:**
```python
# Plugin-aware with fallback
async def check_input_guardrails(
    self,
    server_config: Dict[str, Any],
    tool_name: str,
    tool_args: Dict[str, Any]
) -> Dict[str, Any]:
    global GUARDRAIL_MANAGER

    # Get provider-specific guardrail
    if GUARDRAIL_MANAGER is None:
        from secure_mcp_gateway.plugins.guardrails import get_guardrail_config_manager
        GUARDRAIL_MANAGER = get_guardrail_config_manager()

    input_guardrail = GUARDRAIL_MANAGER.get_input_guardrail(server_config)

    # Validate using the appropriate provider
    response = await input_guardrail.validate(request)
```

### 3. Configuration Changes

#### **Before (Enkrypt Only):**

```json
{
  "server_name": "github_server",
  "input_guardrails_policy": {
    "enabled": true,
    "policy_name": "GitHub Policy",
    "block": ["policy_violation"]
  }
}
```

#### **After (Multi-Provider):**

```json
{
  "server_name": "github_server",
  "input_guardrails_policy": {
    "enabled": true,
    "provider": "enkrypt",  // NEW: Specify provider (optional, defaults to enkrypt)
    "policy_name": "GitHub Policy",
    "block": ["policy_violation"]
  }
}
```

---

## Current System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Gateway                           │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │      GuardrailConfigManager (Singleton)            │ │
│  │  • get_input_guardrail(config)                     │ │
│  │  • get_output_guardrail(config)                    │ │
│  │  • register_provider(provider)                     │ │
│  └──────────────┬─────────────────────────────────────┘ │
│                 │                                         │
│      ┌──────────▼──────────┐                            │
│      │ GuardrailRegistry   │                            │
│      │ (Provider Storage)  │                            │
│      └──────────┬──────────┘                            │
│                 │                                         │
│       ┌─────────▼────────────────┐                      │
│       │   GuardrailProvider      │                      │
│       │   (Abstract Interface)   │                      │
│       └─────────┬────────────────┘                      │
│                 │                                         │
│    ┌────────────┼────────────┬──────────────┐          │
│    │            │            │              │          │
│    ▼            ▼            ▼              ▼          │
│ Enkrypt    OpenAI       AWS          CustomProvider   │
│ Provider   Provider   Provider                         │
└─────────────────────────────────────────────────────────┘
```

### Component Description

#### **1. GuardrailProvider (Abstract Base Class)**

Defines the interface all providers must implement:

```python
class GuardrailProvider(ABC):
    @abstractmethod
    def get_name(self) -> str: ...

    @abstractmethod
    def create_input_guardrail(self, config) -> InputGuardrail: ...

    @abstractmethod
    def create_output_guardrail(self, config) -> OutputGuardrail: ...
```

#### **2. InputGuardrail / OutputGuardrail (Protocols)**

Define the interface for guardrail implementations:

```python
class InputGuardrail(Protocol):
    async def validate(self, request: GuardrailRequest) -> GuardrailResponse: ...
    def get_supported_detectors(self) -> List[ViolationType]: ...
```

#### **3. GuardrailRegistry**

Manages all registered providers:

```python
class GuardrailRegistry:
    def register(self, provider: GuardrailProvider) -> None: ...
    def get_provider(self, name: str) -> GuardrailProvider: ...
    def list_providers(self) -> List[str]: ...
```

#### **4. GuardrailConfigManager**

High-level API for using the system:

```python
class GuardrailConfigManager:
    def get_input_guardrail(self, server_config) -> InputGuardrail: ...
    def get_output_guardrail(self, server_config) -> OutputGuardrail: ...
    def register_provider(self, provider) -> None: ...
```

### Data Flow

```
User Request
     │
     ▼
Gateway (gateway.py)
     │
     ▼
GuardrailConfigManager
     │
     ▼
Get Provider by Name
     │
     ▼
Create Guardrail Instance
     │
     ▼
Validate Request/Response
     │
     ▼
Return GuardrailResponse
     │
     ▼
Gateway Decision (Allow/Block)
```

---

## Plugin Integration Guide

### Step 1: Understanding the Provider Interface

Every provider must implement `GuardrailProvider`:

```python
from secure_mcp_gateway.plugins.guardrails import GuardrailProvider

class MyCustomProvider(GuardrailProvider):
    def get_name(self) -> str:
        """Unique provider name"""
        return "my-custom-provider"

    def get_version(self) -> str:
        """Provider version"""
        return "1.0.0"

    def create_input_guardrail(self, config: dict):
        """Create input guardrail instance"""
        if not config.get("enabled", False):
            return None
        return MyInputGuardrail(config)

    def create_output_guardrail(self, config: dict):
        """Create output guardrail instance"""
        return None  # Not implemented
```

### Step 2: Implementing the Guardrail

```python
from secure_mcp_gateway.plugins.guardrails import (
    GuardrailRequest,
    GuardrailResponse,
    GuardrailViolation,
    ViolationType,
    GuardrailAction,
)

class MyInputGuardrail:
    def __init__(self, config: dict):
        self.config = config
        self.threshold = config.get("threshold", 0.8)

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        """Validate the request"""
        violations = []

        # Your custom validation logic
        if len(request.content) > 1000:
            violations.append(
                GuardrailViolation(
                    violation_type=ViolationType.CUSTOM,
                    severity=0.9,
                    message="Content too long",
                    action=GuardrailAction.BLOCK,
                    metadata={"length": len(request.content)}
                )
            )

        is_safe = len(violations) == 0

        return GuardrailResponse(
            is_safe=is_safe,
            action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
            violations=violations,
            metadata={"provider": "my-custom"}
        )

    def get_supported_detectors(self):
        return [ViolationType.CUSTOM]
```

### Step 3: Registering Your Provider

#### **Option A: Register in gateway.py**

```python
# In gateway.py, after guardrail_manager initialization
from mypackage.providers import MyCustomProvider

custom_provider = MyCustomProvider()
guardrail_manager.register_provider(custom_provider)
```

#### **Option B: Register via Configuration**

1. **Add to `enkrypt_mcp_config.json`:**

```json
{
  "common_mcp_gateway_config": {
    "guardrail_plugins": {
      "enabled": true,
      "providers": [
        {
          "name": "my-custom-provider",
          "type": "custom",
          "module": "mypackage.providers.MyCustomProvider",
          "config": {
            "threshold": 0.8,
            "custom_setting": "value"
          }
        }
      ]
    }
  }
}
```

2. **Add loader in gateway.py:**

```python
elif provider_type == "custom":
    module_path = provider_config.get("module")
    provider = load_custom_provider(module_path, provider_cfg)
    if provider:
        guardrail_manager.register_provider(provider)
```

### Step 4: Using Your Provider

```json
{
  "server_name": "my_server",
  "input_guardrails_policy": {
    "enabled": true,
    "provider": "my-custom-provider",
    "threshold": 0.9
  }
}
```

---

## Configuration Reference

### Common MCP Gateway Config

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_api_key": "your-api-key",
    "enkrypt_base_url": "https://api.enkryptai.com",
    "enkrypt_guardrails_enabled": true,

    "guardrail_plugins": {
      "enabled": true,
      "auto_load_defaults": true,
      "providers": [
        {
          "name": "provider-name",
          "type": "openai|keyword|custom",
          "module": "module.path.ProviderClass",  // For custom only
          "config": {
            // Provider-specific configuration
          }
        }
      ]
    }
  }
}
```

### Server Guardrail Config

```json
{
  "server_name": "server_name",
  "input_guardrails_policy": {
    "enabled": true,
    "provider": "enkrypt",           // Optional, defaults to "enkrypt"
    "policy_name": "Policy Name",    // For Enkrypt
    "threshold": 0.8,                // For OpenAI/custom
    "block": ["policy_violation"],   // Violations to block
    "additional_config": {
      "pii_redaction": true
    }
  },
  "output_guardrails_policy": {
    "enabled": true,
    "provider": "enkrypt",
    "policy_name": "Policy Name",
    "block": ["policy_violation"],
    "additional_config": {
      "relevancy": true,
      "adherence": true
    }
  }
}
```

---

## Examples

### Example 1: Basic Enkrypt Usage (Default)

```json
{
  "server_name": "echo_server",
  "input_guardrails_policy": {
    "enabled": true,
    "policy_name": "test pii",
    "block": ["policy_violation"]
  }
}
```

**No `provider` field needed** - defaults to "enkrypt"

### Example 2: OpenAI Moderation

```json
{
  "server_name": "chat_server",
  "input_guardrails_policy": {
    "enabled": true,
    "provider": "openai-moderation",
    "threshold": 0.8,
    "block_categories": ["hate", "violence", "sexual"]
  }
}
```

### Example 3: Custom Keyword Provider

```json
{
  "server_name": "file_server",
  "input_guardrails_policy": {
    "enabled": true,
    "provider": "custom-keyword",
    "blocked_keywords": ["password", "secret", "api_key"],
    "case_sensitive": false
  }
}
```

### Example 4: Different Providers for Different Servers

```json
{
  "mcp_config": [
    {
      "server_name": "github_server",
      "input_guardrails_policy": {
        "enabled": true,
        "provider": "enkrypt",
        "policy_name": "GitHub Policy"
      }
    },
    {
      "server_name": "chat_server",
      "input_guardrails_policy": {
        "enabled": true,
        "provider": "openai-moderation",
        "threshold": 0.8
      }
    },
    {
      "server_name": "file_server",
      "input_guardrails_policy": {
        "enabled": true,
        "provider": "custom-keyword",
        "blocked_keywords": ["secret"]
      }
    }
  ]
}
```

---

## Troubleshooting

### Issue: Provider Not Found

**Error:** `ValueError: Provider 'my-provider' not found`

**Solution:**
```python
# Check registered providers
manager = get_guardrail_config_manager()
print(manager.list_providers())

# Register if missing
manager.register_provider(MyProvider())
```

### Issue: Guardrails Not Being Called

**Symptoms:** Tool calls succeed but no guardrail checks

**Solutions:**
1. Check `enabled: true` in server config
2. Verify provider is registered
3. Check `GUARDRAIL_MANAGER` is set in gateway.py
4. Enable debug logging: `"enkrypt_log_level": "DEBUG"`

### Issue: Import Errors

**Error:** `ImportError: cannot import name 'GuardrailProvider'`

**Solution:**
```python
# Use correct import
from secure_mcp_gateway.plugins.guardrails import (
    GuardrailProvider,
    GuardrailRequest,
    GuardrailResponse,
)
```

### Issue: Configuration Not Loading

**Symptoms:** Provider config ignored

**Solutions:**
1. Check JSON syntax in `enkrypt_mcp_config.json`
2. Verify `"guardrail_plugins": {"enabled": true}`
3. Check provider type spelling
4. Review gateway.py logs for errors

---

## API Reference

### Core Classes

#### GuardrailRequest
```python
@dataclass
class GuardrailRequest:
    content: str                     # Content to validate
    tool_name: Optional[str]         # Tool being called
    tool_args: Optional[dict]        # Tool arguments
    server_name: Optional[str]       # Server name
    context: Optional[dict]          # Additional context
```

#### GuardrailResponse
```python
@dataclass
class GuardrailResponse:
    is_safe: bool                    # Is content safe?
    action: GuardrailAction          # ALLOW, BLOCK, WARN, MODIFY
    violations: List[GuardrailViolation]
    modified_content: Optional[str]  # If content was modified
    metadata: dict                   # Provider metadata
```

#### GuardrailViolation
```python
@dataclass
class GuardrailViolation:
    violation_type: ViolationType    # Type of violation
    severity: float                  # 0.0 to 1.0
    message: str                     # Human-readable message
    action: GuardrailAction          # Suggested action
    metadata: dict                   # Additional context
```

### Enums

#### ViolationType
```python
class ViolationType(Enum):
    PII = "pii"
    INJECTION_ATTACK = "injection_attack"
    TOXIC_CONTENT = "toxicity"
    NSFW_CONTENT = "nsfw"
    KEYWORD_VIOLATION = "keyword_detector"
    POLICY_VIOLATION = "policy_violation"
    BIAS = "bias"
    RELEVANCY_FAILURE = "relevancy"
    ADHERENCE_FAILURE = "adherence"
    HALLUCINATION = "hallucination"
    CUSTOM = "custom"
```

#### GuardrailAction
```python
class GuardrailAction(Enum):
    ALLOW = "allow"      # Continue processing
    BLOCK = "block"      # Stop and return error
    WARN = "warn"        # Log warning but continue
    MODIFY = "modify"    # Modify content and continue
```

---

## Best Practices

### 1. Provider Design

✅ **DO:**
- Implement comprehensive error handling
- Use async/await for I/O operations
- Add detailed logging
- Validate configuration in `validate_config()`
- Return meaningful error messages

❌ **DON'T:**
- Block the event loop with synchronous I/O
- Raise exceptions without handling
- Hardcode configuration values
- Skip input validation

### 2. Configuration

✅ **DO:**
- Use environment variables for sensitive data
- Validate configuration before use
- Provide sensible defaults
- Document all configuration options

❌ **DON'T:**
- Store API keys in code
- Use default passwords in production
- Skip configuration validation

### 3. Performance

✅ **DO:**
- Cache expensive operations
- Use batch operations when possible
- Set appropriate timeouts
- Monitor guardrail latency

❌ **DON'T:**
- Make unnecessary API calls
- Block on slow operations
- Skip timeout configuration

### 4. Security

✅ **DO:**
- Validate all inputs
- Use HTTPS for API calls
- Implement rate limiting
- Log security events

❌ **DON'T:**
- Trust user input
- Skip SSL verification
- Log sensitive data
- Ignore security violations

---

## Summary

The guardrail plugin system provides:

1. **Flexibility** - Use any guardrail provider
2. **Extensibility** - Easy to add custom providers
3. **Maintainability** - Clean SOLID architecture
4. **Compatibility** - Existing configs work unchanged
5. **Production-Ready** - Comprehensive error handling

### Key Files

- `base.py` - Core interfaces
- `enkrypt_provider.py` - Enkrypt implementation
- `config_manager.py` - Configuration management
- `example_providers.py` - Example implementations

### Quick Start

1. Initialize: `initialize_guardrail_system(config)`
2. Register providers: `manager.register_provider(provider)`
3. Configure servers: Add `provider` field to policies
4. Use: System automatically routes to correct provider

**You're ready to build powerful, flexible guardrail systems!** 🎉
