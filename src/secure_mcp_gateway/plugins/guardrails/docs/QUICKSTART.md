# Guardrail Plugin System - Quick Start

## 🚀 5-Minute Quick Start

### Using Existing Enkrypt Guardrails (No Changes Needed)

```json
{
  "server_name": "my_server",
  "input_guardrails_policy": {
    "enabled": true,
    "policy_name": "My Policy"
  }
}
```

That's it! Defaults to Enkrypt provider.

---

## Adding a Second Provider

### 1. Register Provider in Config

```json
{
  "common_mcp_gateway_config": {
    "guardrail_plugins": {
      "enabled": true,
      "providers": [
        {
          "name": "openai",
          "type": "openai",
          "config": {"api_key": "your-key"}
        }
      ]
    }
  }
}
```

### 2. Use in Server Config

```json
{
  "server_name": "chat_server",
  "input_guardrails_policy": {
    "enabled": true,
    "provider": "openai-moderation",
    "threshold": 0.8
  }
}
```

---

## Creating Custom Provider

```python
from secure_mcp_gateway.plugins.guardrails import GuardrailProvider

class MyProvider(GuardrailProvider):
    def get_name(self) -> str:
        return "my-provider"

    def create_input_guardrail(self, config):
        return MyInputGuardrail(config)
```

Register:
```python
manager.register_provider(MyProvider())
```

---

## API Reference

```python
# Initialize
from secure_mcp_gateway.plugins.guardrails import initialize_guardrail_system
initialize_guardrail_system(config)

# Get manager
from secure_mcp_gateway.plugins.guardrails import get_guardrail_config_manager
manager = get_guardrail_config_manager()

# Register provider
manager.register_provider(provider)

# List providers
print(manager.list_providers())
```

---

## Documentation

- **COMPLETE_DOCUMENTATION.md** - Everything
- **INTEGRATION_GUIDE.md** - Plugin development
- **CHANGELOG.md** - What's new
- **INDEX.md** - Navigation

---

**Status:** ✅ Production Ready | **Version:** 2.0.0 | **Backward Compatible:** Yes
