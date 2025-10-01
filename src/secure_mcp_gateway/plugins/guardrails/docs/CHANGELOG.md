# Changelog - Guardrail Plugin System

## Version 2.0.0 - Guardrail Plugin System

**Release Date:** January 2025

### 🎉 Major Changes

#### **New Plugin Architecture**

Completely redesigned guardrail system following SOLID principles, enabling multiple guardrail providers and custom implementations.

---

## What Changed

### 1. **New Plugin System**

#### Files Added

```

src/secure_mcp_gateway/plugins/guardrails/
├── __init__.py                    # Public API
├── base.py                        # Core interfaces
├── enkrypt_provider.py            # Enkrypt implementation
├── example_providers.py           # Example providers
├── config_manager.py              # Configuration management
├── usage_guide.py                 # Usage examples
├── README.md                      # Documentation
├── INTEGRATION_GUIDE.md           # Integration steps
└── COMPLETE_DOCUMENTATION.md      # Full documentation
```

#### Files Modified

**`src/secure_mcp_gateway/gateway.py`:**

- Added plugin system initialization
- Provider registration from configuration
- Global guardrail manager setup

**`src/secure_mcp_gateway/services/guardrail_service.py`:**

- Added `check_input_guardrails()` method
- Added `check_output_guardrails()` method
- Lazy imports to avoid circular dependencies
- Maintains backward compatibility

### 2. **Architecture Changes**

#### Before (v1.x)

```
Gateway → Guardrail Service → Enkrypt API (hardcoded)
```

#### After (v2.0)

```

Gateway → Config Manager → Provider Registry → Selected Provider
                                  ├── Enkrypt Provider
                                  ├── OpenAI Provider
                                  ├── AWS Provider
                                  └── Custom Provider
```

### 3. **Configuration Changes**

#### New Optional Field

Server configurations now support an optional `provider` field:

```json
{
  "input_guardrails_policy": {
    "enabled": true,
    "provider": "enkrypt",  // NEW (optional, defaults to "enkrypt")
    "policy_name": "Policy Name"
  }
}
```

#### New Plugin Configuration Section

```json
{
  "common_mcp_gateway_config": {
    "guardrail_plugins": {        // NEW
      "enabled": true,
      "providers": [
        {
          "name": "openai-moderation",
          "type": "openai",
          "config": {
            "api_key": "..."
          }
        }
      ]
    }
  }
}
```

---

## Migration Guide

### For Existing Users

**✅ No Action Required!**

All existing configurations work without modification. The system automatically:

- Defaults to "enkrypt" provider if `provider` field is missing
- Uses existing Enkrypt guardrail service
- Maintains all current functionality

### For New Features

To use multiple providers:

1. **Add provider field (optional):**

   ```json
   "provider": "enkrypt"
   ```

2. **Register additional providers in config:**

   ```json
   "guardrail_plugins": {
     "enabled": true,
     "providers": [...]
   }
   ```

---

## New Features

### 1. **Multiple Provider Support**

Use different guardrail providers for different servers:

```json
{
  "mcp_config": [
    {
      "server_name": "server1",
      "input_guardrails_policy": {
        "provider": "enkrypt"
      }
    },
    {
      "server_name": "server2",
      "input_guardrails_policy": {
        "provider": "openai-moderation"
      }
    }
  ]
}
```

### 2. **Custom Provider Support**

Create your own guardrail providers:

```python
from secure_mcp_gateway.plugins.guardrails import GuardrailProvider

class MyProvider(GuardrailProvider):
    def get_name(self) -> str:
        return "my-provider"

    def create_input_guardrail(self, config):
        return MyInputGuardrail(config)
```

### 3. **Composite Providers**

Combine multiple providers:

```python
composite = CompositeGuardrailProvider(
    providers=[enkrypt, openai],
    logic="OR"  # Block if ANY fails
)
```

### 4. **Provider Discovery**

```python
manager = get_guardrail_config_manager()
print(manager.list_providers())  # ['enkrypt', 'openai', ...]
```

---

## API Changes

### New Public APIs

#### In `plugins/guardrails/__init__.py`:

```python
# Core interfaces
from .base import (
    GuardrailProvider,
    InputGuardrail,
    OutputGuardrail,
    PIIHandler,
    GuardrailRequest,
    GuardrailResponse,
    GuardrailViolation,
    ViolationType,
    GuardrailAction,
)

# Management
from .config_manager import (
    GuardrailConfigManager,
    get_guardrail_config_manager,
    initialize_guardrail_system,
)

# Enkrypt provider
from .enkrypt_provider import EnkryptGuardrailProvider
```

### Modified APIs

#### `guardrail_service.py`:

**New Methods:**
```python

async def check_input_guardrails(
    self,
    server_config: Dict[str, Any],
    tool_name: str,
    tool_args: Dict[str, Any]
) -> Dict[str, Any]:
    """Check input using plugin system"""

async def check_output_guardrails(
    self,
    server_config: Dict[str, Any],
    response_content: str,
    original_request: Dict[str, Any]
) -> Dict[str, Any]:
    """Check output using plugin system"""
```

**Existing Methods:** Unchanged (backward compatible)

---

## Breaking Changes

### None! 🎉

This is a **100% backward compatible** release. All existing:

- ✅ Configurations work unchanged
- ✅ API calls work unchanged
- ✅ Behavior works unchanged

---

## Technical Details

### Design Principles

#### SOLID Principles

1. **Single Responsibility**
   - Each class has one clear purpose
   - `GuardrailProvider` → creates guardrails
   - `GuardrailRegistry` → manages providers
   - `GuardrailFactory` → creates instances

2. **Open/Closed**
   - Open for extension (new providers)
   - Closed for modification (core unchanged)

3. **Liskov Substitution**
   - All providers interchangeable
   - Any provider can replace another

4. **Interface Segregation**
   - Separate interfaces for different concerns
   - `InputGuardrail`, `OutputGuardrail`, `PIIHandler`

5. **Dependency Inversion**
   - Depend on abstractions (`GuardrailProvider`)
   - Not concrete implementations

### Performance

- **No Performance Impact** for existing users
- Lazy loading of providers
- Caching at provider level
- Async operations throughout

### Security

- **Enhanced Security** through multiple providers
- Provider isolation
- Configuration validation
- Secure defaults

---

## Examples

### Example 1: Using Enkrypt (No Changes)

```json
{
  "server_name": "echo_server",
  "input_guardrails_policy": {
    "enabled": true,
    "policy_name": "test pii"
  }
}
```

### Example 2: Using OpenAI Moderation

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

### Example 3: Custom Provider

```python
# Create provider
class MyProvider(GuardrailProvider):
    def get_name(self):
        return "my-provider"

# Register
manager = get_guardrail_config_manager()
manager.register_provider(MyProvider())

# Use in config
{
  "input_guardrails_policy": {
    "enabled": true,
    "provider": "my-provider"
  }
}
```

---

## Upgrade Path

### From v1.x to v2.0

1. **No code changes required**
2. **Optional:** Add `provider` field to use new providers
3. **Optional:** Add `guardrail_plugins` section for custom providers

### Testing After Upgrade

```bash
# 1. Start gateway
python src/secure_mcp_gateway/gateway.py

# Expected output:
# ✓ Registered Enkrypt provider
# Registered guardrail providers: ['enkrypt']

# 2. Test existing servers
# All should work as before

# 3. Test new providers (if configured)
# Should see additional providers registered
```

---

## Known Issues

### None Currently

All tests passing. System is production-ready.

---

## Future Enhancements

### Planned for v2.1

- [ ] Auto-loading plugins from directories
- [ ] Plugin marketplace/registry
- [ ] Performance metrics per provider
- [ ] Provider health checks
- [ ] A/B testing between providers

### Under Consideration

- [ ] Provider chaining/pipeline
- [ ] Conditional provider selection
- [ ] Provider fallback mechanisms
- [ ] Real-time provider switching

---

## Contributors

- Initial implementation: Development Team
- Architecture design: Following SOLID principles
- Testing: Comprehensive integration testing

---

## Resources

### Documentation

- `COMPLETE_DOCUMENTATION.md` - Full system documentation
- `README.md` - Quick start guide
- `INTEGRATION_GUIDE.md` - Integration instructions
- `usage_guide.py` - Code examples

### Support

- GitHub Issues: Report bugs
- Documentation: See files above
- Examples: Check `usage_guide.py`

---

## Conclusion

Version 2.0 introduces a powerful, flexible plugin system while maintaining 100% backward compatibility. Users can:

✅ Continue using existing configurations unchanged
✅ Add new providers when needed
✅ Create custom providers easily
✅ Mix and match providers per server

**Upgrade with confidence!** No breaking changes, only new capabilities. 🚀
