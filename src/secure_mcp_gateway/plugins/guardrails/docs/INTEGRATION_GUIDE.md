# Plugin Integration Guide

## Quick Start - Adding Custom Guardrail Providers

This guide shows you how to create and integrate custom guardrail providers into the Enkrypt MCP Gateway.

---

## Table of Contents

1. [Understanding the System](#understanding-the-system)
2. [Creating Your First Provider](#creating-your-first-provider)
3. [Registering Your Provider](#registering-your-provider)
4. [Using Your Provider](#using-your-provider)
5. [Advanced Patterns](#advanced-patterns)
6. [Testing](#testing)

---

## Understanding the System

### Architecture Overview

```
Your Provider
     ↓
GuardrailProvider (Interface)
     ↓
GuardrailRegistry
     ↓
GuardrailConfigManager
     ↓
Gateway (Uses Provider)
```

### Key Concepts

1. **GuardrailProvider** - Interface your provider implements
2. **InputGuardrail** - Validates requests before execution
3. **OutputGuardrail** - Validates responses after execution
4. **GuardrailRequest** - Input data structure
5. **GuardrailResponse** - Output data structure

---

## Creating Your First Provider

### Step 1: Create Provider Class

```python
from typing import Dict, Any, Optional
from secure_mcp_gateway.plugins.guardrails import (
    GuardrailProvider,
    GuardrailRequest,
    GuardrailResponse,
    GuardrailViolation,
    ViolationType,
    GuardrailAction,
)

class MyCustomProvider(GuardrailProvider):
    """My custom guardrail provider."""

    def __init__(self, api_key: str = None, **config):
        self.api_key = api_key
        self.config = config

    def get_name(self) -> str:
        """Unique provider name."""
        return "my-custom-provider"

    def get_version(self) -> str:
        """Provider version."""
        return "1.0.0"

    def create_input_guardrail(self, config: Dict[str, Any]):
        """Create input guardrail instance."""
        if not config.get("enabled", False):
            return None
        return MyInputGuardrail(config)

    def create_output_guardrail(self, config: Dict[str, Any]):
        """Create output guardrail instance (optional)."""
        return None  # Not implemented
```

### Step 2: Implement Input Guardrail

```python
class MyInputGuardrail:
    """Custom input guardrail implementation."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.max_length = config.get("max_length", 1000)

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        """Validate the request."""
        violations = []

        # Your custom validation logic
        if len(request.content) > self.max_length:
            violations.append(
                GuardrailViolation(
                    violation_type=ViolationType.CUSTOM,
                    severity=0.9,
                    message=f"Content exceeds {self.max_length} characters",
                    action=GuardrailAction.BLOCK,
                    metadata={"length": len(request.content)}
                )
            )

        is_safe = len(violations) == 0

        return GuardrailResponse(
            is_safe=is_safe,
            action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
            violations=violations,
            metadata={"provider": "my-custom-provider"}
        )

    def get_supported_detectors(self):
        """List of supported violation types."""
        return [ViolationType.CUSTOM]
```

---

## Registering Your Provider

### Option 1: Register in gateway.py

```python
# In gateway.py, after guardrail_manager initialization

from mypackage.providers import MyCustomProvider

# Create and register
custom_provider = MyCustomProvider(api_key="your-key")
guardrail_manager.register_provider(custom_provider)
```

### Option 2: Register via Configuration

**1. Add to enkrypt_mcp_config.json:**

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
            "api_key": "your-key",
            "max_length": 5000
          }
        }
      ]
    }
  }
}
```

**2. Add loader in gateway.py:**

```python
elif provider_type == "custom":
    module_path = provider_config.get("module")
    if module_path:
        provider = load_custom_provider(module_path, provider_cfg)
        if provider:
            guardrail_manager.register_provider(provider)
```

---

## Using Your Provider

### Configure Server to Use Your Provider

```json
{
  "server_name": "my_server",
  "input_guardrails_policy": {
    "enabled": true,
    "provider": "my-custom-provider",
    "max_length": 5000
  }
}
```

### Verify Provider is Loaded

```python
from secure_mcp_gateway.plugins.guardrails import get_guardrail_config_manager

manager = get_guardrail_config_manager()
print(manager.list_providers())
# Output: ['enkrypt', 'my-custom-provider']
```

---

## Advanced Patterns

### Pattern 1: API-Based Provider

```python
import httpx

class APIGuardrailProvider(GuardrailProvider):
    def __init__(self, api_url: str, api_key: str):
        self.api_url = api_url
        self.api_key = api_key

    def get_name(self) -> str:
        return "api-guardrail"

    def create_input_guardrail(self, config):
        return APIInputGuardrail(self.api_url, self.api_key, config)

class APIInputGuardrail:
    def __init__(self, api_url, api_key, config):
        self.api_url = api_url
        self.api_key = api_key
        self.config = config

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.api_url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"content": request.content},
                timeout=5.0
            )

            result = response.json()

            # Parse API response and create GuardrailResponse
            is_safe = result.get("is_safe", True)
            violations = []

            if not is_safe:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.CUSTOM,
                        severity=result.get("severity", 0.5),
                        message=result.get("message", "Violation detected"),
                        action=GuardrailAction.BLOCK,
                        metadata=result
                    )
                )

            return GuardrailResponse(
                is_safe=is_safe,
                action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
                violations=violations
            )

    def get_supported_detectors(self):
        return [ViolationType.CUSTOM]
```

### Pattern 2: Regex/Pattern Matching Provider

```python
import re

class PatternMatchProvider(GuardrailProvider):
    def __init__(self, patterns: list):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in patterns]

    def get_name(self) -> str:
        return "pattern-match"

    def create_input_guardrail(self, config):
        return PatternMatchGuardrail(self.patterns, config)

class PatternMatchGuardrail:
    def __init__(self, patterns, config):
        self.patterns = patterns
        self.config = config

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        violations = []

        for pattern in self.patterns:
            matches = pattern.findall(request.content)
            if matches:
                violations.append(
                    GuardrailViolation(
                        violation_type=ViolationType.KEYWORD_VIOLATION,
                        severity=1.0,
                        message=f"Sensitive pattern detected",
                        action=GuardrailAction.BLOCK,
                        metadata={"matches": matches[:3]}
                    )
                )

        is_safe = len(violations) == 0

        return GuardrailResponse(
            is_safe=is_safe,
            action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
            violations=violations
        )

    def get_supported_detectors(self):
        return [ViolationType.KEYWORD_VIOLATION]
```

### Pattern 3: ML-Based Provider

```python
class MLGuardrailProvider(GuardrailProvider):
    def __init__(self, model_path: str):
        # Load your ML model
        self.model = self.load_model(model_path)

    def load_model(self, path):
        # Load your trained model
        # import joblib
        # return joblib.load(path)
        pass

    def get_name(self) -> str:
        return "ml-guardrail"

    def create_input_guardrail(self, config):
        return MLInputGuardrail(self.model, config)

class MLInputGuardrail:
    def __init__(self, model, config):
        self.model = model
        self.threshold = config.get("threshold", 0.7)

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        # Use your ML model to predict
        # prediction = self.model.predict([request.content])[0]
        # confidence = self.model.predict_proba([request.content])[0].max()

        # For demo:
        prediction = 0  # 0=safe, 1=unsafe
        confidence = 0.9

        violations = []
        if prediction == 1 and confidence >= self.threshold:
            violations.append(
                GuardrailViolation(
                    violation_type=ViolationType.CUSTOM,
                    severity=confidence,
                    message="ML model flagged content as unsafe",
                    action=GuardrailAction.BLOCK,
                    metadata={"confidence": confidence}
                )
            )

        is_safe = len(violations) == 0

        return GuardrailResponse(
            is_safe=is_safe,
            action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
            violations=violations
        )

    def get_supported_detectors(self):
        return [ViolationType.CUSTOM]
```

---

## Testing

### Unit Test Your Provider

```python
import pytest
from secure_mcp_gateway.plugins.guardrails import GuardrailRequest

@pytest.mark.asyncio
async def test_custom_provider():
    # Create provider
    provider = MyCustomProvider()

    # Create guardrail
    guardrail = provider.create_input_guardrail({
        "enabled": True,
        "max_length": 100
    })

    # Test safe content
    request = GuardrailRequest(content="Short text")
    response = await guardrail.validate(request)

    assert response.is_safe is True
    assert len(response.violations) == 0

    # Test unsafe content
    request = GuardrailRequest(content="x" * 200)
    response = await guardrail.validate(request)

    assert response.is_safe is False
    assert len(response.violations) > 0
    assert response.violations[0].violation_type == ViolationType.CUSTOM
```

### Integration Test

```python
@pytest.mark.asyncio
async def test_provider_integration():
    from secure_mcp_gateway.plugins.guardrails import (
        get_guardrail_config_manager,
        initialize_guardrail_system
    )

    # Initialize system
    config = {"enkrypt_api_key": "test-key"}
    initialize_guardrail_system(config)

    manager = get_guardrail_config_manager()

    # Register provider
    provider = MyCustomProvider()
    manager.register_provider(provider)

    # Verify registration
    assert "my-custom-provider" in manager.list_providers()

    # Test via config manager
    server_config = {
        "server_name": "test_server",
        "input_guardrails_policy": {
            "enabled": True,
            "provider": "my-custom-provider",
            "max_length": 100
        }
    }

    guardrail = manager.get_input_guardrail(server_config)
    assert guardrail is not None
```

---

## Complete Example

Here's a complete, production-ready provider:

```python
"""
Complete Custom Guardrail Provider Example
"""
from typing import Dict, Any, List, Optional
import httpx
from secure_mcp_gateway.plugins.guardrails import (
    GuardrailProvider,
    GuardrailRequest,
    GuardrailResponse,
    GuardrailViolation,
    ViolationType,
    GuardrailAction,
    InputGuardrail,
    OutputGuardrail,
)

class ProductionProvider(GuardrailProvider):
    """Production-ready guardrail provider with error handling."""

    def __init__(self, api_key: str, api_url: str, timeout: int = 5):
        self.api_key = api_key
        self.api_url = api_url
        self.timeout = timeout

    def get_name(self) -> str:
        return "production-provider"

    def get_version(self) -> str:
        return "1.0.0"

    def create_input_guardrail(self, config: Dict[str, Any]) -> Optional[InputGuardrail]:
        if not config.get("enabled", False):
            return None
        return ProductionInputGuardrail(
            self.api_key,
            self.api_url,
            self.timeout,
            config
        )

    def create_output_guardrail(self, config: Dict[str, Any]) -> Optional[OutputGuardrail]:
        if not config.get("enabled", False):
            return None
        return ProductionOutputGuardrail(
            self.api_key,
            self.api_url,
            self.timeout,
            config
        )

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate configuration."""
        if config.get("enabled", False):
            if not self.api_key:
                return False
        return True

    def get_required_config_keys(self) -> List[str]:
        return ["enabled"]

class ProductionInputGuardrail:
    """Input guardrail with comprehensive error handling."""

    def __init__(self, api_key: str, api_url: str, timeout: int, config: Dict[str, Any]):
        self.api_key = api_key
        self.api_url = api_url
        self.timeout = timeout
        self.config = config
        self.fail_open = config.get("fail_open", False)

    async def validate(self, request: GuardrailRequest) -> GuardrailResponse:
        """Validate with proper error handling."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.api_url}/validate",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "content": request.content,
                        "tool_name": request.tool_name,
                        "context": request.context
                    },
                    timeout=self.timeout
                )

                response.raise_for_status()
                result = response.json()

                # Parse API response
                violations = []
                if not result.get("is_safe", True):
                    for violation_data in result.get("violations", []):
                        violations.append(
                            GuardrailViolation(
                                violation_type=ViolationType.CUSTOM,
                                severity=violation_data.get("severity", 0.5),
                                message=violation_data.get("message", "Violation detected"),
                                action=GuardrailAction.BLOCK,
                                metadata=violation_data
                            )
                        )

                is_safe = len(violations) == 0

                return GuardrailResponse(
                    is_safe=is_safe,
                    action=GuardrailAction.ALLOW if is_safe else GuardrailAction.BLOCK,
                    violations=violations,
                    metadata={"provider": "production-provider", "api_response": result}
                )

        except httpx.TimeoutException:
            # Handle timeout
            if self.fail_open:
                return GuardrailResponse(
                    is_safe=True,
                    action=GuardrailAction.ALLOW,
                    violations=[],
                    metadata={"error": "timeout", "fail_open": True}
                )
            else:
                return GuardrailResponse(
                    is_safe=False,
                    action=GuardrailAction.BLOCK,
                    violations=[
                        GuardrailViolation(
                            violation_type=ViolationType.CUSTOM,
                            severity=1.0,
                            message="Guardrail API timeout",
                            action=GuardrailAction.BLOCK,
                            metadata={"error": "timeout"}
                        )
                    ]
                )

        except Exception as e:
            # Handle other errors
            if self.fail_open:
                return GuardrailResponse(
                    is_safe=True,
                    action=GuardrailAction.ALLOW,
                    violations=[],
                    metadata={"error": str(e), "fail_open": True}
                )
            else:
                return GuardrailResponse(
                    is_safe=False,
                    action=GuardrailAction.BLOCK,
                    violations=[
                        GuardrailViolation(
                            violation_type=ViolationType.CUSTOM,
                            severity=1.0,
                            message=f"Guardrail error: {str(e)}",
                            action=GuardrailAction.BLOCK,
                            metadata={"error": str(e)}
                        )
                    ]
                )

    def get_supported_detectors(self) -> List[ViolationType]:
        return [ViolationType.CUSTOM]

class ProductionOutputGuardrail:
    """Output guardrail implementation."""

    def __init__(self, api_key: str, api_url: str, timeout: int, config: Dict[str, Any]):
        # Similar to input guardrail
        self.api_key = api_key
        self.api_url = api_url
        self.timeout = timeout
        self.config = config

    async def validate(
        self,
        response_content: str,
        original_request: GuardrailRequest
    ) -> GuardrailResponse:
        # Similar implementation to input
        # but validates response content
        pass

    def get_supported_detectors(self) -> List[ViolationType]:
        return [ViolationType.CUSTOM]
```

---

## Best Practices

### 1. Error Handling

✅ Always handle timeouts and network errors
✅ Implement fail-open or fail-closed strategy
✅ Log errors for debugging
✅ Return meaningful error messages

### 2. Performance

✅ Use async/await for I/O operations
✅ Set reasonable timeouts
✅ Cache results when appropriate
✅ Avoid blocking the event loop

### 3. Configuration

✅ Validate configuration before use
✅ Provide sensible defaults
✅ Document all configuration options
✅ Use environment variables for secrets

### 4. Testing

✅ Write unit tests for your provider
✅ Test error conditions
✅ Test with real API calls (integration tests)
✅ Mock external dependencies in unit tests

---

## Troubleshooting

### Provider Not Found

```python
# Check registered providers
manager = get_guardrail_config_manager()
print(manager.list_providers())

# Register if missing
manager.register_provider(MyProvider())
```

### Validation Not Running

- Check `enabled: true` in config
- Verify provider name matches
- Check gateway logs for errors
- Enable debug logging

### Import Errors

```python
# Use correct imports
from secure_mcp_gateway.plugins.guardrails import (
    GuardrailProvider,
    GuardrailRequest,
    GuardrailResponse,
    GuardrailViolation,
    ViolationType,
    GuardrailAction,
)
```

---

## Summary

You now know how to:

✅ Create custom guardrail providers
✅ Implement input/output guardrails
✅ Register providers with the system
✅ Configure servers to use your provider
✅ Handle errors properly
✅ Test your implementation

**Your custom provider is ready for production!** 🚀

For more examples, see:

- `example_providers.py` - Multiple provider implementations
- `enkrypt_provider.py` - Reference implementation
- `usage_guide.py` - Usage patterns
