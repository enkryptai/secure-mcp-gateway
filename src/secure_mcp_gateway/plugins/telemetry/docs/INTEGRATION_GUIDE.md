# Telemetry Plugin System - Integration Guide

Complete guide for integrating the Telemetry Plugin System into your application.

## 📋 **Table of Contents**

1. [Basic Integration](#basic-integration)
2. [Gateway Integration](#gateway-integration)
3. [Configuration](#configuration)
4. [Custom Providers](#custom-providers)
5. [Advanced Usage](#advanced-usage)
6. [Testing](#testing)
7. [Troubleshooting](#troubleshooting)

---

## 🚀 **Basic Integration**

### **Step 1: Initialize the System**

```python
from secure_mcp_gateway.plugins.telemetry import (
    get_telemetry_config_manager,
    initialize_telemetry_system,
)

# Option 1: Initialize with config
config = {
    "enkrypt_telemetry": {
        "enabled": True,
        "endpoint": "http://localhost:4317",
        "insecure": True
    }
}
manager = initialize_telemetry_system(config)

# Option 2: Get existing manager
manager = get_telemetry_config_manager()
```

### **Step 2: Use Telemetry**

```python
# Get logger and tracer from active provider
logger = manager.get_logger()
tracer = manager.get_tracer()

# Use them
logger.info("Application started")

with tracer.start_as_current_span("my-operation") as span:
    span.set_attribute("user_id", "12345")
    logger.info("Processing request")
```

---

## 🏗️ **Gateway Integration**

### **Step 1: Update gateway.py**

```python
# src/secure_mcp_gateway/gateway.py

from secure_mcp_gateway.plugins.telemetry import initialize_telemetry_system

# Initialize telemetry system (after guardrails and auth)
common_config = get_common_config()

# Initialize telemetry system
initialize_telemetry_system(common_config)

sys_print("Telemetry system initialized")
```

### **Step 2: Update telemetry_service.py**

```python
# services/telemetry/telemetry_service.py

# Add reference to telemetry manager
TELEMETRY_MANAGER = None

def get_telemetry_manager():
    """Get the global telemetry manager"""
    global TELEMETRY_MANAGER
    if TELEMETRY_MANAGER is None:
        from secure_mcp_gateway.plugins.telemetry import get_telemetry_config_manager
        TELEMETRY_MANAGER = get_telemetry_config_manager()
    return TELEMETRY_MANAGER
```

---

## ⚙️ **Configuration**

### **Basic Configuration**

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_telemetry": {
      "enabled": true,
      "endpoint": "http://localhost:4317",
      "insecure": true
    }
  }
}
```

### **Multiple Providers**

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_telemetry": {
      "enabled": true,
      "endpoint": "http://localhost:4317",
      "insecure": true
    },

    "telemetry_plugins": {
      "enabled": true,
      "providers": [
        {
          "name": "console-dev",
          "type": "console",
          "config": {
            "level": "DEBUG"
          }
        },
        {
          "name": "datadog-prod",
          "type": "datadog",
          "config": {
            "api_key": "YOUR_DATADOG_API_KEY",
            "hostname": "localhost",
            "port": 8126
          }
        }
      ]
    }
  }
}
```

---

## 🎨 **Custom Providers**

### **Simple Custom Provider**

```python
from secure_mcp_gateway.plugins.telemetry import TelemetryProvider, TelemetryResult
import logging

class FileTelemetryProvider(TelemetryProvider):
    """Write logs to a file"""

    def __init__(self, filename: str):
        self.filename = filename
        self._logger = None

    @property
    def name(self) -> str:
        return "file"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, config: dict) -> TelemetryResult:
        """Initialize file logging"""
        try:
            self._logger = logging.getLogger("file-logger")
            handler = logging.FileHandler(self.filename)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)

            return TelemetryResult(
                success=True,
                provider_name=self.name,
                message=f"Logging to {self.filename}"
            )
        except Exception as e:
            return TelemetryResult(
                success=False,
                provider_name=self.name,
                error=str(e)
            )

    def create_logger(self, name: str):
        return self._logger

    def create_tracer(self, name: str):
        return None

# Use it
manager.register_provider(FileTelemetryProvider("app.log"))
manager.initialize_provider("file", {})
manager.set_active_provider("file")
```

---

## 🔧 **Advanced Usage**

### **Dynamic Provider Switching**

```python
class TelemetryManager:
    def __init__(self):
        self.manager = get_telemetry_config_manager()

    def use_provider_for_env(self):
        """Switch provider based on environment"""
        import os
        env = os.getenv("ENV", "dev")

        provider_map = {
            "dev": "console",
            "staging": "opentelemetry",
            "production": "datadog"
        }

        provider = provider_map.get(env, "console")
        self.manager.set_active_provider(provider)

        return provider

    def get_logger_with_context(self, context: dict):
        """Get logger with additional context"""
        logger = self.manager.get_logger()

        # Add context to all logs
        class ContextLogger:
            def __init__(self, logger, context):
                self._logger = logger
                self._context = context

            def info(self, msg, **kwargs):
                self._logger.info(msg, extra=self._context, **kwargs)

            def error(self, msg, **kwargs):
                self._logger.error(msg, extra=self._context, **kwargs)

        return ContextLogger(logger, context)
```

### **Fallback Chain**

```python
def initialize_with_fallback_chain(manager):
    """Try providers in order until one works"""
    providers = [
        ("datadog", datadog_config),
        ("newrelic", newrelic_config),
        ("opentelemetry", otel_config),
        ("console", {})
    ]

    for provider_name, config in providers:
        result = manager.initialize_provider(provider_name, config)

        if result.success:
            manager.set_active_provider(provider_name)
            print(f"✓ Using {provider_name}")
            return provider_name

    raise RuntimeError("No telemetry provider could be initialized")
```

### **Multi-Provider Broadcasting**

```python
class MultiProviderLogger:
    """Send logs to multiple providers simultaneously"""

    def __init__(self, manager):
        self.manager = manager
        self.providers = manager.list_providers()

    def log_to_all(self, level: str, message: str, **kwargs):
        """Log to all active providers"""
        for provider_name in self.providers:
            try:
                # Temporarily switch to provider
                original = self.manager._active_provider
                self.manager.set_active_provider(provider_name)

                logger = self.manager.get_logger()
                getattr(logger, level)(message, **kwargs)

                # Switch back
                self.manager.set_active_provider(original)
            except Exception as e:
                print(f"Failed to log to {provider_name}: {e}")

# Use it
multi_logger = MultiProviderLogger(manager)
multi_logger.log_to_all("info", "Application started")
```

---

## 🧪 **Testing**

### **Mock Provider for Testing**

```python
from secure_mcp_gateway.plugins.telemetry import TelemetryProvider, TelemetryResult

class MockTelemetryProvider(TelemetryProvider):
    """Mock provider for testing"""

    def __init__(self):
        self.logs = []
        self.spans = []

    @property
    def name(self) -> str:
        return "mock"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, config: dict) -> TelemetryResult:
        return TelemetryResult(success=True, provider_name=self.name)

    def create_logger(self, name: str):
        class MockLogger:
            def __init__(self, provider):
                self.provider = provider

            def info(self, msg, **kwargs):
                self.provider.logs.append(("info", msg, kwargs))

            def error(self, msg, **kwargs):
                self.provider.logs.append(("error", msg, kwargs))

        return MockLogger(self)

    def create_tracer(self, name: str):
        return None

# Use in tests
def test_logging():
    mock = MockTelemetryProvider()
    manager.register_provider(mock)
    manager.initialize_provider("mock", {})
    manager.set_active_provider("mock")

    logger = manager.get_logger()
    logger.info("test message")

    assert len(mock.logs) == 1
    assert mock.logs[0][0] == "info"
    assert mock.logs[0][1] == "test message"
```

### **Integration Test**

```python
import pytest

def test_telemetry_integration():
    """Test telemetry system integration"""
    from secure_mcp_gateway.plugins.telemetry import initialize_telemetry_system

    config = {
        "enkrypt_telemetry": {
            "enabled": True,
            "endpoint": "http://localhost:4317"
        }
    }

    manager = initialize_telemetry_system(config)

    # Test provider registration
    assert "opentelemetry" in manager.list_providers()

    # Test logger creation
    logger = manager.get_logger()
    assert logger is not None

    # Test tracer creation
    tracer = manager.get_tracer()
    assert tracer is not None

    # Test provider switching
    status = manager.get_provider_status()
    assert status["opentelemetry"]["active"] == True
```

---

## 🔍 **Troubleshooting**

### **Common Issues**

#### **Issue: No active provider**
```python
# Error: RuntimeError: No active telemetry provider

# Solution: Initialize a provider first
manager.initialize_provider("console", {})
```

#### **Issue: Provider not found**
```python
# Error: Provider 'xyz' not found

# Solution: Register the provider first
from secure_mcp_gateway.plugins.telemetry.example_providers import ConsoleTelemetryProvider

manager.register_provider(ConsoleTelemetryProvider())
manager.initialize_provider("console", {})
```

#### **Issue: Initialization failed**
```python
# Check initialization result
result = manager.initialize_provider("datadog", config)

if not result.success:
    print(f"Error: {result.error}")
    print(f"Message: {result.message}")

    # Try fallback
    manager.initialize_provider("console", {})
```

### **Debug Mode**

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Check provider status
status = manager.get_provider_status()
print(f"Provider status: {status}")

# List providers
providers = manager.list_providers()
print(f"Available providers: {providers}")

# Check active provider
active = manager.get_active_provider()
print(f"Active provider: {active.name if active else 'None'}")
```

---

## ✅ **Best Practices**

1. **Always check initialization results**
   ```python
   result = manager.initialize_provider("provider", config)
   if not result.success:
       # Handle error
   ```

2. **Use environment-based configuration**
   ```python
   env = os.getenv("ENV", "dev")
   provider = "datadog" if env == "prod" else "console"
   ```

3. **Implement fallback providers**
   ```python
   try:
       manager.set_active_provider("datadog")
   except:
       manager.set_active_provider("console")
   ```

4. **Log provider switches**
   ```python
   logger.info(f"Switching to provider: {provider_name}")
   manager.set_active_provider(provider_name)
   ```

5. **Use type hints**
   ```python
   from secure_mcp_gateway.plugins.telemetry import TelemetryConfigManager

   def setup_telemetry() -> TelemetryConfigManager:
       return initialize_telemetry_system(config)
   ```

---

## 🎯 **Complete Example**

```python
from secure_mcp_gateway.plugins.telemetry import (
    initialize_telemetry_system,
    OpenTelemetryProvider,
)
from secure_mcp_gateway.plugins.telemetry.example_providers import (
    ConsoleTelemetryProvider,
    DatadogTelemetryProvider,
)
import os

def setup_telemetry():
    """Complete telemetry setup"""

    # 1. Load configuration
    config = load_config()

    # 2. Initialize system
    manager = initialize_telemetry_system(config)

    # 3. Register additional providers
    manager.register_provider(ConsoleTelemetryProvider())

    if os.getenv("DATADOG_API_KEY"):
        manager.register_provider(
            DatadogTelemetryProvider(
                api_key=os.getenv("DATADOG_API_KEY")
            )
        )

    # 4. Initialize providers
    manager.initialize_provider("console", {"level": "DEBUG"})

    if "datadog" in manager.list_providers():
        result = manager.initialize_provider("datadog", {
            "hostname": "localhost",
            "port": 8126
        })

        if result.success:
            print("✓ Datadog initialized")

    # 5. Set active provider based on environment
    env = os.getenv("ENVIRONMENT", "development")

    if env == "production" and "datadog" in manager.list_providers():
        manager.set_active_provider("datadog")
    elif env == "staging":
        manager.set_active_provider("opentelemetry")
    else:
        manager.set_active_provider("console")

    # 6. Return manager
    return manager

# Use it
manager = setup_telemetry()
logger = manager.get_logger()
tracer = manager.get_tracer()

logger.info("Telemetry system ready!")
```

---

**Integration complete! Your telemetry plugin system is ready to use! 🎉**
