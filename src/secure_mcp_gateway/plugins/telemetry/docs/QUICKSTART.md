# Telemetry Plugin System - Quick Start

Get started with the Telemetry Plugin System in 5 minutes!

## 🚀 Basic Usage

### 1. **Initialize the System**

```python
from secure_mcp_gateway.plugins.telemetry import initialize_telemetry_system

# Initialize with config
config = {
    "enkrypt_telemetry": {
        "enabled": True,
        "endpoint": "http://localhost:4317",
        "insecure": True
    }
}

manager = initialize_telemetry_system(config)
```

### 2. **Get Logger and Tracer**

```python
# Get logger
logger = manager.get_logger()
logger.info("Hello from telemetry plugin!")

# Get tracer
tracer = manager.get_tracer()

# Use tracer
with tracer.start_as_current_span("my-operation") as span:
    span.set_attribute("custom.attribute", "value")
    logger.info("Processing...")
```

---

## 📦 **Using Different Providers**

### **OpenTelemetry (Default)**

```python
from secure_mcp_gateway.plugins.telemetry import OpenTelemetryProvider

# Register provider
provider = OpenTelemetryProvider()
manager.register_provider(provider)

# Initialize with config
config = {
    "enabled": True,
    "endpoint": "http://localhost:4317",
    "insecure": True,
    "service_name": "my-service"
}
manager.initialize_provider("opentelemetry", config)

# Use it
logger = manager.get_logger()
tracer = manager.get_tracer()
```

### **Console Logger (Development)**

```python
from secure_mcp_gateway.plugins.telemetry.example_providers import ConsoleTelemetryProvider

# Register provider
provider = ConsoleTelemetryProvider()
manager.register_provider(provider)

# Initialize
config = {"level": "DEBUG"}
manager.initialize_provider("console", config)

# Switch to console provider
manager.set_active_provider("console")

# Use it
logger = manager.get_logger()
logger.debug("Debug message")
logger.info("Info message")
```

### **Datadog**

```python
from secure_mcp_gateway.plugins.telemetry.example_providers import DatadogTelemetryProvider

# Register provider
provider = DatadogTelemetryProvider(
    api_key="your-datadog-api-key",
    app_key="your-datadog-app-key"
)
manager.register_provider(provider)

# Initialize
config = {
    "hostname": "localhost",
    "port": 8126,
    "service_name": "my-service",
    "environment": "production"
}
manager.initialize_provider("datadog", config)

# Switch to Datadog
manager.set_active_provider("datadog")
```

---

## ⚙️ **Configuration File**

### **enkrypt_mcp_config.json**

```json
{
  "common_mcp_gateway_config": {
    "enkrypt_telemetry": {
      "enabled": true,
      "endpoint": "http://localhost:4317",
      "insecure": true
    },

    "telemetry_plugins": {
      "enabled": false,
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
            "app_key": "YOUR_DATADOG_APP_KEY",
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

## 🔄 **Switching Providers**

```python
# List available providers
providers = manager.list_providers()
print(f"Available providers: {providers}")

# Check provider status
status = manager.get_provider_status()
print(status)

# Switch active provider
manager.set_active_provider("console")

# Get logger from active provider
logger = manager.get_logger()
```

---

## 🎨 **Custom Provider**

Create your own telemetry provider:

```python
from secure_mcp_gateway.plugins.telemetry import TelemetryProvider, TelemetryResult

class MyCustomProvider(TelemetryProvider):
    @property
    def name(self) -> str:
        return "my-custom-provider"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, config: dict) -> TelemetryResult:
        # Your initialization logic
        self._api_key = config.get("api_key")

        return TelemetryResult(
            success=True,
            provider_name=self.name,
            message="Custom provider initialized"
        )

    def create_logger(self, name: str):
        # Return your logger
        import logging
        return logging.getLogger(name)

    def create_tracer(self, name: str):
        # Return your tracer
        return None

# Use it
manager.register_provider(MyCustomProvider())
manager.initialize_provider("my-custom-provider", {"api_key": "xxx"})
manager.set_active_provider("my-custom-provider")
```

---

## 🔍 **Common Patterns**

### **Pattern 1: Development vs Production**

```python
import os

env = os.getenv("ENVIRONMENT", "development")

if env == "production":
    # Use Datadog in production
    manager.set_active_provider("datadog")
else:
    # Use console in development
    manager.set_active_provider("console")

logger = manager.get_logger()
```

### **Pattern 2: Multiple Destinations**

```python
# Register multiple providers
manager.register_provider(OpenTelemetryProvider())
manager.register_provider(ConsoleTelemetryProvider())

# Initialize both
manager.initialize_provider("opentelemetry", otel_config)
manager.initialize_provider("console", console_config)

# Use OpenTelemetry as primary
manager.set_active_provider("opentelemetry")

# Can switch to console for debugging
# manager.set_active_provider("console")
```

### **Pattern 3: Fallback Provider**

```python
try:
    # Try to use Datadog
    result = manager.initialize_provider("datadog", datadog_config)
    if result.success:
        manager.set_active_provider("datadog")
    else:
        raise Exception(result.error)
except Exception as e:
    print(f"Datadog failed, falling back to console: {e}")
    manager.set_active_provider("console")
```

---

## 🎯 **Integration with Gateway**

### **In gateway.py**

```python
from secure_mcp_gateway.plugins.telemetry import initialize_telemetry_system

# Initialize telemetry system
telemetry_manager = initialize_telemetry_system(common_config)

# Get logger and tracer
logger = telemetry_manager.get_logger()
tracer = telemetry_manager.get_tracer()

# Use them throughout your code
logger.info("Gateway started")

with tracer.start_as_current_span("process_request") as span:
    # Your code
    pass
```

---

## 📊 **Provider Status**

```python
# Get detailed status
status = manager.get_provider_status()

# Example output:
{
    "opentelemetry": {
        "version": "1.0.0",
        "initialized": True,
        "active": True
    },
    "console": {
        "version": "1.0.0",
        "initialized": True,
        "active": False
    },
    "datadog": {
        "version": "1.0.0",
        "initialized": False,
        "active": False
    }
}
```

---

## 🚨 **Error Handling**

```python
# Check initialization result
result = manager.initialize_provider("datadog", config)

if not result.success:
    print(f"Failed to initialize: {result.error}")
    print(f"Message: {result.message}")

    # Fallback to another provider
    manager.set_active_provider("console")

# Check if provider exists
try:
    logger = manager.get_logger()
except RuntimeError as e:
    print(f"No active provider: {e}")
```

---

## ✅ **Next Steps**

1. **Read the [Integration Guide](INTEGRATION_GUIDE.md)** for advanced usage
2. **Check [README.md](README.md)** for complete documentation
3. **See [example_providers.py](../example_providers.py)** for provider examples
4. **Create your own custom provider!**

---

## 💡 **Tips**

- ✅ Use **OpenTelemetry** for distributed tracing
- ✅ Use **Console** for development and debugging
- ✅ Use **Datadog/New Relic** for production monitoring
- ✅ Always check initialization results
- ✅ Use environment variables for provider selection
- ✅ Implement fallback providers for reliability

---

**That's it! You're ready to use the Telemetry Plugin System! 🎉**
