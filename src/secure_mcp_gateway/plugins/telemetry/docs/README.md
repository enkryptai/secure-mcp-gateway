# Telemetry Plugin System

A flexible, extensible telemetry system for the Enkrypt MCP Gateway built on SOLID principles.

## 🎯 **Overview**

The Telemetry Plugin System allows you to:
- **Switch between telemetry providers** (OpenTelemetry, Datadog, New Relic, Prometheus, etc.)
- **Use multiple providers simultaneously**
- **Create custom telemetry providers**
- **Configure via JSON files**
- **Maintain backward compatibility** with existing code

## ✨ **Features**

### **🔌 Multiple Provider Support**
- **OpenTelemetry** - Default, distributed tracing & metrics
- **Datadog** - APM and infrastructure monitoring
- **New Relic** - Application performance monitoring
- **Prometheus** - Metrics and alerting
- **Console** - Simple console logging for development
- **Custom** - Build your own!

### **🏗️ SOLID Architecture**
- **Single Responsibility** - Each provider has one job
- **Open/Closed** - Add providers without modifying code
- **Liskov Substitution** - All providers are interchangeable
- **Interface Segregation** - Minimal, focused interfaces
- **Dependency Inversion** - Depend on abstractions

### **⚙️ Flexible Configuration**
- JSON-based configuration
- Environment-specific settings
- Provider switching at runtime
- Graceful fallback handling

### **🔄 Backward Compatible**
- Works with existing telemetry service
- No breaking changes required
- Gradual migration path

---

## 🚀 **Quick Start**

### **1. Basic Usage**

```python
from secure_mcp_gateway.plugins.telemetry import initialize_telemetry_system

# Initialize with config
config = {
    "enkrypt_telemetry": {
        "enabled": True,
        "endpoint": "http://localhost:4317"
    }
}

manager = initialize_telemetry_system(config)

# Get logger and tracer
logger = manager.get_logger()
tracer = manager.get_tracer()

# Use them
logger.info("Application started")

with tracer.start_as_current_span("operation") as span:
    span.set_attribute("key", "value")
    logger.info("Processing...")
```

### **2. Configuration**

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
          "config": {"level": "DEBUG"}
        },
        {
          "name": "datadog-prod",
          "type": "datadog",
          "config": {
            "api_key": "YOUR_API_KEY",
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

## 📦 **Available Providers**

### **OpenTelemetry (Default)**
```python
from secure_mcp_gateway.plugins.telemetry import OpenTelemetryProvider

provider = OpenTelemetryProvider()
manager.register_provider(provider)
manager.initialize_provider("opentelemetry", {
    "enabled": True,
    "endpoint": "http://localhost:4317",
    "insecure": True
})
```

**Features:**
- ✅ Distributed tracing
- ✅ Metrics collection
- ✅ Context propagation
- ✅ OTLP export

### **Console (Development)**
```python
from secure_mcp_gateway.plugins.telemetry.example_providers import ConsoleTelemetryProvider

provider = ConsoleTelemetryProvider()
manager.register_provider(provider)
manager.initialize_provider("console", {"level": "DEBUG"})
```

**Features:**
- ✅ Simple console output
- ✅ Python logging
- ✅ Quick debugging
- ✅ No external dependencies

### **Datadog**
```python
from secure_mcp_gateway.plugins.telemetry.example_providers import DatadogTelemetryProvider

provider = DatadogTelemetryProvider(api_key="xxx", app_key="yyy")
manager.register_provider(provider)
manager.initialize_provider("datadog", {
    "hostname": "localhost",
    "port": 8126
})
```

**Features:**
- ✅ APM traces
- ✅ Infrastructure monitoring
- ✅ Custom metrics
- ✅ Log aggregation

### **New Relic**
```python
from secure_mcp_gateway.plugins.telemetry.example_providers import NewRelicTelemetryProvider

provider = NewRelicTelemetryProvider(license_key="xxx")
manager.register_provider(provider)
manager.initialize_provider("newrelic", {
    "app_name": "my-app",
    "environment": "production"
})
```

**Features:**
- ✅ Application monitoring
- ✅ Transaction tracing
- ✅ Custom events
- ✅ Error tracking

### **Prometheus**
```python
from secure_mcp_gateway.plugins.telemetry.example_providers import PrometheusTelemetryProvider

provider = PrometheusTelemetryProvider(port=8000)
manager.register_provider(provider)
manager.initialize_provider("prometheus", {
    "port": 8000,
    "namespace": "enkrypt"
})
```

**Features:**
- ✅ Metrics endpoint
- ✅ Time-series data
- ✅ Alerting
- ✅ Grafana integration

---

## 🎨 **Creating Custom Providers**

### **Step 1: Implement Provider**

```python
from secure_mcp_gateway.plugins.telemetry import TelemetryProvider, TelemetryResult

class MyProvider(TelemetryProvider):
    @property
    def name(self) -> str:
        return "my-provider"

    @property
    def version(self) -> str:
        return "1.0.0"

    def initialize(self, config: dict) -> TelemetryResult:
        # Initialize your telemetry backend
        self._client = MyTelemetryClient(config)

        return TelemetryResult(
            success=True,
            provider_name=self.name,
            message="Initialized successfully"
        )

    def create_logger(self, name: str):
        # Return logger compatible with Python's logging
        return self._client.get_logger(name)

    def create_tracer(self, name: str):
        # Return tracer compatible with OpenTelemetry
        return self._client.get_tracer(name)
```

### **Step 2: Register and Use**

```python
# Register
provider = MyProvider()
manager.register_provider(provider)

# Initialize
result = manager.initialize_provider("my-provider", config)

if result.success:
    # Use it
    manager.set_active_provider("my-provider")
    logger = manager.get_logger()
```

---

## 🔄 **Provider Switching**

### **Runtime Switching**

```python
# List providers
providers = manager.list_providers()  # ['opentelemetry', 'console', 'datadog']

# Check status
status = manager.get_provider_status()

# Switch provider
manager.set_active_provider("datadog")

# Get logger from new provider
logger = manager.get_logger()
```

### **Environment-Based**

```python
import os

env = os.getenv("ENVIRONMENT", "development")

if env == "production":
    manager.set_active_provider("datadog")
elif env == "staging":
    manager.set_active_provider("opentelemetry")
else:
    manager.set_active_provider("console")
```

### **Fallback Strategy**

```python
def initialize_with_fallback():
    # Try production provider
    result = manager.initialize_provider("datadog", datadog_config)

    if result.success:
        manager.set_active_provider("datadog")
        return

    # Fallback to OpenTelemetry
    result = manager.initialize_provider("opentelemetry", otel_config)

    if result.success:
        manager.set_active_provider("opentelemetry")
        return

    # Last resort: console
    manager.set_active_provider("console")
```

---

## 📊 **Architecture**

```
┌─────────────────────────────────────────┐
│     TelemetryConfigManager              │
│  (Manages providers & configuration)    │
└────────────┬────────────────────────────┘
             │
             ├─────────────────────┐
             │                     │
┌────────────▼──────────┐  ┌──────▼──────────────┐
│  TelemetryRegistry    │  │  Active Provider    │
│  (Provider storage)   │  │  (Current provider) │
└───────────┬───────────┘  └──────┬──────────────┘
            │                     │
            ├─────────────────────┤
            │                     │
┌───────────▼────────┐   ┌────────▼─────────┐
│ TelemetryProvider  │   │ TelemetryProvider│
│   (OpenTelemetry)  │   │   (Datadog)      │
└────────────────────┘   └──────────────────┘
```

### **Key Components**

1. **TelemetryProvider** - Base interface for all providers
2. **TelemetryRegistry** - Stores and manages providers
3. **TelemetryConfigManager** - Coordinates provider lifecycle
4. **TelemetryResult** - Standardized result format

---

## 🎓 **SOLID Principles**

### **Single Responsibility**
Each class has one clear purpose:
- Provider = Telemetry implementation
- Registry = Provider storage
- Manager = Coordination

### **Open/Closed**
- Open for extension (add new providers)
- Closed for modification (no core changes needed)

### **Liskov Substitution**
All providers implement the same interface and are interchangeable.

### **Interface Segregation**
Minimal, focused interfaces - providers only implement what they need.

### **Dependency Inversion**
Code depends on abstractions (TelemetryProvider), not concrete implementations.

---

## 📚 **Documentation**

- **[Quick Start](QUICKSTART.md)** - Get started in 5 minutes
- **[Integration Guide](INTEGRATION_GUIDE.md)** - Detailed integration steps
- **[Summary](SUMMARY.md)** - Complete overview

---

## 🔧 **Installation**

Already included in `secure-mcp-gateway` package!

```bash
# Optional dependencies for specific providers
pip install ddtrace  # For Datadog
pip install newrelic  # For New Relic
pip install prometheus-client  # For Prometheus
```

---

## 🎯 **Use Cases**

### **Development**
```python
manager.set_active_provider("console")
# Simple console output for debugging
```

### **Staging**
```python
manager.set_active_provider("opentelemetry")
# OpenTelemetry for testing distributed tracing
```

### **Production**
```python
manager.set_active_provider("datadog")
# Full APM and monitoring
```

---

## ✅ **Benefits**

- ✅ **Flexibility** - Switch providers without code changes
- ✅ **Extensibility** - Add custom providers easily
- ✅ **Testability** - Mock providers for testing
- ✅ **Maintainability** - Clean separation of concerns
- ✅ **Reliability** - Fallback provider support
- ✅ **Performance** - Minimal overhead

---

## 🚀 **Migration Path**

The plugin system is **100% backward compatible**:

1. **Current code works unchanged** - Uses OpenTelemetry by default
2. **Gradual adoption** - Add new providers when ready
3. **No breaking changes** - Existing telemetry service still works

---

## 🎉 **Summary**

The Telemetry Plugin System provides:
- 🔌 **Multiple provider support**
- 🏗️ **SOLID architecture**
- ⚙️ **Flexible configuration**
- 🔄 **Runtime provider switching**
- 🎨 **Custom provider creation**
- ✅ **Backward compatibility**

**Ready to use in production!** 🚀
