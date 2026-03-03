# Enkrypt In-Agent SDK (Moved)

This package has been consolidated into **enkrypt-security**.

The SDK now lives at `src/enkrypt_security/sdk/` in the main repository.

```python
# New import paths
from enkrypt_security.sdk import auto_secure
from enkrypt_security.sdk.config import SDKConfig, GuardrailConfig
from enkrypt_security.sdk.adapters.langchain import LangChainAdapter
```

Install: `pip install enkrypt-security[sdk]`

See the main [README](../README.md) for details.
