#!/bin/bash
set -e

mkdir -p /root/.enkrypt
cp /mnt/e/github/enkryptai/secure-mcp-gateway/tests/bwrap_test_config.json /root/.enkrypt/enkrypt_mcp_config.json
echo "Config copied to /root/.enkrypt/enkrypt_mcp_config.json"

python3 -c "
import json
d = json.load(open('/root/.enkrypt/enkrypt_mcp_config.json'))
print('Runtime:', d['common_mcp_gateway_config']['sandbox']['runtime'])
servers = d['mcp_configs']['bwrap-test-config-001']['mcp_config']
for s in servers:
    sb = s.get('sandbox', {})
    print(f\"  {s['server_name']}: sandbox={sb.get('enabled', False)} runtime={sb.get('runtime', 'inherit')} network={sb.get('network', 'inherit')}\")
"

echo ""
echo "Starting gateway..."
cd /mnt/e/github/enkryptai/secure-mcp-gateway
/tmp/sandbox-venv/bin/python -m secure_mcp_gateway.gateway
