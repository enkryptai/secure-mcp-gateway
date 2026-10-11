"""Tool args that advertise a null default must accept an explicit null."""

from mcp.shared.memory import create_connected_server_and_client_session

from secure_mcp_gateway.gateway import mcp


def _accepts_null(schema: dict) -> bool:
    if schema.get("type") == "null":
        return True
    if isinstance(schema.get("type"), list) and "null" in schema["type"]:
        return True
    return any(_accepts_null(s) for s in schema.get("anyOf", []))


async def test_null_default_args_accept_null():
    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        tools = (await client.list_tools()).tools

        null_default_args = [
            (tool.name, arg, schema)
            for tool in tools
            for arg, schema in tool.inputSchema.get("properties", {}).items()
            if "default" in schema and schema["default"] is None
        ]
        assert null_default_args, "expected at least one argument with a null default"

        for tool_name, arg, schema in null_default_args:
            assert _accepts_null(schema), f"{tool_name}.{arg} schema rejects null"

            result = await client.call_tool(tool_name, {arg: None})
            text = " ".join(getattr(c, "text", "") for c in result.content)
            assert "validation error" not in text, f"{tool_name}.{arg}: {text}"
