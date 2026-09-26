"""Verify the configured MCP server against an existing sample project."""

import asyncio
import json
import os
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parents[1]


async def main():
    env = {key: value for key, value in os.environ.items() if key.startswith("PROJECT_KB_")}
    params = StdioServerParameters(command=sys.executable,
        args=["-B", "-X", "utf8", "-u", str(ROOT / "mcp_server.py")], cwd=str(ROOT), env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as client:
            await client.initialize()
            tools = await client.list_tools()
            names = {tool.name for tool in tools.tools}
            assert {"kb_retrieve", "kb2_evidence"} <= names

            async def call(name, arguments):
                result = await client.call_tool(name, arguments)
                assert not result.isError
                return json.loads(next(block.text for block in result.content if block.type == "text"))

            result = await call("kb_retrieve", {"query": "calibration", "project_id": "sample"})
            assert result["status"] == "ok" and result["results"]
            row = result["results"][0]
            assert row["kind"] == "evidence" and row["project_id"] == "sample"
            body = await call("kb2_evidence", {"evidence_id": row["evidence_id"],
                "generation_id": result["generation"], "offset": row["snippet_start"],
                "length": row["snippet_end"] - row["snippet_start"]})
            assert body["status"] == "ok" and body["text"] == row["snippet"]
            print(json.dumps({"status": "passed", "tool_count": len(names),
                "retrieval_revision": result["retrieval_revision"],
                "project_id": row["project_id"], "exact_readback": True}))


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(), timeout=45))
