# mcp_server.py
import json
from mcp.server.fastmcp import FastMCP
from app.services.nmap_service import NmapService

# 初始化标准 MCP 服务
mcp = FastMCP("Nmap-Security-MCP")


@mcp.tool()
async def scan_network_target(target: str, ports: str = "", detect_services: bool = True) -> str:
    """
    对指定的目标 IP 或域名执行 Nmap 端口与服务深度扫描。

    参数:
    - target: 目标 IP 地址 (例如: 192.168.1.1) 或合法域名 (例如: example.com)
    - ports: 端口范围字符串，例如 '80,443', '1-1024'。默认扫描 Top 100 常见端口。
    - detect_services: 是否启用服务版本识别 (-sV)。默认为 True。
    """
    ports_param = ports if ports.strip() else None
    response = await NmapService.run_scan(target, ports=ports_param, service_detection=detect_services)
    # 返回 JSON 字符串给 MCP 规范
    return response.model_dump_json(indent=2)


if __name__ == "__main__":
    # 启动基于 Stdio 的 MCP 服务
    mcp.run()