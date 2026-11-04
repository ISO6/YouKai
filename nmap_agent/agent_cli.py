# agent_cli.py
import asyncio
import os
import json
from openai import OpenAI
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from app.config import settings
from app.services.nmap_service import NmapService

console = Console()


class ReconAgent:
    def __init__(self):
        self.client = OpenAI(
            api_key=settings.LLM_API_KEY,
            base_url=settings.LLM_BASE_URL
        )
        self.messages = [
            {
                "role": "system",
                "content": (
                    "你是一个专业的网络安全渗透测试与资产侦察智能体。\n"
                    "你的任务是通过对话理解用户的意图，自主调用网络扫描工具探测目标资产，并为下一步漏洞分析提供建议。\n"
                    "重要原则：\n"
                    "1. 严格遵守安全伦理，只能对授权资产进行探测。\n"
                    "2. 拿到扫描结果后，需要输出：开放端口、服务名称、精准版本号（Product & Version）、以及潜在的 CVE 关注方向。\n"
                    "3. 如果存在 Apache 2.4.49、OpenSSH 低版本等经典高危组件，需重点高亮提醒。"
                )
            }
        ]

        # 注册可给 LLM 调用的工具定义
        self.tools = [
            {
                "type": "function",
                "function": {
                    "name": "scan_network_target",
                    "description": "执行 Nmap 网络端口及服务版本识别扫描",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "目标 IP 或域名"},
                            "ports": {"type": "string", "description": "指定端口，如 '80,443' 或留空扫描 Top100"},
                            "detect_services": {"type": "boolean", "description": "是否识别版本号"}
                        },
                        "required": ["target"]
                    }
                }
            }
        ]

    async def execute_tool(self, tool_name: str, arguments: dict) -> str:
        """执行本地工具 (模拟 MCP Client 转发执行)"""
        if tool_name == "scan_network_target":
            target = arguments.get("target")
            ports = arguments.get("ports", None)
            detect_services = arguments.get("detect_services", True)

            console.print(
                f"[bold cyan]🔍 [Tool Calling] 正在调度 Nmap 扫描目标: {target} (端口: {ports or 'Top100'})...[/bold cyan]")
            resp = await NmapService.run_scan(target=target, ports=ports, service_detection=detect_services)
            return resp.model_dump_json()
        return json.dumps({"error": f"Tool {tool_name} not found"})

    async def chat(self, user_prompt: str):
        self.messages.append({"role": "user", "content": user_prompt})

        while True:
            response = self.client.chat.completions.create(
                model=settings.LLM_MODEL,
                messages=self.messages,
                tools=self.tools,
                tool_choice="auto"
            )

            msg = response.choices[0].message
            if msg.content:
                self.messages.append({"role": "assistant", "content": msg.content})

            # 判断模型是否决定调用工具
            if msg.tool_calls:
                self.messages.append(msg)
                for tool_call in msg.tool_calls:
                    func_name = tool_call.function.name
                    func_args = json.loads(tool_call.function.arguments)

                    # 人工授权确认 (毕设亮点：Human-in-the-Loop)
                    console.print(Panel(f"智能体请求调用工具: [yellow]{func_name}[/yellow]\n参数: {func_args}",
                                        title="⚠️ 安全审计授权"))
                    confirm = input("是否授权执行此网络扫描? (y/n): ").strip().lower()
                    if confirm != 'y':
                        tool_result = json.dumps({"error": "User rejected the execution authorization."})
                    else:
                        tool_result = await self.execute_tool(func_name, func_args)

                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": tool_result
                    })
            else:
                # 思考完毕，给出最终回复
                console.print(Panel(Markdown(msg.content), title="🤖 攻防智能体评估报告", border_style="green"))
                break


async def main():
    agent = ReconAgent()
    console.print(Panel("[bold green]网络攻防侦察智能体 (Nmap MCP Agent) 已就绪[/bold green]\n输入 'exit' 退出程序。"))

    while True:
        user_input = input("\nUser > ").strip()
        if not user_input:
            continue
        if user_input.lower() in ["exit", "quit"]:
            break
        await agent.chat(user_input)


if __name__ == "__main__":
    asyncio.run(main())