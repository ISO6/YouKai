# app/adapters/nmap_adapter.py
import asyncio
from typing import List, Tuple
from app.config import settings


class NmapAdapter:
    @staticmethod
    async def execute_scan(target: str, flags: List[str]) -> Tuple[str, str, int]:
        """异步安全调用 Nmap，强制捕获 XML 输出"""
        cmd = [settings.NMAP_PATH] + flags + ["-oX", "-", target]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=settings.MAX_TIMEOUT_SECONDS
            )
            return stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"), proc.returncode
        except asyncio.TimeoutError:
            proc.kill()
            raise TimeoutError(f"Nmap scan timed out after {settings.MAX_TIMEOUT_SECONDS} seconds.")