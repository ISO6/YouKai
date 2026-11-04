import re
from typing import List
from app.config import settings


class SecurityPolicy:
    ALLOWED_PORTS_PATTERN = re.compile(r"^[0-9,\-]+$")
    ALLOWED_FLAGS = {
        "-sS", "-sT", "-sV", "-Pn", "-F", "--top-ports", "-n", "-v"
    }

    @classmethod
    def validate_target(cls, target: str) -> None:
        """检查目标格式，阻断命令注入"""
        if not target or not isinstance(target, str):
            raise ValueError("Target must be a non-empty string.")

        # 严格禁止任何 shell 注入字符
        if any(char in target for char in [";", "&", "|", "`", "$", "(", ")", ">", "<", "\n", "\r"]):
            raise ValueError(f"Security Warning: Potential injection characters detected in target: {target}")

        if not re.match(settings.ALLOWED_TARGET_REGEX, target.strip()):
            raise ValueError(f"Target validation failed: {target} is not a valid IP or domain.")

    @classmethod
    def sanitize_arguments(cls, ports: str = None, service_detection: bool = True) -> List[str]:
        """构建安全受限的参数列表，禁止 Agent 自行拼接恶意参数"""
        args = ["-n"]  # 禁用反向 DNS 加快速度

        if service_detection:
            args.append("-sV")
            args.extend(["--version-intensity", "5"])

        if ports:
            clean_ports = ports.strip()
            if not cls.ALLOWED_PORTS_PATTERN.match(clean_ports):
                raise ValueError(f"Invalid ports format: {clean_ports}. Allowed: e.g., '80,443' or '1-1000'")
            args.extend(["-p", clean_ports])
        else:
            args.extend(["--top-ports", "100"])

        return args