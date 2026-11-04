# app/services/nmap_service.py
import logging
from app.policies.validation import SecurityPolicy
from app.adapters.nmap_adapter import NmapAdapter
from app.parsers.xml_parser import NmapXMLParser
from app.schemas.nmap_schema import ScanResponse

logger = logging.getLogger(__name__)


class NmapService:
    @classmethod
    async def run_scan(cls, target: str, ports: str = None, service_detection: bool = True) -> ScanResponse:
        """核心业务编排：校验 -> 执行 -> 解析 -> 结构化返回"""
        try:
            # 1. 安全合规检查
            SecurityPolicy.validate_target(target)
            args = SecurityPolicy.sanitize_arguments(ports, service_detection)
            cmd_preview = f"nmap {' '.join(args)} -oX - {target}"

            # 2. 外部命令执行
            stdout, stderr, code = await NmapAdapter.execute_scan(target, args)

            if code != 0 and not stdout:
                return ScanResponse(success=False, command_executed=cmd_preview, error=stderr)

            # 3. XML 结构化反序列化
            scan_data = NmapXMLParser.parse(stdout, target)
            return ScanResponse(success=True, command_executed=cmd_preview, data=scan_data)

        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return ScanResponse(success=False, command_executed="unknown", error=str(e))