import defusedxml.ElementTree as ET
from app.schemas.nmap_schema import HostScanResult, PortInfo, ServiceInfo


class NmapXMLParser:
    @staticmethod
    def parse(xml_content: str, target: str) -> HostScanResult:
        """将 Nmap -oX 标准输出转换为 Pydantic 结构化对象"""
        root = ET.fromstring(xml_content)
        host_node = root.find("host")

        if host_node is None:
            return HostScanResult(target=target, status="down", ports=[])

        status_node = host_node.find("status")
        state = status_node.get("state") if status_node is not None else "unknown"

        ports_result = []
        ports_node = host_node.find("ports")

        if ports_node is not None:
            for port in ports_node.findall("port"):
                port_id = int(port.get("portid"))
                protocol = port.get("protocol", "tcp")

                state_node = port.find("state")
                port_state = state_node.get("state") if state_node is not None else "unknown"

                # 只保留非关闭状态端口，避免上下文被撑爆
                if port_state != "open":
                    continue

                service_info = None
                service_node = port.find("service")
                if service_node is not None:
                    service_info = ServiceInfo(
                        name=service_node.get("name", "unknown"),
                        product=service_node.get("product"),
                        version=service_node.get("version"),
                        extra_info=service_node.get("extrainfo")
                    )

                ports_result.append(
                    PortInfo(
                        port_id=port_id,
                        protocol=protocol,
                        state=port_state,
                        service=service_info
                    )
                )

        return HostScanResult(
            target=target,
            status=state,
            ports=ports_result
        )