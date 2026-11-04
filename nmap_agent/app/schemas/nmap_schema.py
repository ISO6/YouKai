from typing import List, Optional
from pydantic import BaseModel, Field

class ServiceInfo(BaseModel):
    name: str = Field(description="服务名称，如 http, ssh")
    product: Optional[str] = Field(None, description="产品名，如 Apache httpd, OpenSSH")
    version: Optional[str] = Field(None, description="服务具体版本号")
    extra_info: Optional[str] = Field(None, description="额外信息")

class PortInfo(BaseModel):
    port_id: int = Field(description="端口号")
    protocol: str = Field(description="传输协议，如 tcp, udp")
    state: str = Field(description="端口状态，如 open, closed, filtered")
    service: Optional[ServiceInfo] = Field(None, description="运行的服务详情")

class HostScanResult(BaseModel):
    target: str = Field(description="目标主机 IP 或域名")
    status: str = Field(description="主机状态: up / down")
    ports: List[PortInfo] = Field(default_factory=list, description="端口扫描结果")

class ScanResponse(BaseModel):
    success: bool
    command_executed: str
    data: Optional[HostScanResult] = None
    error: Optional[str] = None