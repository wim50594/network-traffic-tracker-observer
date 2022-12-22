from dataclasses import dataclass, field
from typing import List
from tld import get_fld
from urllib.parse import urlparse
from tld.exceptions import TldDomainNotFound, TldBadUrl


@dataclass
class resource:
    id: str
    url: str
    connection_id: str
    ip: str
    protocol: str
    method: str
    website_call: str
    hostname: str = field(init=False)
    start: int
    end_header: int = None
    end_stream: int = None
    packets: List[int] = field(init=False)
    content: str = None
    first_party: str = None
    context: str = None
    ip_context: str = None

    def __post_init__(self):
        self.packets = [self.start]
        self.hostname = self.get_hostname()

    def add_packet(self, packet_nr):
        if packet_nr not in self.packets:
            self.packets.append(packet_nr)

    def add_packets(self, packets):
        for p in packets:
            self.add_packet(p)

    def is_closed(self) -> bool:
        """Check if resource is closed meaning an end packet was received"""
        if self.protocol == "http":
            return self.end_header is not None
        else:
            return self.end_header is not None and self.end_stream is not None

    def is_thirdparty(self) -> bool:
        """Check if resource is in third party context"""
        try:
            return get_fld(self.url) != self.context
        except:
            # Probably because an ip is used
            return self.ip != self.ip_context

    def get_hostname(self):
        try:
            return get_fld(self.url)
        except:
            return urlparse(self.url).netloc

    def get_type(self):
        if not self.content:
            return ""

        if "javascript" in self.content or "ecmascript" in self.content:
            return "script"
        elif "image" in self.content:
            return "image"
        elif "css" in self.content:
            return "stylesheet"
        elif "html" in self.content:
            return "document"
        elif "font" in self.content:
            return "font"
        elif "video" in self.content or "audio" in self.content:
            return "media"
        else:
            return "other"
