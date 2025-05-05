import socket
from dnslib import DNSRecord, DNSHeader, QTYPE


class DNSNetworkHandler:
    def __init__(self, upstream_dns):
        self.upstream_dns = upstream_dns

    def query_upstream(self, query_data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5)
                s.sendto(query_data, (self.upstream_dns, 53))
                return s.recvfrom(4096)[0]
        except (socket.timeout, ConnectionError):
            return None

    def create_servfail(self, query_data=None):
        if query_data:
            query = DNSRecord.parse(query_data)
            return DNSRecord(DNSHeader(id=query.header.id, qr=1, rcode=2), q=query.q).pack()
        return DNSRecord(DNSHeader(id=0, qr=1, rcode=2)).pack()