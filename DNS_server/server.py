from .cache import DNSCache
from .network import DNSNetworkHandler
from threading import Thread
import socket


class CachingDNSServer:
    def __init__(self, upstream_dns='8.8.8.8', cache_file='dns_cache.pkl'):
        self.cache = DNSCache(cache_file)
        self.network = DNSNetworkHandler(upstream_dns)

    def handle_query(self, data, addr, sock):
        try:
            response = self.cache.check_cache(data)
            if not response:
                response = self.network.query_upstream(data)
                if response:
                    self.cache.process_response(response)

            sock.sendto(response or self.network.create_servfail(data), addr)

        except Exception as e:
            print(f"Error handling query: {e}")
            sock.sendto(self.network.create_servfail(data), addr)

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('0.0.0.0', 53))
            print(f"DNS server started on port 53, using upstream {self.network.upstream_dns}")

            try:
                while True:
                    data, addr = s.recvfrom(512)
                    Thread(target=self.handle_query, args=(data, addr, s)).start()
            except KeyboardInterrupt:
                print("\nShutting down server...")
                self.cache.save_cache()
                print("Cache saved to disk.")