from DNS_server.server import CachingDNSServer

if __name__ == "__main__":
    server = CachingDNSServer(
        upstream_dns='8.8.8.8',
        cache_file='dns_cache.pkl'
    )
    print("Запуск DNS-сервера на порту 53...")
    server.start()