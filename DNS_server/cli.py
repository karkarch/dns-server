from .server import CachingDNSServer
import argparse


def main():
    parser = argparse.ArgumentParser(description='Caching DNS Server')
    parser.add_argument('--upstream', default='8.8.8.8', help='Upstream DNS server')
    parser.add_argument('--cache-file', default='dns_cache.pkl', help='Cache file path')
    parser.add_argument('--port', type=int, default=53, help='Port to listen on')

    args = parser.parse_args()

    server = CachingDNSServer(upstream_dns=args.upstream, cache_file=args.cache_file)
    print(f"Starting DNS server on port {args.port}...")
    server.start()


if __name__ == '__main__':
    main()