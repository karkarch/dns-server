import time
import pickle
from dnslib import DNSRecord, RR, A, AAAA, NS, PTR, QTYPE, DNSHeader


class DNSCache:
    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.domain_cache = {}
        self.ip_cache = {}
        self.load_cache()

    def save_cache(self):
        with open(self.cache_file, 'wb') as f:
            pickle.dump({
                'domain_cache': self.domain_cache,
                'ip_cache': self.ip_cache
            }, f)

    def load_cache(self):
        try:
            with open(self.cache_file, 'rb') as f:
                data = pickle.load(f)
                self.domain_cache = data.get('domain_cache', {})
                self.ip_cache = data.get('ip_cache', {})
                self.remove_expired_entries()
        except (FileNotFoundError, EOFError, pickle.PickleError):
            self.domain_cache = {}
            self.ip_cache = {}

    def remove_expired_entries(self):
        now = time.time()
        self._clean_domain_cache(now)
        self._clean_ip_cache(now)

    def _clean_domain_cache(self, now):
        for domain in list(self.domain_cache.keys()):
            self.domain_cache[domain] = [
                r for r in self.domain_cache[domain] if r['expire_time'] > now
            ]
            if not self.domain_cache[domain]:
                del self.domain_cache[domain]

    def _clean_ip_cache(self, now):
        for ip in list(self.ip_cache.keys()):
            if self.ip_cache[ip]['expire_time'] <= now:
                del self.ip_cache[ip]

    def process_response(self, response_data):
        now = time.time()
        dns_response = DNSRecord.parse(response_data)

        for section in [dns_response.rr, dns_response.auth, dns_response.ar]:
            for record in section:
                self._process_record(record, now)

    def _add_a_record(self, rname, rdata, expire_time):
        """Добавляет A-запись (IPv4)"""
        if rname not in self.domain_cache:
            self.domain_cache[rname] = []
        self.domain_cache[rname].append({
            'type': 'A',
            'data': str(rdata),
            'expire_time': expire_time
        })
        self.ip_cache[str(rdata)] = {
            'domain': rname,
            'expire_time': expire_time
        }

    def _add_aaaa_record(self, rname, rdata, expire_time):
        """Добавляет AAAA-запись (IPv6)"""
        if rname not in self.domain_cache:
            self.domain_cache[rname] = []
        self.domain_cache[rname].append({
            'type': 'AAAA',
            'data': str(rdata),
            'expire_time': expire_time
        })
        self.ip_cache[str(rdata)] = {
            'domain': rname,
            'expire_time': expire_time
        }

    def _add_ns_record(self, rname, rdata, expire_time):
        """Добавляет NS-запись (сервер имен)"""
        if rname not in self.domain_cache:
            self.domain_cache[rname] = []
        self.domain_cache[rname].append({
            'type': 'NS',
            'data': str(rdata),
            'expire_time': expire_time
        })

    def _add_ptr_record(self, rname, rdata, expire_time):
        """Добавляет PTR-запись (обратное преобразование IP -> домен)"""
        self.ip_cache[rname] = {
            'domain': str(rdata),
            'expire_time': expire_time
        }

    def _process_record(self, record, now):
        rname = str(record.rname)
        ttl = record.ttl
        expire_time = now + ttl

        if record.rtype == QTYPE.A:
            self._add_a_record(rname, record.rdata, expire_time)
        elif record.rtype == QTYPE.AAAA:
            self._add_aaaa_record(rname, record.rdata, expire_time)
        elif record.rtype == QTYPE.NS:
            self._add_ns_record(rname, record.rdata, expire_time)
        elif record.rtype == QTYPE.PTR:
            self._add_ptr_record(rname, record.rdata, expire_time)

    def check_cache(self, query_data):
        query = DNSRecord.parse(query_data)
        qname = str(query.q.qname)
        qtype = query.q.qtype

        if qtype == QTYPE.PTR and qname in self.ip_cache:
            return self._create_ptr_response(query, qname)

        if qname in self.domain_cache:
            return self._create_domain_response(query, qname, qtype)

        return None

    def _create_ptr_response(self, query, qname):
        record = self.ip_cache[qname]
        if time.time() < record['expire_time']:
            reply = DNSRecord(DNSHeader(id=query.header.id, qr=1, aa=0, ra=1), q=query.q)
            reply.add_answer(RR(qname, QTYPE.PTR, rdata=PTR(record['domain']), ttl=60))
            return reply.pack()
        return None

    def _create_domain_response(self, query, qname, qtype):
        reply = DNSRecord(DNSHeader(id=query.header.id, qr=1, aa=0, ra=1), q=query.q)
        added = False

        for record in self.domain_cache[qname]:
            if self._add_record_to_reply(record, qname, qtype, reply):
                added = True

        return reply.pack() if added else None

    def _add_record_to_reply(self, record, qname, qtype, reply):
        if time.time() < record['expire_time'] and (qtype == QTYPE.ANY or qtype == QTYPE.get(record['type'])):
            if record['type'] == 'A':
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(record['data']), ttl=60))
                return True
            elif record['type'] == 'AAAA':
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(record['data']), ttl=60))
                return True
            elif record['type'] == 'NS':
                reply.add_answer(RR(qname, QTYPE.NS, rdata=NS(record['data']), ttl=60))
                return True
        return False
