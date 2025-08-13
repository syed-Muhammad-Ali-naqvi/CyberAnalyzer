import dns.resolver

def lookup_dns(domain):
    results = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    for record_type in record_types:
        try:
            answer = dns.resolver.resolve(domain, record_type, lifetime=5)
            results[record_type] = [str(r.to_text()) for r in answer]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            results[record_type] = ["Record not found or query timed out"]

    return results









