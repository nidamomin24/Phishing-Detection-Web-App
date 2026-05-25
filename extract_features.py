import tldextract, re, math, socket, ssl, requests
from datetime import datetime
from urllib.parse import urlparse

def entropy(s):
    from collections import Counter
    if not s:
        return 0.0
    probs = [float(c)/len(s) for c in Counter(s).values()]
    return -sum(p*math.log2(p) for p in probs) if s else 0.0

def get_ssl_days_left(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            notAfter = cert.get('notAfter')
            if notAfter:
                try:
                    expire = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
                    return (expire - datetime.now()).days
                except Exception:
                    return -1
    except Exception:
        return -1
    return -1

def extract_features(url):
    u = url.strip()
    features = {}
    features['url_length'] = len(u)
    features['has_at'] = 1 if "@" in u else 0
    features['count_double_slash'] = 1 if u.count("//")>1 else 0
    parsed = urlparse(u if '://' in u else 'http://'+u)
    host = parsed.hostname or ''
    features['num_dots'] = host.count('.') if host else u.count('.')
    features['num_digits'] = sum(c.isdigit() for c in u)
    features['entropy'] = entropy(u)
    features['https'] = 1 if parsed.scheme=='https' else 0
    t = tldextract.extract(u)
    domain = (t.domain or '') + ('.'+t.suffix if t.suffix else '')
    features['domain'] = domain
    features['ssl_days_left'] = get_ssl_days_left(host) if host else -1
    try:
        r = requests.get(u if '://' in u else 'http://'+u, timeout=4, allow_redirects=True)
        features['redirect_count'] = len(r.history)
        text = r.text.lower()
        features['has_form'] = 1 if '<form' in text else 0
        features['num_external_links'] = text.count('href')
    except Exception:
        features['redirect_count'] = -1
        features['has_form'] = 0
        features['num_external_links'] = -1
    ordered = [
        features['url_length'],
        features['has_at'],
        features['count_double_slash'],
        features['num_dots'],
        features['num_digits'],
        features['entropy'],
        features['https'],
        features['ssl_days_left'],
        features['redirect_count'],
        features['has_form'],
        features['num_external_links']
    ]
    return ordered