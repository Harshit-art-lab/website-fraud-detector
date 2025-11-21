
import re
import ssl
import socket
import ipaddress
import math
import logging
from urllib.parse import urlparse, urljoin
from datetime import datetime
from typing import Dict, Any, List, Optional

# Optional imports: guard with try/except to allow dry runs
try:
    import whois as whois_lib  # python-whois
except Exception:
    whois_lib = None

try:
    import dns.resolver  # dnspython
    import dns.exception
except Exception:
    dns = None

try:
    import requests
    from bs4 import BeautifulSoup
except Exception:
    requests = None
    BeautifulSoup = None

try:
    import tldextract
except Exception:
    tldextract = None

DEFAULT_CONFIG = {
    # Basic heuristics
    "url_length_threshold": 100,
    "suspicious_chars_ratio": 0.30,
    "entropy_threshold": 3.5,  # Shannon entropy threshold (lower -> readable; higher -> random)
    # WHOIS / domain age
    "min_domain_age_years": 1,
    # scoring weights (tunable)
    "weights": {
        "excessive_url_length": 8,
        "suspicious_encoding": 18,
        "ip_address_domain": 18,
        "excessive_subdomain_depth": 8,
        "non_standard_port": 4,
        "no_ssl_certificate": 22,
        "invalid_ssl_certificate": 30,
        "expired_ssl_certificate": 28,
        "near_expiry_certificate": 8,
        "punycode": 14,
        "unicode_homoglyphs": 18,
        "suspicious_character_ratio": 14,
        "high_entropy_domain": 18,
        "young_domain": 22,
        "no_mx": 8,
        "no_spf": 6,
        "many_redirects": 6,
        "login_forms": 18,
        "password_inputs": 20,
        "external_links_ratio": 8,
        "phishing_keywords": 16,
        "favicon_mismatch": 8,
    },
    # network timeouts
    "ssl_timeout": 3.0,
    "http_timeout": 4.0,
    # control flags
    "enable_network_checks": True,
    "max_redirects_considered_suspicious": 3,
    "max_worker_threads": 4,
}

# simple logger
logger = logging.getLogger("WFD")
logger.setLevel(logging.INFO)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class WebsiteFraudDetector:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = dict(DEFAULT_CONFIG)
        if config:
            # shallow merge for weights
            w = dict(cfg["weights"]);
            w.update(config.get("weights", {}))
            cfg.update({k: v for k, v in config.items() if k != "weights"})
            cfg["weights"] = w
        self.cfg = cfg

    # ---------- Public API ----------
    def analyze_url(self, url: str) -> Dict[str, Any]:
        if not isinstance(url, str) or not url.strip():
            return self._error_response("URL cannot be empty", score=100)

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname is None:
            return self._error_response("Invalid URL (no hostname parsed)", score=90)

        hostname = hostname.rstrip(".")

        issues = []
        score = 0

        # Basic checks
        if len(url) > self.cfg["url_length_threshold"]:
            issues.append(self._make_issue("excessive_url_length", "medium",
                                           f"URL length {len(url)} > {self.cfg['url_length_threshold']}"))
            score += self.cfg["weights"]["excessive_url_length"]

        enc_issue, enc_score = self._check_url_encoding(parsed)
        if enc_issue:
            issues.append(enc_issue);
            score += enc_score

        # Host checks
        if self._is_ip_address(hostname):
            issues.append(self._make_issue("ip_address_domain", "high", "Hostname is a numeric IP address"))
            score += self.cfg["weights"]["ip_address_domain"]

        labels = hostname.split(".")
        if len(labels) > 4:
            issues.append(self._make_issue("excessive_subdomain_depth", "medium",
                                           f"Domain has {len(labels)} labels (depth > 4)"))
            score += self.cfg["weights"]["excessive_subdomain_depth"]

        if parsed.port and parsed.port not in (80, 443):
            issues.append(self._make_issue("non_standard_port", "low", f"Using port {parsed.port}"))
            score += self.cfg["weights"]["non_standard_port"]

        # Homoglyph / punycode
        puny_issue, puny_score = self._check_punycode_and_homoglyphs(hostname)
        if puny_issue:
            issues.append(puny_issue);
            score += puny_score

        # Suspicious char ratio
        scr_issue, scr_score = self._check_suspicious_chars_ratio(hostname)
        if scr_issue:
            issues.append(scr_issue);
            score += scr_score

        # Domain entropy
        entropy = _shannon_entropy(self._label_without_tld(hostname))
        if entropy > self.cfg["entropy_threshold"]:
            issues.append(self._make_issue("high_entropy_domain", "high",
                                           f"Domain label entropy {entropy:.2f} > {self.cfg['entropy_threshold']}"))
            score += self.cfg["weights"]["high_entropy_domain"]

        # Optional network checks
        if self.cfg["enable_network_checks"]:
            # WHOIS / domain age
            try:
                w_issue, w_score = self._check_whois_age(hostname)
                if w_issue:
                    issues.append(w_issue);
                    score += w_score
            except Exception as e:
                logger.debug("WHOIS check failed: %s", e)

            # DNS checks: MX and SPF/TXT
            try:
                dns_issues, dns_score = self._check_dns(hostname)
                for it in dns_issues:
                    issues.append(it)
                score += dns_score
            except Exception as e:
                logger.debug("DNS check failed: %s", e)

            # HTTP fetch page-level checks (redirects, forms, external links, title)
            try:
                page_issues, page_score = self._check_http_page(url)
                issues.extend(page_issues);
                score += page_score
            except Exception as e:
                logger.debug("HTTP check failed: %s", e)

            # SSL/TLS checks
            try:
                cert_issue, cert_score = self._check_ssl_certificate(hostname)
                if cert_issue:
                    issues.append(cert_issue);
                    score += cert_score
            except Exception as e:
                logger.debug("SSL check failed: %s", e)

        # Phishing keyword scan (on hostname and path)
        kw_issue, kw_score = self._check_phishing_keywords(
            hostname + parsed.path + ("?" + parsed.query if parsed.query else ""))
        if kw_issue:
            issues.append(kw_issue);
            score += kw_score

        # Cap and normalize
        score = max(0, min(100, score))

        return {
            "success": True,
            "url": url,
            "hostname": hostname,
            "risk_score": score,
            "risk_level": self._get_risk_level(score),
            "is_legitimate": score < 40,
            "issues": issues,
            "issue_count": len(issues),
            "debug": {
                "entropy": round(entropy, 3)
            }
        }

    # ---------- Helper checks ----------
    def _check_url_encoding(self, parsed):
        # conservative: look for many encoded chars in path+query
        path_q = parsed.path + ("?" + parsed.query if parsed.query else "")
        matches = re.findall(r"%[0-9A-Fa-f]{2}", path_q)
        if len(matches) >= 5 or (len(matches) > 0 and len(matches) / max(1, len(path_q)) > 0.05):
            return (self._make_issue("suspicious_url_encoding", "high",
                                     f"{len(matches)} percent-encoded sequences in path/query"),
                    self.cfg["weights"]["suspicious_encoding"])
        return (None, 0)

    def _check_punycode_and_homoglyphs(self, hostname):
        # punycode
        if "xn--" in hostname:
            return (self._make_issue("punycode", "medium", "Domain uses punycode (xn--)"),
                    self.cfg["weights"]["punycode"])
        # attempt idna decode label by label and detect non-ascii
        non_ascii_chars = []
        try:
            for lbl in hostname.split("."):
                try:
                    decoded = lbl.encode("ascii").decode("idna")
                except Exception:
                    decoded = lbl
                for ch in decoded:
                    if ord(ch) > 127:
                        non_ascii_chars.append(ch)
            if non_ascii_chars:
                return (self._make_issue("unicode_homoglyphs", "high",
                                         f"Unicode chars in hostname: {', '.join(sorted(set(non_ascii_chars)))}"),
                        self.cfg["weights"]["unicode_homoglyphs"])
        except Exception:
            pass
        return (None, 0)

    def _check_suspicious_chars_ratio(self, hostname):
        total = len(hostname)
        if total == 0:
            return (None, 0)
        allowed = re.compile(r"[A-Za-z0-9\.\-]")
        non_allowed = sum(1 for ch in hostname if not allowed.match(ch))
        ratio = non_allowed / total
        if ratio >= self.cfg["suspicious_chars_ratio"]:
            return (self._make_issue("suspicious_character_ratio", "high",
                                     f"{non_allowed}/{total} non-standard chars ({ratio:.2f})"),
                    self.cfg["weights"]["suspicious_character_ratio"])
        return (None, 0)

    def _check_whois_age(self, hostname):
        """Use python-whois if installed. Conservative scoring if domain is very young or whois unavailable"""
        if whois_lib is None:
            # cannot perform whois; do not penalize
            return (None, 0)
        try:
            # use tldextract to get registrable domain if available
            target = self._label_without_subdomain(hostname)
            w = whois_lib.whois(target)
            creation = None
            if isinstance(w.creation_date, list):
                creation = w.creation_date[0]
            else:
                creation = w.creation_date
            if creation is None:
                # unknown creation date -> don't penalize harshly
                return (None, 0)
            age_years = (datetime.utcnow() - creation).days / 365.25
            if age_years < self.cfg["min_domain_age_years"]:
                return (self._make_issue("young_domain", "high",
                                         f"Domain age {age_years:.2f} years < {self.cfg['min_domain_age_years']}"),
                        self.cfg["weights"]["young_domain"])
        except Exception as e:
            logger.debug("whois error: %s", e)
            # be conservative
            return (None, 0)
        return (None, 0)

    def _check_dns(self, hostname):
        if dns is None:
            return ([], 0)
        total_score = 0
        issues = []
        try:
            # MX records
            try:
                mx = dns.resolver.resolve(hostname, "MX", lifetime=3.0)
                if len(mx) == 0:
                    issues.append(self._make_issue("no_mx", "low", "No MX record found"))
                    total_score += self.cfg["weights"]["no_mx"]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                # no mx
                issues.append(self._make_issue("no_mx", "low", "No MX record found or lookup failed"))
                total_score += self.cfg["weights"]["no_mx"]
            # SPF / TXT - simple check
            try:
                txts = dns.resolver.resolve(hostname, "TXT", lifetime=3.0)
                spf_found = any("v=spf1" in b.to_text().lower() for b in txts)
                if not spf_found:
                    issues.append(self._make_issue("no_spf", "low", "No SPF record found in TXT records"))
                    total_score += self.cfg["weights"]["no_spf"]
            except Exception:
                # ignore TXT read errors
                pass
        except Exception as e:
            logger.debug("dns exception: %s", e)
        return (issues, total_score)

    def _check_http_page(self, url):
        if not requests or not BeautifulSoup:
            return ([], 0)
        issues = []
        score = 0
        try:
            resp = requests.get(url, timeout=self.cfg["http_timeout"], allow_redirects=True)
            # redirect chain length
            redirects = len(resp.history)
            if redirects >= self.cfg["max_redirects_considered_suspicious"]:
                issues.append(self._make_issue("many_redirects", "medium", f"{redirects} redirects found"))
                score += self.cfg["weights"]["many_redirects"]

            # parse page
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" in content_type and resp.text:
                soup = BeautifulSoup(resp.text, "html.parser")
                forms = soup.find_all("form")
                if len(forms) > 0:
                    issues.append(self._make_issue("login_forms", "medium", f"{len(forms)} form(s) found on page"))
                    score += self.cfg["weights"]["login_forms"]
                # detect password inputs
                if soup.find("input", {"type": "password"}):
                    issues.append(self._make_issue("password_inputs", "high", "Password input field present"))
                    score += self.cfg["weights"]["password_inputs"]
                # external vs internal links
                links = soup.find_all("a", href=True)
                internal = 0;
                external = 0
                base_hostname = urlparse(url).hostname
                for a in links:
                    href = a.get("href")
                    if href.startswith("#") or href.startswith("javascript:"):
                        continue
                    try:
                        target = urlparse(urljoin(url, href)).hostname
                        if target and target != base_hostname:
                            external += 1
                        else:
                            internal += 1
                    except Exception:
                        external += 1
                total_links = internal + external
                if total_links > 0 and (external / total_links) > 0.8:
                    issues.append(self._make_issue("external_links_ratio", "medium",
                                                   f"{external}/{total_links} links are external"))
                    score += self.cfg["weights"]["external_links_ratio"]
                # title heuristic: if title contains phishing keywords, add small score
                title = soup.title.string if soup.title else ""
                if title and any(k in title.lower() for k in ["login", "secure", "account", "verify", "bank"]):
                    issues.append(
                        self._make_issue("suspicious_title", "low", f"Page title suggests login/secure: {title[:80]}"))
                    score += 6

                # favicon mismatch (placeholder): check if favicon host differs from main host
                favicon = None
                link_icon = soup.find("link", rel=lambda v: v and "icon" in v.lower())
                if link_icon and link_icon.get("href"):
                    favicon = urlparse(urljoin(url, link_icon.get("href"))).hostname
                    if favicon and favicon != base_hostname:
                        issues.append(self._make_issue("favicon_mismatch", "low",
                                                       f"Favicon served from {favicon} not matching {base_hostname}"))
                        score += self.cfg["weights"]["favicon_mismatch"]

            # small anti-fingerprinting: if server returns tiny body (possible parked/placeholder)
            if resp.status_code == 200 and len(resp.content) < 300:
                issues.append(
                    self._make_issue("tiny_page", "low", f"Page content very small ({len(resp.content)} bytes)"))
                score += 4

        except requests.exceptions.SSLError:
            issues.append(self._make_issue("http_ssl_error", "high", "HTTPS SSL error when fetching page"))
            score += 8
        except requests.exceptions.Timeout:
            # timeout: can't conclude
            pass
        except Exception as e:
            logger.debug("http fetch error: %s", e)
        return (issues, score)

    def _check_ssl_certificate(self, hostname):
        # Similar to earlier implementation but includes CN/SAN mismatch check
        if self._is_ip_address(hostname):
            return (self._make_issue("ip_no_tls_name", "low", "IP hosts have less meaningful TLS name checks"), 6)
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.cfg["ssl_timeout"]) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return (self._make_issue("no_ssl_certificate", "high", "No SSL certificate presented"),
                                self.cfg["weights"]["no_ssl_certificate"])
                    # check expiration
                    not_after = cert.get("notAfter")
                    if not_after:
                        try:
                            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        except Exception:
                            exp = None
                        if exp:
                            days_left = (exp - datetime.utcnow()).days
                            if days_left < 0:
                                return (self._make_issue("expired_ssl_certificate", "high",
                                                         f"Certificate expired {abs(days_left)} days ago"),
                                        self.cfg["weights"]["expired_ssl_certificate"])
                            if days_left < 15:
                                return (self._make_issue("near_expiry_certificate", "medium",
                                                         f"Certificate expires in {days_left} days"),
                                        self.cfg["weights"]["near_expiry_certificate"])
                    # CN / SAN check: see if hostname matches cert subject or SANs
                    san = cert.get("subjectAltName", ())
                    allowed_names = set()
                    for typ, val in san:
                        if typ.lower() == "dns":
                            allowed_names.add(val.lower().rstrip("."))
                    # subject CN fallback
                    subj = cert.get("subject", ())
                    for tup in subj:
                        for k, v in tup:
                            if k.lower() == "commonname":
                                allowed_names.add(v.lower().rstrip("."))
                    if allowed_names:
                        normalized = hostname.lower().rstrip(".")
                        # simple wildcard matching
                        matched = any(self._match_hostname_to_certname(normalized, a) for a in allowed_names)
                        if not matched:
                            return (self._make_issue("cert_name_mismatch", "high",
                                                     f"Hostname {hostname} not matched by cert names {', '.join(sorted(allowed_names))}"),
                                    20)
        except ssl.SSLError:
            return (self._make_issue("invalid_ssl_certificate", "high", "SSL/TLS handshake failed or cert invalid"),
                    self.cfg["weights"]["invalid_ssl_certificate"])
        except (socket.timeout, ConnectionRefusedError):
            # cannot reach 443 -> neutral
            return (None, 0)
        except Exception as e:
            logger.debug("SSL unknown error: %s", e)
            return (None, 0)
        return (None, 0)

    def _check_phishing_keywords(self, text):
        keywords = ["login", "secure", "account", "verify", "update", "bank", "paypal", "confirm", "password", "signin"]
        tl = text.lower()
        found = [k for k in keywords if k in tl]
        if found:
            return (self._make_issue("phishing_keywords", "medium", f"Found keywords: {', '.join(found)}"),
                    self.cfg["weights"]["phishing_keywords"])
        return (None, 0)

    # ---------- Utilities ----------
    def _match_hostname_to_certname(self, hostname: str, certname: str) -> bool:
        """Simple wildcard match (certname may start with '*.')"""
        hostname = hostname.lower().rstrip(".")
        certname = certname.lower().rstrip(".")
        if certname.startswith("*."):
            # match last labels
            return hostname.endswith(certname[1:])
        return hostname == certname

    def _label_without_tld(self, hostname: str) -> str:
        if tldextract:
            try:
                ext = tldextract.extract(hostname)
                return ext.subdomain + ext.domain  # join subdomain+domain but not suffix
            except Exception:
                pass
        # fallback: take first label (leftmost) as main
        return hostname.split(".")[0]

    def _label_without_subdomain(self, hostname: str) -> str:
        """Return the registrable domain (if tldextract available) else the last two labels"""
        if tldextract:
            try:
                ext = tldextract.extract(hostname)
                if ext.registered_domain:
                    return ext.registered_domain
            except Exception:
                pass
        parts = hostname.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname

    def _is_ip_address(self, host: str) -> bool:
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _make_issue(self, typ: str, severity: str, details: str) -> Dict[str, Any]:
        return {
            "type": typ,
            "severity": severity,
            "details": details,
            "recommendation": self._recommended_action(typ)
        }

    def _recommended_action(self, typ: str) -> str:
        mapping = {
            "ip_address_domain": "Avoid clicking; verify domain ownership or look up related company",
            "no_ssl_certificate": "Do not enter credentials; require HTTPS",
            "expired_ssl_certificate": "Do not trust site until certificate is renewed",
            "young_domain": "New domains require extra caution",
            "password_inputs": "Do not enter credentials on unknown domains",
            "phishing_keywords": "Be careful; message/content may try to trick you",
        }
        return mapping.get(typ, "Investigate further before trusting this site")

    def _get_risk_level(self, score: float) -> str:
        if score < 20:
            return "safe"
        if score < 40:
            return "low_risk"
        if score < 60:
            return "medium_risk"
        if score < 80:
            return "high_risk"
        return "critical_risk"

    def _error_response(self, msg: str, score: int = 100) -> Dict[str, Any]:
        return {
            "success": False,
            "error": msg,
            "risk_score": score,
            "risk_level": self._get_risk_level(score),
            "is_legitimate": False
        }
