# ==============================================================================
# PART 3 — МОДУЛИ АНАЛИЗА
# Порты, HTTP, DNS, OSINT, Поддомены
# ==============================================================================
# Требует: part1_core.py, part2_repos.py
# ==============================================================================

import os
import re
import ssl
import json
import time
import socket
import asyncio
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# Мягкие импорты
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import dns.resolver
    import dns.exception
    import dns.reversename
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois as whois_lib
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


# ==============================================================================
# БАЗА: МОДУЛЬ АНАЛИЗА
# ==============================================================================
class AnalysisModule:
    """Базовый класс для всех модулей анализа"""

    NAME = "base"
    DESCRIPTION = "Базовый модуль"

    def __init__(self, logger: "Logger"):
        self.logger = logger
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.errors: List[str] = []

    def _start(self):
        self.start_time = time.time()
        self.errors = []

    def _stop(self):
        self.end_time = time.time()

    def duration(self) -> float:
        if not self.start_time:
            return 0.0
        end = self.end_time or time.time()
        return end - self.start_time

    def _add_error(self, msg: str):
        self.errors.append(msg)
        self.logger.debug(f"[{self.NAME}] {msg}")

    def run(self, target: "Target", **kwargs) -> Dict[str, Any]:
        """Переопределяется в наследниках"""
        raise NotImplementedError


# ==============================================================================
# PORT SCANNER
# ==============================================================================
class PortScanner(AnalysisModule):
    """
    Сканер портов: TCP + UDP
    - top-1000 портов по умолчанию
    - параллельное сканирование (ThreadPoolExecutor)
    - определение сервисов по баннерам
    - graceful shutdown
    """

    NAME = "ports"
    DESCRIPTION = "Сканирование портов"

    # ---------- ТОП-1000 портов (сокращённый список ~200 популярных) ----------
    COMMON_PORTS = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
        88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp",
        123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
        139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmp-trap",
        179: "bgp", 194: "irc", 389: "ldap", 443: "https",
        445: "microsoft-ds", 465: "smtps", 500: "isakmp", 514: "syslog",
        515: "printer", 520: "rip", 548: "afp", 554: "rtsp",
        587: "submission", 623: "ipmi", 631: "ipp", 636: "ldaps",
        646: "ldp", 873: "rsync", 902: "vmware", 989: "ftps-data",
        990: "ftps", 993: "imaps", 995: "pop3s", 1025: "nfs",
        1080: "socks", 1194: "openvpn", 1433: "mssql", 1434: "mssql-m",
        1521: "oracle", 1701: "l2tp", 1723: "pptp", 1883: "mqtt",
        1900: "upnp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
        2086: "whm", 2087: "whm-ssl", 2095: "webmail", 2096: "webmail-ssl",
        2181: "zookeeper", 2222: "ssh-alt", 2375: "docker", 2376: "docker-ssl",
        3128: "squid", 3260: "iscsi", 3306: "mysql", 3389: "rdp",
        3478: "stun", 3690: "svn", 4000: "icq", 4443: "pharos",
        4567: "sinatra", 5000: "upnp", 5060: "sip", 5061: "sips",
        5222: "xmpp", 5269: "xmpp-server", 5353: "mdns", 5432: "postgresql",
        5555: "android-adb", 5601: "kibana", 5672: "amqp", 5683: "coap",
        5900: "vnc", 5938: "teamviewer", 5984: "couchdb", 5985: "winrm",
        5986: "winrm-ssl", 6000: "x11", 6379: "redis", 6443: "kubernetes",
        6667: "irc", 6881: "bittorrent", 7001: "weblogic", 7002: "weblogic-ssl",
        7070: "realserver", 7443: "oracle-ssl", 7474: "neo4j", 8000: "http-alt",
        8008: "http-alt", 8009: "ajp", 8010: "http-alt", 8042: "http-alt",
        8069: "openerp", 8080: "http-proxy", 8081: "http-alt", 8082: "http-alt",
        8083: "http-alt", 8086: "influxdb", 8088: "http-alt", 8090: "http-alt",
        8123: "http-alt", 8161: "activemq", 8180: "http-alt", 8200: "http-alt",
        8222: "http-alt", 8243: "https-alt", 8280: "http-alt", 8300: "http-alt",
        8333: "bitcoin", 8400: "http-alt", 8443: "https-alt", 8444: "https-alt",
        8500: "consul", 8530: "http-alt", 8531: "https-alt", 8600: "http-alt",
        8649: "ganglia", 8834: "nessus", 8880: "http-alt", 8888: "http-alt",
        8899: "http-alt", 8983: "solr", 9000: "http-alt", 9001: "http-alt",
        9042: "cassandra", 9060: "http-alt", 9080: "http-alt", 9090: "http-alt",
        9091: "http-alt", 9100: "printer", 9160: "cassandra", 9200: "elasticsearch",
        9300: "elasticsearch", 9443: "https-alt", 9500: "http-alt", 9600: "http-alt",
        9800: "http-alt", 9943: "https-alt", 9981: "http-alt", 9999: "http-alt",
        10000: "webmin", 10250: "kubelet", 10443: "https-alt", 11211: "memcached",
        12345: "netbus", 15672: "rabbitmq", 16379: "redis-alt", 25565: "minecraft",
        27017: "mongodb", 27018: "mongodb", 28017: "mongodb-web", 37777: "dahua",
        44818: "ethernet-ip", 47808: "bacnet", 50000: "sap", 50030: "hadoop",
        50060: "hadoop", 50070: "hadoop", 50075: "hadoop", 50090: "hadoop",
        54321: "http-alt", 61616: "activemq",
    }

    # Порты с известными уязвимостями (приоритет)
    HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}

    # UDP порты
    UDP_PORTS = {53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 4500, 5353}

    def __init__(self, logger: "Logger", timeout: float = 1.5, max_workers: int = 100):
        super().__init__(logger)
        self.timeout = timeout
        self.max_workers = max_workers

    def scan(self, target: "Target",
             ports: Optional[List[int]] = None,
             udp: bool = False,
             grab_banners: bool = True,
             top_only: bool = False) -> Dict[str, Any]:
        """
        Сканирует порты цели

        ports       — список портов (если None — COMMON_PORTS)
        udp         — сканировать UDP тоже
        grab_banners — пытаться получить баннер сервиса
        top_only    — только топ-50
        """
        self._start()
        result = {
            "ports": {},
            "open_count": 0,
            "udp_ports": {},
            "scanned": 0,
            "errors": [],
            "duration": 0.0,
        }

        if not target.ip:
            self._add_error("Нет IP для сканирования")
            result["errors"] = self.errors
            self._stop()
            result["duration"] = self.duration()
            return result

        # Определяем порты
        if ports:
            port_list = list(ports)
        elif top_only:
            port_list = [22, 80, 443, 21, 25, 3306, 3389, 8080, 8443, 5900]
        else:
            port_list = list(self.COMMON_PORTS.keys())

        result["scanned"] = len(port_list)
        self.logger.info(f"  TCP-сканирование {target.ip} ({len(port_list)} портов)...")

        # ---------- TCP ----------
        open_ports = self._scan_tcp(target.ip, port_list)

        for port in open_ports:
            service = self.COMMON_PORTS.get(port, "unknown")
            result["ports"][port] = {
                "service": service,
                "banner": None,
                "risk": "high" if port in self.HIGH_RISK_PORTS else "normal",
            }

        # ---------- Баннеры ----------
        if grab_banners and open_ports:
            self.logger.debug(f"  Получение баннеров...")
            banners = self._grab_banners(target.ip, open_ports[:20])
            for port, banner in banners.items():
                if port in result["ports"]:
                    result["ports"][port]["banner"] = banner

        # ---------- UDP ----------
        if udp:
            self.logger.info(f"  UDP-сканирование...")
            udp_open = self._scan_udp(target.ip, list(self.UDP_PORTS))
            for port in udp_open:
                result["udp_ports"][port] = self.COMMON_PORTS.get(port, "unknown")

        result["open_count"] = len(result["ports"])
        result["errors"] = self.errors
        self._stop()
        result["duration"] = self.duration()

        return result

    # ---------- TCP ----------
    def _scan_tcp(self, ip: str, ports: List[int]) -> List[int]:
        """Параллельное TCP-сканирование"""
        open_ports: List[int] = []
        lock = __import__('threading').Lock()

        def check(port: int):
            if is_shutdown_requested():
                return
            if self._check_tcp_port(ip, port):
                with lock:
                    open_ports.append(port)

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = [ex.submit(check, p) for p in ports]
            for _ in as_completed(futures):
                pass

        return sorted(open_ports)

    def _check_tcp_port(self, ip: str, port: int) -> bool:
        """Проверка одного TCP-порта"""
        try:
            family = socket.AF_INET6 if ':' in ip else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((ip, port)) == 0
        except (socket.error, OSError, ValueError):
            return False

    # ---------- UDP ----------
    def _scan_udp(self, ip: str, ports: List[int]) -> List[int]:
        """UDP-сканирование (менее надёжное)"""
        open_ports: List[int] = []
        for port in ports:
            if is_shutdown_requested():
                break
            if self._check_udp_port(ip, port):
                open_ports.append(port)
        return open_ports

    def _check_udp_port(self, ip: str, port: int) -> bool:
        """Проверка UDP-порта (эвристика)"""
        try:
            family = socket.AF_INET6 if ':' in ip else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(b'\x00', (ip, port))
                try:
                    s.recvfrom(1024)
                    return True  # ответил — открыт
                except socket.timeout:
                    return False
                except ConnectionRefusedError:
                    return False  # ICMP port unreachable — закрыт
        except Exception:
            return False

    # ---------- Баннеры ----------
    def _grab_banners(self, ip: str, ports: List[int]) -> Dict[int, str]:
        """Пытается получить баннер сервиса"""
        banners: Dict[int, str] = {}

        def grab(port: int):
            banner = self._grab_one_banner(ip, port)
            if banner:
                banners[port] = banner

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = [ex.submit(grab, p) for p in ports]
            for _ in as_completed(futures):
                pass

        return banners

    def _grab_one_banner(self, ip: str, port: int) -> Optional[str]:
        """Получение баннера одного порта"""
        try:
            family = socket.AF_INET6 if ':' in ip else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((ip, port))

                # Для HTTP/HTTPS отправляем запрос
                if port in (80, 8080, 8000, 8888, 8081):
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                elif port in (443, 8443):
                    return "https (TLS)"
                elif port == 21:
                    pass  # FTP сам пришлёт
                elif port == 22:
                    pass  # SSH сам пришлёт
                elif port == 25 or port == 587:
                    pass  # SMTP сам пришлёт

                data = s.recv(1024)
                if not data:
                    return None

                banner = data.decode('utf-8', errors='ignore').strip()

                # Для HTTP вытаскиваем Server
                if banner.startswith("HTTP/"):
                    for line in banner.split('\r\n'):
                        if line.lower().startswith("server:"):
                            return line.strip()

                return Utils.truncate(banner, 200)
        except Exception:
            return None


# ==============================================================================
# HTTP ANALYZER
# ==============================================================================
class HTTPAnalyzer(AnalysisModule):
    """
    HTTP/HTTPS анализатор
    - заголовки, статус, title
    - SSL/TLS сертификат
    - WAF-детект (Cloudflare, Sucuri, AWS WAF, Akamai, Imperva)
    - технологии (Server, X-Powered-By, cookies)
    - security headers
    - редиректы
    """

    NAME = "http"
    DESCRIPTION = "HTTP-анализ"

    # Признаки WAF
    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
        "Akamai": ["akamai", "x-akamai-transformed", "akamaighost"],
        "Imperva": ["x-iinfo", "incap_ses", "visid_incap"],
        "F5 BIG-IP": ["x-wa-info", "bigipserver", "ts cookie"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Barracuda": ["barra_counter_session", "barracuda"],
        "Fastly": ["x-served-by", "x-fastly", "fastly-io-info"],
        "Varnish": ["x-varnish", "via: varnish"],
    }

    # Security headers
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "X-Frame-Options": "X-Frame-Options",
        "X-XSS-Protection": "X-XSS-Protection",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy",
        "Cross-Origin-Opener-Policy": "COOP",
        "Cross-Origin-Resource-Policy": "CORP",
        "Cross-Origin-Embedder-Policy": "COEP",
    }

    def __init__(self, logger: "Logger", timeout: int = 10,
                 follow_redirects: bool = True, verify_ssl: bool = False):
        super().__init__(logger)
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl

    def analyze(self, target: "Target", force_scheme: Optional[str] = None) -> Dict[str, Any]:
        """
        Синхронная обёртка вокруг async analyze
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Уже в async-контексте — запускаем в отдельном потоке
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as ex:
                    return ex.submit(
                        lambda: asyncio.run(self._analyze_async(target, force_scheme))
                    ).result()
            else:
                return loop.run_until_complete(self._analyze_async(target, force_scheme))
        except RuntimeError:
            return asyncio.run(self._analyze_async(target, force_scheme))

    async def _analyze_async(self, target: "Target",
                              force_scheme: Optional[str] = None) -> Dict[str, Any]:
        """Асинхронный анализ HTTP"""
        self._start()
        result = self._empty_result()

        if not HAS_AIOHTTP:
            self._add_error("aiohttp не установлен")
            result["errors"] = self.errors
            self._stop()
            result["duration"] = self.duration()
            return result

        schemes = [force_scheme] if force_scheme else ["https", "http"]

        for scheme in schemes:
            url = target.base_url(scheme)
            try:
                r = await self._fetch(url)
                if r:
                    result.update(r)
                    result["scheme"] = scheme
                    result["url"] = url
                    break
            except Exception as e:
                self._add_error(f"{scheme}: {e}")

        # SSL (только для https)
        if result.get("scheme") == "https":
            try:
                result["ssl"] = self._check_ssl(target.hostname, target.port or 443)
            except Exception as e:
                self._add_error(f"SSL: {e}")

        result["errors"] = self.errors
        self._stop()
        result["duration"] = self.duration()
        return result

    def _empty_result(self) -> Dict[str, Any]:
        return {
            "status_code": None,
            "headers": {},
            "server": None,
            "content_type": None,
            "title": None,
            "cookies": [],
            "technologies": [],
            "security_headers": {},
            "waf": None,
            "has_cloudflare": False,
            "redirects": [],
            "ssl": None,
            "errors": [],
            "duration": 0.0,
            "scheme": None,
            "url": None,
        }

    async def _fetch(self, url: str) -> Optional[Dict[str, Any]]:
        """Асинхронный GET-запрос"""
        headers = {
            "User-Agent": Utils.get_random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url,
                headers=headers,
                ssl=self.verify_ssl,
                allow_redirects=self.follow_redirects,
                max_redirects=5,
            ) as resp:

                result = self._empty_result()
                result["status_code"] = resp.status
                result["headers"] = dict(resp.headers)
                result["content_type"] = resp.headers.get("Content-Type")
                result["server"] = resp.headers.get("Server")

                # Редиректы
                if resp.history:
                    result["redirects"] = [
                        {"status": h.status, "location": h.headers.get("Location")}
                        for h in resp.history
                    ]

                # Cookies
                cookies = []
                for c in resp.cookies.values():
                    cookies.append({
                        "name": c.key,
                        "value": Utils.truncate(c.value, 50),
                        "secure": c.get("secure", False),
                        "httponly": c.get("httponly", False),
                    })
                result["cookies"] = cookies

                # WAF
                result.update(self._detect_waf(resp.headers))

                # Security headers
                result["security_headers"] = self._extract_security_headers(resp.headers)

                # Технологии
                result["technologies"] = self._detect_technologies(resp.headers, url)

                # Title
                try:
                    html = await resp.text(errors='ignore')
                    result["title"] = self._extract_title(html)
                except Exception:
                    pass

                return result

    # ---------- SSL ----------
    def _check_ssl(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Проверка SSL/TLS сертификата"""
        result = {
            "valid": False,
            "issuer": None,
            "subject": None,
            "expires": None,
            "issued": None,
            "days_left": None,
            "version": None,
            "cipher": None,
            "san": [],
            "error": None,
        }

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result["valid"] = bool(cert)
                    result["version"] = ssock.version()
                    cipher = ssock.cipher()
                    result["cipher"] = cipher[0] if cipher else None

                    if cert:
                        # Issuer
                        issuer = cert.get("issuer", [])
                        result["issuer"] = self._format_cert_name(issuer)
                        # Subject
                        subject = cert.get("subject", [])
                        result["subject"] = self._format_cert_name(subject)
                        # SAN
                        result["san"] = [v for k, v in cert.get("subjectAltName", [])]

                        # Даты
                        if "notAfter" in cert:
                            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                            result["expires"] = exp.isoformat()
                            result["days_left"] = (exp - datetime.now()).days
                            if result["days_left"] < 0:
                                result["valid"] = False
                        if "notBefore" in cert:
                            iss = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                            result["issued"] = iss.isoformat()
        except ssl.SSLError as e:
            result["error"] = f"SSL: {e}"
        except socket.timeout:
            result["error"] = "Timeout"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _format_cert_name(self, parts) -> str:
        """Форматирует issuer/subject сертификата"""
        try:
            d = {}
            for item in parts:
                for k, v in item:
                    d[k] = v
            if "commonName" in d:
                return d["commonName"]
            if "organizationName" in d:
                return d["organizationName"]
            return str(parts)
        except Exception:
            return str(parts)

    # ---------- WAF ----------
    def _detect_waf(self, headers) -> Dict[str, Any]:
        """Определяет WAF по заголовкам"""
        result = {"waf": None, "has_cloudflare": False}

        # Приводим заголовки к нижнему регистру
        h = {k.lower(): str(v).lower() for k, v in headers.items()}
        all_text = " ".join(f"{k}:{v}" for k, v in h.items())

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in all_text:
                    result["waf"] = waf_name
                    if waf_name == "Cloudflare":
                        result["has_cloudflare"] = True
                    return result

        # Отдельно Cloudflare
        if "cf-ray" in h or "cloudflare" in h.get("server", ""):
            result["waf"] = "Cloudflare"
            result["has_cloudflare"] = True

        return result

    # ---------- Security headers ----------
    def _extract_security_headers(self, headers) -> Dict[str, Any]:
        """Извлекает security-заголовки"""
        result = {}
        for header, name in self.SECURITY_HEADERS.items():
            if header in headers:
                result[name] = Utils.truncate(headers[header], 200)
        return result

    # ---------- Технологии ----------
    def _detect_technologies(self, headers, url: str) -> List[str]:
        """Определяет технологии по заголовкам и URL"""
        techs = set()

        # По заголовкам
        if "X-Powered-By" in headers:
            techs.add(f"Powered-By: {headers['X-Powered-By']}")
        if "X-Generator" in headers:
            techs.add(f"Generator: {headers['X-Generator']}")
        if "X-AspNet-Version" in headers:
            techs.add(f"ASP.NET {headers['X-AspNet-Version']}")
        if "X-AspNetMvc-Version" in headers:
            techs.add(f"ASP.NET MVC {headers['X-AspNetMvc-Version']}")
        if "X-Drupal-Cache" in headers:
            techs.add("Drupal")
        if "X-Drupal-Dynamic-Cache" in headers:
            techs.add("Drupal")
        if "X-Generator" in headers and "WordPress" in headers["X-Generator"]:
            techs.add("WordPress")
        if "X-Shopify-Stage" in headers:
            techs.add("Shopify")
        if "X-Varnish" in headers:
            techs.add("Varnish")
        if "X-Cache" in headers:
            techs.add("CDN-Cache")
        if "X-Cache-Hits" in headers:
            techs.add("Fastly")

        # Server
        server = (headers.get("Server") or "").lower()
        for kw, name in [
            ("nginx", "nginx"), ("apache", "Apache"), ("iis", "IIS"),
            ("caddy", "Caddy"), ("gunicorn", "Gunicorn"), ("uvicorn", "Uvicorn"),
            ("cloudflare", "Cloudflare"), ("openresty", "OpenResty"),
            ("litespeed", "LiteSpeed"), ("tomcat", "Tomcat"),
        ]:
            if kw in server:
                techs.add(name)

        # Cookies
        cookie_str = " ".join(
            f"{c.split('=')[0]}" for c in headers.getall("Set-Cookie", []) if isinstance(headers, dict) and hasattr(headers, "getall")
        ) if hasattr(headers, "getall") else ""
        if "PHPSESSID" in cookie_str:
            techs.add("PHP")
        if "JSESSIONID" in cookie_str:
            techs.add("Java")
        if "ASP.NET_SessionId" in cookie_str:
            techs.add("ASP.NET")
        if "laravel_session" in cookie_str:
            techs.add("Laravel")
        if "django" in cookie_str.lower():
            techs.add("Django")
        if "wordpress" in cookie_str.lower():
            techs.add("WordPress")

        return sorted(techs)

    # ---------- Title ----------
    def _extract_title(self, html: str) -> Optional[str]:
        """Извлекает <title> из HTML"""
        if not html:
            return None
        try:
            m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()
                # Убираем лишние пробелы
                title = re.sub(r'\s+', ' ', title)
                return Utils.truncate(title, 200)
        except Exception:
            pass
        return None


# ==============================================================================
# DNS ANALYZER
# ==============================================================================
class DNSAnalyzer(AnalysisModule):
    """
    DNS-анализатор
    A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, CAA, SRV
    """

    NAME = "dns"
    DESCRIPTION = "DNS-анализ"

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]

    def __init__(self, logger: "Logger", timeout: int = 5):
        super().__init__(logger)
        self.timeout = timeout

    def analyze(self, target: "Target") -> Dict[str, Any]:
        """Анализирует DNS-записи"""
        self._start()
        result = {
            "records": {},
            "has_mx": False,
            "has_txt": False,
            "has_cname": False,
            "has_spf": False,
            "has_dmarc": False,
            "ns": [],
            "mx": [],
            "txt": [],
            "errors": [],
            "duration": 0.0,
        }

        if not HAS_DNS:
            self._add_error("dnspython не установлен")
            result["errors"] = self.errors
            self._stop()
            result["duration"] = self.duration()
            return result

        if not target.hostname:
            self._add_error("Нет домена")
            result["errors"] = self.errors
            self._stop()
            result["duration"] = self.duration()
            return result

        # Резолвер
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
        except Exception as e:
            self._add_error(f"Resolver: {e}")
            resolver = None

        # Основные записи
        for rtype in self.RECORD_TYPES:
            if is_shutdown_requested():
                break
            values = self._query(resolver, target.hostname, rtype)
            if values:
                result["records"][rtype] = values
                if rtype == "MX":
                    result["has_mx"] = True
                    result["mx"] = values
                elif rtype == "NS":
                    result["ns"] = values
                elif rtype == "TXT":
                    result["has_txt"] = True
                    result["txt"] = values
                    for v in values:
                        vl = v.lower()
                        if "v=spf1" in vl:
                            result["has_spf"] = True
                elif rtype == "CNAME":
                    result["has_cname"] = True

        # DMARC
        dmarc = self._query(resolver, f"_dmarc.{target.hostname}", "TXT")
        if dmarc:
            result["has_dmarc"] = True
            result["records"]["DMARC"] = dmarc

        # PTR (reverse DNS)
        if target.ip:
            ptr = self._reverse_dns(target.ip)
            if ptr:
                result["records"]["PTR"] = [ptr]

        result["errors"] = self.errors
        self._stop()
        result["duration"] = self.duration()
        return result

    def _query(self, resolver, name: str, rtype: str) -> List[str]:
        """Выполняет один DNS-запрос"""
        if resolver is None:
            return []
        try:
            answers = resolver.resolve(name, rtype, lifetime=self.timeout)
            return [str(a).strip('"') for a in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception as e:
            self._add_error(f"{rtype} {name}: {e}")
            return []

    def _reverse_dns(self, ip: str) -> Optional[str]:
        """Обратный DNS-запрос"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None


# ==============================================================================
# OSINT MODULE
# ==============================================================================
class OSINTModule(AnalysisModule):
    """
    OSINT-модуль
    - WHOIS
    - DNS-история (эмуляция через crt.sh)
    """

    NAME = "osint"
    DESCRIPTION = "OSINT / WHOIS"

    def __init__(self, logger: "Logger"):
        super().__init__(logger)

    def whois(self, target: "Target") -> Dict[str, Any]:
        """WHOIS-запрос"""
        self._start()
        result = {
            "domain": target.hostname,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "status": [],
            "emails": [],
            "country": None,
            "org": None,
            "raw": None,
            "errors": [],
            "duration": 0.0,
        }

        if not HAS_WHOIS:
            self._add_error("python-whois не установлен")
            result["errors"] = self.errors
            self._stop()
            result["duration"] = self.duration()
            return result

        try:
            w = whois_lib.whois(target.hostname)

            result["registrar"] = w.registrar
            result["country"] = getattr(w, "country", None)
            result["org"] = getattr(w, "org", None)

            # Даты (могут быть list)
            for key in ("creation_date", "expiration_date", "updated_date"):
                v = getattr(w, key, None)
                if isinstance(v, list):
                    v = v[0] if v else None
                result[key] = str(v) if v else None

            # NS
            ns = getattr(w, "name_servers", None)
            if ns:
                if isinstance(ns, str):
                    ns = [ns]
                result["name_servers"] = [str(x).lower() for x in ns]

            # Status
            st = getattr(w, "status", None)
            if st:
                if isinstance(st, str):
                    st = [st]
                result["status"] = [str(x) for x in st]

            # Emails
            em = getattr(w, "emails", None)
            if em:
                if isinstance(em, str):
                    em = [em]
                result["emails"] = [str(x) for x in em]

            result["raw"] = str(w)[:2000]

        except Exception as e:
            self._add_error(f"WHOIS: {e}")

        result["errors"] = self.errors
        self._stop()
        result["duration"] = self.duration()
        return result

    def analyze(self, target: "Target") -> Dict[str, Any]:
        """Полный OSINT-анализ"""
        return {
            "whois": self.whois(target),
        }


# ==============================================================================
# SUBDOMAIN MODULE
# ==============================================================================
class SubdomainModule(AnalysisModule):
    """
    Поиск поддоменов
    Источники:
        - crt.sh (Certificate Transparency)
        - Sublist3r (если скачан)
        - amass (если скачан)
        - subfinder (если скачан)
        - DNS-брутфорс по словарю (опционально)
    """

    NAME = "subdomains"
    DESCRIPTION = "Поиск поддоменов"

    # Небольшой словарь для DNS-брутфорса
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
        "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile",
        "mx", "static", "docs", "beta", "shop", "sql", "secure", "demo",
        "cp", "calendar", "wiki", "web", "media", "email", "images", "img",
        "www1", "intranet", "portal", "video", "sip", "dns2", "api", "cdn",
        "stats", "dns1", "ns4", "www3", "dns", "search", "staging", "server",
        "mx1", "chat", "wap", "my", "svn", "mail1", "sites", "proxy",
        "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover",
        "info", "apps", "download", "remote", "db", "forums", "store",
        "relay", "files", "newsletter", "app", "live", "owa", "en",
        "start", "sms", "office", "exchange", "ipv4",
    ]

    def __init__(self, logger: "Logger", repo_manager: "RepoManager",
                 max_subdomains: int = 500):
        super().__init__(logger)
        self.repo_manager = repo_manager
        self.max_subdomains = max_subdomains

    def find(self, target: "Target", use_bruteforce: bool = False,
             use_tools: bool = True) -> Dict[str, Any]:
        """
        Ищет поддомены

        use_bruteforce — использовать DNS-брутфорс
        use_tools      — использовать внешние инструменты (Sublist3r, amass, subfinder)
        """
        self._start()
        result = {
            "subdomains": [],
            "total": 0,
            "sources": [],
            "by_source": {},
            "errors": [],
            "duration": 0.0,
        }

        domain = target.hostname
        if not domain or target.is_ip:
            self._add_error("Поддомены ищутся только для доменов")
            result["errors"] = self.errors
            self._stop()
            result["duration"] = self.duration()
            return result

        collected = set()

        # 1. crt.sh
        if not is_shutdown_requested():
            try:
                subs = self._crt_sh(domain)
                if subs:
                    result["sources"].append("crt.sh")
                    result["by_source"]["crt.sh"] = subs
                    collected.update(subs)
                    self.logger.info(f"    crt.sh: {len(subs)}")
            except Exception as e:
                self._add_error(f"crt.sh: {e}")

        # 2. Sublist3r
        if use_tools and not is_shutdown_requested():
            try:
                subs = self._run_sublist3r(domain)
                if subs:
                    result["sources"].append("Sublist3r")
                    result["by_source"]["Sublist3r"] = subs
                    collected.update(subs)
                    self.logger.info(f"    Sublist3r: {len(subs)}")
            except Exception as e:
                self._add_error(f"Sublist3r: {e}")

        # 3. amass
        if use_tools and not is_shutdown_requested():
            try:
                subs = self._run_amass(domain)
                if subs:
                    result["sources"].append("amass")
                    result["by_source"]["amass"] = subs
                    collected.update(subs)
                    self.logger.info(f"    amass: {len(subs)}")
            except Exception as e:
                self._add_error(f"amass: {e}")

        # 4. subfinder
        if use_tools and not is_shutdown_requested():
            try:
                subs = self._run_subfinder(domain)
                if subs:
                    result["sources"].append("subfinder")
                    result["by_source"]["subfinder"] = subs
                    collected.update(subs)
                    self.logger.info(f"    subfinder: {len(subs)}")
            except Exception as e:
                self._add_error(f"subfinder: {e}")

        # 5. DNS-брутфорс
        if use_bruteforce and not is_shutdown_requested():
            try:
                subs = self._dns_bruteforce(domain)
                if subs:
                    result["sources"].append("dns-bruteforce")
                    result["by_source"]["dns-bruteforce"] = subs
                    collected.update(subs)
                    self.logger.info(f"    DNS-bruteforce: {len(subs)}")
            except Exception as e:
                self._add_error(f"bruteforce: {e}")

        # Финал
        subs = sorted(collected)
        if len(subs) > self.max_subdomains:
            subs = subs[:self.max_subdomains]

        result["subdomains"] = subs
        result["total"] = len(subs)
        result["errors"] = self.errors
        self._stop()
        result["duration"] = self.duration()
        return result

    # ---------- crt.sh ----------
    def _crt_sh(self, domain: str) -> List[str]:
        """Ищет поддомены через crt.sh"""
        if not HAS_REQUESTS:
            return []

        subs = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        try:
            r = requests.get(
                url,
                timeout=20,
                headers={"User-Agent": Utils.get_random_ua()}
            )
            if r.status_code != 200:
                return []
            data = r.json()
            for entry in data:
                for name in (entry.get("name_value") or "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain) and name != domain and " " not in name:
                        subs.add(name)
        except Exception as e:
            self._add_error(f"crt.sh: {e}")

        return sorted(subs)

    # ---------- Sublist3r ----------
    def _run_sublist3r(self, domain: str) -> List[str]:
        """Запускает Sublist3r из RepoManager"""
        repo_path = self.repo_manager.get_repo_path("sublist3r")
        if not repo_path:
            return []

        script = repo_path / "sublist3r.py"
        if not script.exists():
            return []

        try:
            cmd = f'"{sys.executable}" "{script}" -d {domain} -v -t 20'
            ok, out, err = self.repo_manager._run_command(cmd, timeout=120)
            if not ok:
                return []

            subs = set()
            for line in out.splitlines():
                line = line.strip()
                if not line or line.startswith("[") or line.startswith(" "):
                    continue
                # Sublist3r выводит чистые домены
                if domain in line and " " not in line:
                    subs.add(line.lower())
            return sorted(subs)
        except Exception as e:
            self._add_error(f"Sublist3r: {e}")
            return []

    # ---------- amass ----------
    def _run_amass(self, domain: str) -> List[str]:
        """Запускает amass из RepoManager"""
        repo_path = self.repo_manager.get_repo_path("amass")
        if not repo_path:
            return []

        # amass — Go-бинарник, может быть уже скомпилирован
        amass_bin = None
        for candidate in ["amass", "cmd/amass/amass"]:
            p = repo_path / candidate
            if p.exists():
                amass_bin = p
                break

        if not amass_bin:
            # Пробуем системный amass
            if Utils.has_command("amass"):
                cmd = f"amass enum -passive -d {domain} -timeout 2"
            else:
                return []
        else:
            cmd = f'"{amass_bin}" enum -passive -d {domain} -timeout 2'

        try:
            ok, out, err = self.repo_manager._run_command(cmd, timeout=120)
            if not ok:
                return []

            subs = set()
            for line in out.splitlines():
                line = line.strip()
                if domain in line and " " not in line:
                    subs.add(line.lower())
            return sorted(subs)
        except Exception as e:
            self._add_error(f"amass: {e}")
            return []

    # ---------- subfinder ----------
    def _run_subfinder(self, domain: str) -> List[str]:
        """Запускает subfinder из RepoManager"""
        repo_path = self.repo_manager.get_repo_path("subfinder")
        if not repo_path:
            return []

        # subfinder — Go, ищем бинарник
        subfinder_bin = None
        for candidate in ["subfinder", "cmd/subfinder/subfinder"]:
            p = repo_path / candidate
            if p.exists():
                subfinder_bin = p
                break

        if not subfinder_bin:
            if Utils.has_command("subfinder"):
                cmd = f"subfinder -d {domain} -silent -timeout 10"
            else:
                return []
        else:
            cmd = f'"{subfinder_bin}" -d {domain} -silent -timeout 10'

        try:
            ok, out, err = self.repo_manager._run_command(cmd, timeout=120)
            if not ok:
                return []

            subs = set()
            for line in out.splitlines():
                line = line.strip()
                if domain in line and " " not in line:
                    subs.add(line.lower())
            return sorted(subs)
        except Exception as e:
            self._add_error(f"subfinder: {e}")
            return []

    # ---------- DNS-брутфорс ----------
    def _dns_bruteforce(self, domain: str) -> List[str]:
        """DNS-брутфорс по встроенному словарю"""
        if not HAS_DNS:
            return []

        subs = set()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        def check(sub: str):
            if is_shutdown_requested():
                return
            full = f"{sub}.{domain}"
            try:
                resolver.resolve(full, "A", lifetime=2)
                subs.add(full)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = [ex.submit(check, s) for s in self.COMMON_SUBDOMAINS]
            for _ in as_completed(futures):
                pass

        return sorted(subs)


# ==============================================================================
# КОНЕЦ PART 3
# ==============================================================================
# В следующей части (part4_vuln.py):
#   - class VulnBase
#   - class CVEScanner  (NVD API + offline fallback)
#   - class NiktoScanner (через RepoManager)
#   - class SQLiScanner
#   - class XSSScanner
#   - class LfiScanner
#   - class StressTester (Slowloris + HTTP-флуд + GoldenEye)
# ==============================================================================