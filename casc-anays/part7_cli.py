# ==============================================================================
# PART 7 — ФИНАЛЬНЫЙ CLI, ТЕСТЫ, ТОЧКА ВХОДА
# CASC-ANAYS v4.0 — Финальная сборка
# ==============================================================================
# Требует: part1_core.py … part6_reports.py
# ==============================================================================

import os
import sys
import json
import time
import argparse
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


# ==============================================================================
# КОНФИГУРАЦИЯ ПО УМОЛЧАНИЮ (config.json)
# ==============================================================================
DEFAULT_CONFIG_JSON: Dict[str, Any] = {
    "targets": [],
    "modules": {
        "osint": True,
        "subdomain": True,
        "vuln": True,
        "stress": True,
        "port_scan": True
    },
    "settings": {
        "threads": 10,
        "timeout": 10,
        "output_dir": "reports",
        "log_level": "INFO",
        "log_file": None,
        "use_proxy": False,
        "proxy_file": "proxies.txt",
        "user_agent": None,
        "follow_redirects": True,
        "verify_ssl": False,
        "max_subdomains": 500,
        "parallel_repos": False,
        "subdomain_bruteforce": False
    },
    "repos": {
        # OSINT (12)
        "sherlock": {"url": "https://github.com/sherlock-project/sherlock.git", "branch": "master"},
        "whatsmyname": {"url": "https://github.com/WebBreacher/WhatsMyName.git", "branch": "main"},
        "maigret": {"url": "https://github.com/soxoj/maigret.git", "branch": "main"},
        "theharvester": {"url": "https://github.com/laramies/theHarvester.git", "branch": "master"},
        "spiderfoot": {"url": "https://github.com/smicallef/spiderfoot.git", "branch": "master"},
        "ghunt": {"url": "https://github.com/mxrch/GHunt.git", "branch": "main"},
        "photon": {"url": "https://github.com/s0md3v/Photon.git", "branch": "master"},
        "osintgram": {"url": "https://github.com/Datalux/Osintgram.git", "branch": "main"},
        "h8mail": {"url": "https://github.com/khast3x/h8mail.git", "branch": "master"},
        "holehe": {"url": "https://github.com/megadose/holehe.git", "branch": "master"},
        "trape": {"url": "https://github.com/jofpin/trape.git", "branch": "master"},
        "torbot": {"url": "https://github.com/DedSecInside/TorBot.git", "branch": "main"},
        # Поддомены (9)
        "sublist3r": {"url": "https://github.com/aboul3la/Sublist3r.git", "branch": "master"},
        "amass": {"url": "https://github.com/owasp-amass/amass.git", "branch": "master"},
        "subfinder": {"url": "https://github.com/projectdiscovery/subfinder.git", "branch": "main"},
        "findomain": {"url": "https://github.com/Findomain/Findomain.git", "branch": "master"},
        "subcat": {"url": "https://github.com/duty1g/subcat.git", "branch": "main"},
        "subdomain-enumerator": {"url": "https://github.com/ryuukhagetsu/subdomain-enumerator.git", "branch": "main"},
        "subdomain-enum-tool": {"url": "https://github.com/Sergios9494/subdomain-enum-tool.git", "branch": "main"},
        "dnsrecon": {"url": "https://github.com/darkoperator/dnsrecon.git", "branch": "master"},
        "certinfo": {"url": "https://github.com/rix4uni/certinfo.git", "branch": "main"},
        # Уязвимости (12)
        "nikto": {"url": "https://github.com/sullo/nikto.git", "branch": "master"},
        "nuclei": {"url": "https://github.com/projectdiscovery/nuclei.git", "branch": "main"},
        "web-vuln-scanner": {"url": "https://github.com/HoangZuzi-14/Web-Vulnerability-Scanner.git", "branch": "main"},
        "wpscan": {"url": "https://github.com/wpscanteam/wpscan.git", "branch": "master"},
        "joomscan": {"url": "https://github.com/rezasp/joomscan.git", "branch": "master"},
        "cmsmap": {"url": "https://github.com/dionach/CMSmap.git", "branch": "master"},
        "cmseek": {"url": "https://github.com/Tuhinshubhra/CMSeeK.git", "branch": "master"},
        "cms-vuln-scanner": {"url": "https://github.com/Lordozer/cms-scanner.git", "branch": "main"},
        "jaeles": {"url": "https://github.com/jaeles-project/jaeles.git", "branch": "main"},
        "gitleaks": {"url": "https://github.com/gitleaks/gitleaks.git", "branch": "master"},
        "trufflehog": {"url": "https://github.com/trufflesecurity/trufflehog.git", "branch": "main"},
        "wordpress-plugins": {"url": "https://github.com/rix4uni/wordpress-plugins.git", "branch": "main"},
        # Стресс (4)
        "floodles": {"url": "https://github.com/franckferman/Floodles.git", "branch": "main"},
        "ddos-attack": {"url": "https://github.com/karthik558/ddos-attack.git", "branch": "main"},
        "slowloris": {"url": "https://github.com/gkbrk/slowloris.git", "branch": "master"},
        "goldeneye": {"url": "https://github.com/jseidl/GoldenEye.git", "branch": "master"},
        # Словари (2)
        "seclists": {"url": "https://github.com/danielmiessler/SecLists.git", "branch": "master"},
        "fuzzdb": {"url": "https://github.com/fuzzdb-project/fuzzdb.git", "branch": "master"},
        # Вспомогательные (1)
        "behindthecdn": {"url": "https://github.com/Neved4/behindTheCDN.git", "branch": "main"}
    }
}


def create_default_config(path: str = "config.json", force: bool = False) -> bool:
    """
    Создаёт config.json, если его нет
    force=True — перезаписать
    """
    p = Path(path)
    if p.exists() and not force:
        return False

    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_CONFIG_JSON, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(Colors.red(f"Ошибка создания конфига: {e}"))
        return False


# ==============================================================================
# CLI-ПАРСЕР
# ==============================================================================
def build_cli() -> argparse.ArgumentParser:
    """
    Строит полный CLI CASC-ANAYS
    Все аргументы сгруппированы по логическим блокам
    """
    parser = argparse.ArgumentParser(
        prog="casc-anays",
        description=f"{Colors.purple('CASC-ANAYS')} — Глобальный аналитический комплекс",
        epilog=f"Автор: {AUTHOR} | GitHub: {GITHUB_URL} | Лицензия: {LICENSE}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    # ==========================================================================
    # ГРУППА 1: ЦЕЛИ
    # ==========================================================================
    targets = parser.add_argument_group("🎯 ЦЕЛИ")
    targets.add_argument(
        "-t", "--target",
        metavar="DOMAIN/IP",
        help="Цель для анализа (домен или IP-адрес)"
    )
    targets.add_argument(
        "--targets-file",
        metavar="FILE",
        help="Файл со списком целей (по одной на строку, # — комментарий)"
    )
    targets.add_argument(
        "--list-targets",
        action="store_true",
        help="Показать список сохранённых целей из config.json"
    )
    targets.add_argument(
        "--add-target",
        metavar="TARGET",
        help="Добавить цель в config.json"
    )
    targets.add_argument(
        "--remove-target",
        metavar="TARGET",
        help="Удалить цель из config.json"
    )

    # ==========================================================================
    # ГРУППА 2: РЕЖИМЫ АНАЛИЗА
    # ==========================================================================
    modes = parser.add_argument_group("⚙️  РЕЖИМЫ АНАЛИЗА")
    modes.add_argument(
        "-f", "--full",
        action="store_true",
        help="Полный анализ цели (все модули)"
    )
    modes.add_argument(
        "-s", "--smart",
        action="store_true",
        help="Умный анализ (авто-подбор модулей по результатам разведки)"
    )
    modes.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Запустить интерактивный режим"
    )
    modes.add_argument(
        "-m", "--modules",
        metavar="MODULES",
        help="Список модулей через запятую: ports,http,dns,osint,subdomains,vuln,stress"
    )
    modes.add_argument(
        "--no-stress",
        action="store_true",
        help="Исключить стресс-тесты (только анализ)"
    )
    modes.add_argument(
        "--no-vuln",
        action="store_true",
        help="Исключить проверку уязвимостей"
    )
    modes.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Исключить поиск поддоменов"
    )
    modes.add_argument(
        "--subdomain-brute",
        action="store_true",
        help="Использовать DNS-брутфорс поддоменов (медленно)"
    )

    # ==========================================================================
    # ГРУППА 3: РЕПОЗИТОРИИ
    # ==========================================================================
    repos = parser.add_argument_group("📦 РЕПОЗИТОРИИ")
    repos.add_argument(
        "--init-repos",
        action="store_true",
        help="Инициализировать все репозитории (клонировать/обновить)"
    )
    repos.add_argument(
        "--update-repos",
        action="store_true",
        help="Обновить существующие репозитории"
    )
    repos.add_argument(
        "--list-repos",
        action="store_true",
        help="Показать список всех репозиториев"
    )
    repos.add_argument(
        "--clean-repos",
        action="store_true",
        help="Удалить все клонированные репозитории"
    )
    repos.add_argument(
        "--all",
        action="store_true",
        help="Включить тяжёлые репозитории (seclists, spiderfoot и т.д.)"
    )
    repos.add_argument(
        "--parallel",
        action="store_true",
        help="Параллельное клонирование репозиториев"
    )
    repos.add_argument(
        "--install-deps",
        action="store_true",
        help="Установить зависимости репозиториев (pip/npm/go)"
    )

    # ==========================================================================
    # ГРУППА 4: ОТЧЁТЫ
    # ==========================================================================
    reports = parser.add_argument_group("📄 ОТЧЁТЫ")
    reports.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Путь к файлу отчёта (.html, .json, .csv, .md)"
    )
    reports.add_argument(
        "--format",
        choices=["html", "json", "csv", "md", "all"],
        default="both",
        help="Формат отчёта (по умолчанию: both = html + json)"
    )
    reports.add_argument(
        "--no-report",
        action="store_true",
        help="Не генерировать отчёты"
    )
    reports.add_argument(
        "--no-html",
        action="store_true",
        help="Не генерировать HTML-отчёт"
    )
    reports.add_argument(
        "--no-json",
        action="store_true",
        help="Не генерировать JSON-отчёт"
    )
    reports.add_argument(
        "--open",
        action="store_true",
        help="Открыть HTML-отчёт в браузере после генерации"
    )

    # ==========================================================================
    # ГРУППА 5: НАСТРОЙКИ
    # ==========================================================================
    settings = parser.add_argument_group("🔧 НАСТРОЙКИ")
    settings.add_argument(
        "--config",
        metavar="FILE",
        default="config.json",
        help="Путь к файлу конфигурации (по умолчанию: config.json)"
    )
    settings.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Уровень логирования (по умолчанию: INFO)"
    )
    settings.add_argument(
        "--log-file",
        metavar="FILE",
        help="Путь к файлу логов"
    )
    settings.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Количество потоков (по умолчанию: 10)"
    )
    settings.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Таймаут запросов в секундах (по умолчанию: 10)"
    )
    settings.add_argument(
        "--output-dir",
        default="reports",
        help="Директория для отчётов (по умолчанию: reports)"
    )
    settings.add_argument(
        "--proxy",
        metavar="URL",
        help="Использовать прокси (например: socks5://127.0.0.1:9050)"
    )
    settings.add_argument(
        "--user-agent",
        metavar="UA",
        help="Кастомный User-Agent"
    )

    # ==========================================================================
    # ГРУППА 6: ДИАГНОСТИКА
    # ==========================================================================
    diag = parser.add_argument_group("🔬 ДИАГНОСТИКА")
    diag.add_argument(
        "--self-test",
        action="store_true",
        help="Запустить самотестирование всех модулей"
    )
    diag.add_argument(
        "--deps",
        action="store_true",
        help="Показать статус зависимостей"
    )
    diag.add_argument(
        "--system-info",
        action="store_true",
        help="Показать информацию о системе"
    )
    diag.add_argument(
        "--check-git",
        action="store_true",
        help="Проверить наличие git в системе"
    )

    # ==========================================================================
    # ГРУППА 7: ИНТЕРФЕЙС
    # ==========================================================================
    ui = parser.add_argument_group("🖥  ИНТЕРФЕЙС")
    ui.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Тихий режим (без баннера)"
    )
    ui.add_argument(
        "--debug",
        action="store_true",
        help="Отладочный режим (много логов)"
    )
    ui.add_argument(
        "--no-color",
        action="store_true",
        help="Отключить цвета (для логов в файл)"
    )
    ui.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Автоматически подтверждать все запросы"
    )
    ui.add_argument(
        "--print-help",
        action="store_true",
        help="Показать расширенную справку с примерами"
    )

    # ==========================================================================
    # ИНФО
    # ==========================================================================
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"CASC-ANAYS v{VERSION}"
    )

    return parser


# ==============================================================================
# РАСШИРЕННАЯ СПРАВКА
# ==============================================================================
def print_help_extended():
    """Красивая расширенная справка с примерами"""
    text = f"""
{Colors.purple('╔══════════════════════════════════════════════════════════════════════╗')}
{Colors.purple('║')}  {Colors.bold(Colors.light_purple('CASC-ANAYS v' + VERSION))} — Глобальный аналитический комплекс       {Colors.purple('║')}
{Colors.purple('║')}  {Colors.cyan('Анализ веб-сайтов | OSINT | Поддомены | Уязвимости | Стресс')}      {Colors.purple('║')}
{Colors.purple('╚══════════════════════════════════════════════════════════════════════╝')}

{Colors.bold_purple('ПРИМЕРЫ:')}

  {Colors.dim('# Полный анализ одного домена')}
  {Colors.cyan('casc-anays -t example.com --full')}

  {Colors.dim('# Умный анализ (авто-подбор модулей)')}
  {Colors.cyan('casc-anays -t example.com --smart')}

  {Colors.dim('# Интерактивный режим')}
  {Colors.cyan('casc-anays -i')}

  {Colors.dim('# Только порты и HTTP')}
  {Colors.cyan('casc-anays -t example.com -m ports,http')}

  {Colors.dim('# Без стресс-тестов (безопасно)')}
  {Colors.cyan('casc-anays -t example.com --full --no-stress')}

  {Colors.dim('# Список целей из файла')}
  {Colors.cyan('casc-anays --targets-file targets.txt --full -o report.html')}

  {Colors.dim('# Множество целей + CSV-отчёт')}
  {Colors.cyan('casc-anays --targets-file targets.txt --smart --format csv')}

  {Colors.dim('# Инициализация всех репозиториев')}
  {Colors.cyan('casc-anays --init-repos')}

  {Colors.dim('# Только конкретные репозитории + параллельно')}
  {Colors.cyan('casc-anays --init-repos --parallel')}

  {Colors.dim('# С зависимостями')}
  {Colors.cyan('casc-anays --init-repos --install-deps')}

  {Colors.dim('# Включить тяжёлые (SecLists ~1.5GB)')}
  {Colors.cyan('casc-anays --init-repos --all')}

  {Colors.dim('# Список репозиториев')}
  {Colors.cyan('casc-anays --list-repos')}

  {Colors.dim('# Самотестирование')}
  {Colors.cyan('casc-anays --self-test')}

{Colors.bold_purple('МОДУЛИ:')}
  {Colors.light_purple('ports')}       — Сканирование портов (TCP + UDP)
  {Colors.light_purple('http')}        — HTTP-анализ (заголовки, SSL, WAF, технологии)
  {Colors.light_purple('dns')}         — DNS-анализ (A/AAAA/MX/NS/TXT/CNAME/SOA)
  {Colors.light_purple('osint')}       — WHOIS, разведка
  {Colors.light_purple('subdomains')}  — Поддомены (crt.sh + Sublist3r + amass + subfinder)
  {Colors.light_purple('vuln')}        — Уязвимости (CVE, Nikto, SQLi, XSS, LFI)
  {Colors.light_purple('stress')}      — Стресс-тесты (Slowloris, HTTP-флуд, GoldenEye)

{Colors.bold_purple('ИНТЕРАКТИВНЫЙ РЕЖИМ:')}
  Запустите {Colors.cyan('casc-anays -i')} и выберите нужный пункт меню.
  Все результаты сохраняются в {Colors.cyan('./reports/')}.

{Colors.bold_purple('АВТОР:')}   {AUTHOR}
{Colors.bold_purple('GITHUB:')}  {GITHUB_URL}
{Colors.bold_purple('ЛИЦЕНЗИЯ:')} {LICENSE}
"""
    print(text)


# ==============================================================================
# САМОТЕСТИРОВАНИЕ
# ==============================================================================
def run_self_tests() -> bool:
    """
    Запускает самотестирование всех модулей
    Возвращает True, если все тесты прошли
    """
    print()
    print(Colors.bold_purple("╔" + "═" * 68 + "╗"))
    print(Colors.bold_purple("║" + " " * 20 + "CASC-ANAYS — САМОТЕСТИРОВАНИЕ" + " " * 20 + "║"))
    print(Colors.bold_purple("╚" + "═" * 68 + "╝"))
    print()

    passed = 0
    failed = 0
    tests: List[tuple] = []

    # ---------- 1. Utils ----------
    def test_utils():
        assert Utils.normalize_target("https://example.com/path") == "example.com"
        assert Utils.normalize_target("example.com:8080") == "example.com"
        assert Utils.get_domain_from_url("https://example.com/x") == "example.com"
        assert Utils.format_bytes(1024) == "1.00 KB"
        assert Utils.format_bytes(1048576) == "1.00 MB"
        assert Utils.is_valid_ip("8.8.8.8")
        assert not Utils.is_valid_ip("not-an-ip")
        assert Utils.is_valid_domain("example.com")
        assert not Utils.is_valid_domain("not a domain")
        assert Utils.safe_int("42") == 42
        assert Utils.safe_int("bad", 0) == 0
        return "Utils: 11 проверок"

    # ---------- 2. Target ----------
    def test_target():
        t = Target("example.com")
        assert t.is_valid()
        assert t.hostname == "example.com"

        t2 = Target("https://example.com:8443/path")
        assert t2.hostname == "example.com"
        assert t2.port == 8443
        assert t2.scheme == "https"

        t3 = Target("8.8.8.8")
        assert t3.is_ip
        assert t3.ip == "8.8.8.8"

        t4 = Target("127.0.0.1")
        assert t4.is_valid()
        assert t4.base_url("http") == "http://127.0.0.1"

        return "Target: 8 проверок"

    # ---------- 3. Config ----------
    def test_config():
        test_path = "test_config_casc.json"
        if os.path.exists(test_path):
            os.remove(test_path)

        cfg = Config(test_path)
        assert cfg.get('settings.timeout') == 10

        cfg.set('settings.timeout', 30)
        assert cfg.get('settings.timeout') == 30

        cfg.add_target("test.com")
        assert "test.com" in cfg.list_targets()

        cfg.remove_target("test.com")
        assert "test.com" not in cfg.list_targets()

        os.remove(test_path)
        return "Config: 5 проверок"

    # ---------- 4. Logger ----------
    def test_logger():
        log = Logger(log_file=None, level="DEBUG")
        log.debug("test")
        log.info("test")
        log.warning("test")
        log.error("test")
        log.success("test")
        assert log.level == 0
        log.set_level("ERROR")
        assert log.level == 3
        return "Logger: 2 проверки"

    # ---------- 5. PortScanner ----------
    def test_portscanner():
        log = Logger()
        scanner = PortScanner(log, timeout=0.5)
        t = Target("127.0.0.1")
        result = scanner.scan(t, ports=[99999, 99998], grab_banners=False)
        assert isinstance(result, dict)
        assert "ports" in result
        assert "open_count" in result
        assert result["open_count"] == 0  # эти порты точно закрыты
        return "PortScanner: 4 проверки"

    # ---------- 6. HTTPAnalyzer ----------
    def test_http_analyzer():
        log = Logger()
        analyzer = HTTPAnalyzer(log, timeout=3)
        # Проверяем только что класс создаётся и имеет нужные методы
        assert hasattr(analyzer, "analyze")
        assert hasattr(analyzer, "_check_ssl")
        assert hasattr(analyzer, "_detect_waf")
        assert hasattr(analyzer, "_detect_technologies")
        return "HTTPAnalyzer: 4 проверки"

    # ---------- 7. DNSAnalyzer ----------
    def test_dns_analyzer():
        log = Logger()
        analyzer = DNSAnalyzer(log)
        assert hasattr(analyzer, "analyze")
        # Тест на localhost
        t = Target("localhost")
        result = analyzer.analyze(t)
        assert isinstance(result, dict)
        assert "records" in result
        return "DNSAnalyzer: 3 проверки"

    # ---------- 8. OSINTModule ----------
    def test_osint():
        log = Logger()
        osint = OSINTModule(log)
        assert hasattr(osint, "whois")
        assert hasattr(osint, "analyze")
        return "OSINTModule: 2 проверки"

    # ---------- 9. CVEScanner ----------
    def test_cve():
        log = Logger()
        cve = CVEScanner(log)
        # Проверка offline базы
        vulns = cve._check_offline("apache", "2.4.49")
        assert len(vulns) > 0
        assert vulns[0][0] == "CVE-2021-41773"
        # Парсинг версий
        parsed = cve._parse_version_string("nginx/1.18.0")
        assert parsed.get("nginx") == "1.18.0"
        return "CVEScanner: 4 проверки"

    # ---------- 10. SQLiScanner ----------
    def test_sqli():
        log = Logger()
        sqli = SQLiScanner(log, timeout=2)
        assert hasattr(sqli, "scan")
        # Проверка детекта SQL-ошибки
        assert sqli._looks_like_sqli("You have an error in your SQL syntax")
        assert sqli._looks_like_sqli("Warning: mysql_fetch_array()")
        assert not sqli._looks_like_sqli("Hello world")
        return "SQLiScanner: 3 проверки"

    # ---------- 11. XSSScanner ----------
    def test_xss():
        log = Logger()
        xss = XSSScanner(log, timeout=2)
        assert hasattr(xss, "scan")
        assert hasattr(xss, "_is_reflected")
        assert xss._is_reflected("<script>alert(1)</script>", "<script>alert(1)</script>", "X")
        return "XSSScanner: 3 проверки"

    # ---------- 12. LfiScanner ----------
    def test_lfi():
        log = Logger()
        lfi = LfiScanner(log, timeout=2)
        assert hasattr(lfi, "scan")
        assert lfi._looks_like_lfi("root:x:0:0:root:/root:/bin/bash")
        assert not lfi._looks_like_lfi("Hello world")
        return "LfiScanner: 2 проверки"

    # ---------- 13. StressTester ----------
    def test_stress():
        log = Logger()
        st = StressTester(log, None)
        assert hasattr(st, "slowloris_test")
        assert hasattr(st, "http_flood_test")
        assert hasattr(st, "goldeneye_test")
        return "StressTester: 3 проверки"

    # ---------- 14. HTMLReportGenerator ----------
    def test_html_report():
        gen = HTMLReportGenerator(version=VERSION)
        test_results = {
            "test.com": {
                "hostname": "test.com",
                "ip": "1.2.3.4",
                "status": "completed",
                "duration": 1.5,
                "modules": {
                    "ports": {
                        "ports": {
                            80: {"service": "http", "risk": "normal", "banner": "nginx"},
                            443: {"service": "https", "risk": "normal", "banner": ""},
                        },
                        "open_count": 2,
                        "scanned": 100,
                    },
                    "http": {
                        "server": "nginx/1.18.0",
                        "status_code": 200,
                        "title": "Test Page",
                        "waf": None,
                        "scheme": "https",
                        "technologies": ["nginx"],
                    },
                },
            }
        }
        html = gen.generate(test_results)
        assert "<!DOCTYPE html>" in html
        assert "CASC-ANAYS" in html
        assert "test.com" in html
        assert "nginx" in html
        return "HTMLReport: 4 проверки"

    # ---------- 15. JSONReportGenerator ----------
    def test_json_report():
        gen = JSONReportGenerator()
        test_results = {"test.com": {"hostname": "test.com"}}
        j = gen.generate(test_results)
        data = json.loads(j)
        assert "meta" in data
        assert data["meta"]["generator"] == "CASC-ANAYS"
        assert "results" in data
        return "JSONReport: 3 проверки"

    # ---------- 16. CSVReportGenerator ----------
    def test_csv_report():
        gen = CSVReportGenerator()
        test_results = {
            "test.com": {
                "hostname": "test.com",
                "modules": {
                    "vuln": {
                        "sqli": [
                            {"name": "SQLi", "severity": "high", "description": "test"}
                        ]
                    }
                }
            }
        }
        csv_text = gen.generate(test_results)
        assert "Target" in csv_text
        assert "SQLi" in csv_text
        return "CSVReport: 2 проверки"

    # ---------- 17. MarkdownReportGenerator ----------
    def test_md_report():
        gen = MarkdownReportGenerator()
        test_results = {"test.com": {"hostname": "test.com", "modules": {}}}
        md = gen.generate(test_results)
        assert "# CASC-ANAYS" in md
        assert "test.com" in md
        return "MarkdownReport: 2 проверки"

    # ---------- 18. AppState ----------
    def test_app_state():
        state = AppState()
        state.start()
        time.sleep(0.01)
        state.stop()
        assert state.duration() >= 0.01
        state.inc_targets()
        assert state.targets_processed == 1
        s = state.summary()
        assert "duration" in s
        return "AppState: 3 проверки"

    # ---------- 19. ProgressBar ----------
    def test_progress_bar():
        with ProgressBar(3, prefix="Test") as pb:
            for i in range(1, 4):
                pb.update(i)
        return "ProgressBar: 1 проверка"

    # ---------- 20. Интеграция CascAnalys ----------
    def test_casc_integration():
        test_path = "test_casc_integration.json"
        if os.path.exists(test_path):
            os.remove(test_path)

        app = CascAnalys(config_path=test_path)
        assert hasattr(app, "analyze_target")
        assert hasattr(app, "smart_analyze")
        assert hasattr(app, "run")
        assert hasattr(app, "generate_report")
        assert hasattr(app, "generate_json_report")
        assert hasattr(app, "generate_csv_report")
        assert hasattr(app, "generate_markdown_report")
        assert len(app.ALL_MODULES) == 7

        if os.path.exists(test_path):
            os.remove(test_path)
        return "CascAnalys: 8 проверок"

    # ---------- Список всех тестов ----------
    tests = [
        ("Utils", test_utils),
        ("Target", test_target),
        ("Config", test_config),
        ("Logger", test_logger),
        ("PortScanner", test_portscanner),
        ("HTTPAnalyzer", test_http_analyzer),
        ("DNSAnalyzer", test_dns_analyzer),
        ("OSINTModule", test_osint),
        ("CVEScanner", test_cve),
        ("SQLiScanner", test_sqli),
        ("XSSScanner", test_xss),
        ("LfiScanner", test_lfi),
        ("StressTester", test_stress),
        ("HTMLReport", test_html_report),
        ("JSONReport", test_json_report),
        ("CSVReport", test_csv_report),
        ("MarkdownReport", test_md_report),
        ("AppState", test_app_state),
        ("ProgressBar", test_progress_bar),
        ("CascAnalys", test_casc_integration),
    ]

    # ---------- Запуск ----------
    for name, func in tests:
        try:
            result = func()
            passed += 1
            print(f"  {Colors.green('✓')} {name:20} {Colors.dim(result)}")
        except AssertionError as e:
            failed += 1
            print(f"  {Colors.red('✗')} {name:20} {Colors.red('AssertionError')}")
            print(f"      {Colors.dim(str(e)[:100])}")
        except Exception as e:
            failed += 1
            print(f"  {Colors.red('✗')} {name:20} {Colors.red(type(e).__name__)}")
            print(f"      {Colors.dim(str(e)[:100])}")

    # ---------- Итог ----------
    print()
    print(Colors.purple("  " + "─" * 66))
    total = passed + failed
    if failed == 0:
        print(Colors.green(f"  ✓ ВСЕ ТЕСТЫ ПРОЙДЕНЫ: {passed}/{total}"))
    else:
        print(Colors.red(f"  ✗ ПРОВАЛЕНО: {failed}/{total}"))
        print(Colors.green(f"  ✓ Пройдено:  {passed}/{total}"))
    print(Colors.purple("  " + "─" * 66))
    print()

    return failed == 0


# ==============================================================================
# ОТКРЫТИЕ ОТЧЁТА В БРАУЗЕРЕ
# ==============================================================================
def open_in_browser(path: str) -> bool:
    """Открывает файл в браузере по умолчанию"""
    try:
        import webbrowser
        webbrowser.open(f"file://{Path(path).absolute()}")
        return True
    except Exception:
        return False


# ==============================================================================
# ОБРАБОТКА ОТДЕЛЬНЫХ КОМАНД CLI
# ==============================================================================
def cmd_list_repos(app: "CascAnalys"):
    """Команда --list-repos"""
    print()
    app.repo_manager.print_list(group_by_category=True)
    print()
    stats = app.repo_manager.get_status_summary()
    print(f"  Всего: {stats['total']}  |  "
          f"Клонировано: {Colors.green(str(stats['cloned']))}  |  "
          f"Обновлено: {Colors.green(str(stats['updated']))}  |  "
          f"Ошибок: {Colors.red(str(stats['errors']))}")
    print(f"  Общий размер: {Colors.cyan(Utils.format_bytes(app.repo_manager.get_total_size()))}")
    print()


def cmd_clean_repos(app: "CascAnalys", yes: bool = False):
    """Команда --clean-repos"""
    if not yes:
        answer = input(Colors.yellow("  Удалить все репозитории? (y/N): ")).strip().lower()
        if answer != 'y':
            print(Colors.dim("  Отменено"))
            return
    if app.repo_manager.clean():
        print(Colors.green("  ✓ Все репозитории удалены"))
    else:
        print(Colors.red("  ✗ Не удалось удалить"))


def cmd_list_targets(app: "CascAnalys"):
    """Команда --list-targets"""
    targets = app.config.list_targets()
    if not targets:
        print(Colors.yellow("\n  Нет сохранённых целей"))
        return
    print(Colors.bold_purple(f"\n  СОХРАНЁННЫЕ ЦЕЛИ ({len(targets)})"))
    print(Colors.purple("  " + "─" * 50))
    for i, t in enumerate(targets, 1):
        print(f"    {Colors.cyan(str(i).rjust(2) + '.')} {t}")
    print()


def cmd_add_target(app: "CascAnalys", target: str):
    """Команда --add-target"""
    if app.config.add_target(target):
        print(Colors.green(f"  ✓ Добавлено: {target}"))
    else:
        print(Colors.yellow(f"  Уже есть: {target}"))


def cmd_remove_target(app: "CascAnalys", target: str):
    """Команда --remove-target"""
    if app.config.remove_target(target):
        print(Colors.green(f"  ✓ Удалено: {target}"))
    else:
        print(Colors.yellow(f"  Не найдено: {target}"))


def cmd_init_repos(app: "CascAnalys", args):
    """Команда --init-repos / --update-repos"""
    print(Colors.bold_purple("\n  ИНИЦИАЛИЗАЦИЯ РЕПОЗИТОРИЕВ"))
    print(Colors.purple("  " + "─" * 50))
    print(f"  Тяжёлые репо:  {'включены' if args.all else 'пропущены'}")
    print(f"  Параллельно:   {'да' if args.parallel else 'нет'}")
    print(f"  Зависимости:   {'да' if args.install_deps else 'нет'}")
    print()

    if not check_git():
        print(Colors.red("  ✗ git не найден в системе"))
        return

    app.init_repos(
        skip_heavy=not args.all,
        parallel=args.parallel,
        install_deps=args.install_deps,
    )


def cmd_deps():
    """Команда --deps"""
    print(Colors.bold_purple("\n  СТАТУС ЗАВИСИМОСТЕЙ"))
    print(Colors.purple("  " + "─" * 50))
    print_dependencies_status()


def cmd_system_info():
    """Команда --system-info"""
    print(Colors.bold_purple("\n  СИСТЕМНАЯ ИНФОРМАЦИЯ"))
    print(Colors.purple("  " + "─" * 50))
    info = Utils.get_system_info()
    print(f"  OS:      {info['os']} {info['os_release']}")
    print(f"  Python:  {info['python']}")
    print(f"  Arch:    {info['arch']}")
    print(f"  Host:    {info['hostname']}")
    print(f"  CWD:     {os.getcwd()}")
    print()


def cmd_check_git():
    """Команда --check-git"""
    if check_git():
        git_path = Utils.which("git")
        print(Colors.green(f"\n  ✓ git найден: {git_path}"))
        try:
            result = subprocess.run(
                ["git", "--version"],
                capture_output=True, text=True, timeout=5
            )
            print(f"  Версия: {result.stdout.strip()}")
        except Exception:
            pass
    else:
        print(Colors.red("\n  ✗ git не найден в PATH"))
    print()


# ==============================================================================
# ВЫВОД РЕЗУЛЬТАТОВ В КОНСОЛЬ
# ==============================================================================
def print_results(app: "CascAnalys"):
    """Красиво выводит результаты анализа в консоль"""
    if not app.results:
        return

    stats = app.get_stats()

    print()
    print(Colors.purple("╔" + "═" * 68 + "╗"))
    print(Colors.purple("║") + Colors.bold_purple(" " * 23 + "ИТОГИ АНАЛИЗА" + " " * 23) + Colors.purple("║"))
    print(Colors.purple("╚" + "═" * 68 + "╝"))

    # Сводка
    print()
    print(f"  {Colors.light_purple('Целей:')}        {stats['targets']}")
    print(f"  {Colors.light_purple('Портов:')}       {stats['total_ports']}")
    print(f"  {Colors.light_purple('Поддоменов:')}   {stats['total_subdomains']}")
    print(f"  {Colors.light_purple('Уязвимостей:')}  {stats['total_vulns']}")
    print()

    # По severity
    sev = stats['vulns_by_severity']
    if stats['total_vulns'] > 0:
        print(Colors.bold("  Уязвимости по severity:"))
        if sev['critical']:
            print(f"    {Colors.red('● Critical:')} {sev['critical']}")
        if sev['high']:
            print(f"    {Colors.red('● High:')}     {sev['high']}")
        if sev['medium']:
            print(f"    {Colors.yellow('● Medium:')}   {sev['medium']}")
        if sev['low']:
            print(f"    {Colors.green('● Low:')}      {sev['low']}")
        if sev['info']:
            print(f"    {Colors.cyan('● Info:')}     {sev['info']}")
        print()

    # По каждой цели
    for name, data in app.results.items():
        hostname = data.get("hostname", name)
        ip = data.get("ip") or "N/A"
        status = data.get("status", "unknown")
        duration = data.get("duration", 0)

        print(Colors.purple("  " + "─" * 66))
        print(f"  {Colors.bold_cyan('▶ ' + hostname)}  {Colors.dim(ip)}  {Colors.dim(f'[{status}, {Utils.format_duration(duration)}]')}")

        mods = data.get("modules", {})

        # Порты
        if "ports" in mods:
            ports_data = mods["ports"]
            ports = ports_data.get("ports", {})
            if ports:
                port_list = ", ".join(str(p) for p in sorted(ports.keys())[:15])
                extra = f" (+{len(ports) - 15})" if len(ports) > 15 else ""
                print(f"    {Colors.green('● Порты:')} {port_list}{extra}")
            else:
                print(f"    {Colors.dim('● Портов: нет')}")

        # HTTP
        if "http" in mods:
            http = mods["http"]
            server = http.get("server") or "N/A"
            waf = http.get("waf") or "нет"
            status_code = http.get("status_code") or "N/A"
            print(f"    {Colors.green('● HTTP:')}   {status_code}  {server}")
            if waf != "нет":
                print(f"    {Colors.yellow('● WAF:')}    {waf}")

        # SSL
        if "http" in mods and mods["http"].get("ssl"):
            ssl_info = mods["http"]["ssl"]
            days = ssl_info.get("days_left")
            if days is not None:
                color = Colors.green if days > 30 else Colors.yellow if days > 7 else Colors.red
                print(f"    {Colors.green('● SSL:')}    {color(str(days) + ' дн.')}")

        # DNS
        if "dns" in mods:
            records = mods["dns"].get("records", {})
            if records:
                rtypes = ", ".join(records.keys())
                print(f"    {Colors.green('● DNS:')}    {rtypes}")

        # OSINT
        if "osint" in mods:
            whois = mods["osint"].get("whois", {})
            registrar = whois.get("registrar")
            if registrar:
                print(f"    {Colors.green('● WHOIS:')}  {Utils.truncate(registrar, 50)}")

        # Поддомены
        if "subdomains" in mods:
            subs = mods["subdomains"]
            total = subs.get("total", 0)
            if total:
                sources = ", ".join(subs.get("sources", []))
                print(f"    {Colors.green('● Поддомены:')} {total}  ({Colors.dim(sources)})")

        # Уязвимости
        if "vuln" in mods:
            vuln = mods["vuln"]
            total = sum(len(v) for v in vuln.values() if isinstance(v, list))
            if total:
                print(f"    {Colors.red('● Уязвимости:')} {total}")
                for vtype, lst in vuln.items():
                    if not isinstance(lst, list) or not lst:
                        continue
                    for v in lst[:3]:
                        sev = (v.get("severity") or "info").lower()
                        sev_color = {
                            "critical": Colors.red,
                            "high": Colors.red,
                            "medium": Colors.yellow,
                            "low": Colors.green,
                            "info": Colors.cyan,
                        }.get(sev, Colors.dim)
                        name = v.get("name", "Vuln")
                        print(f"      {sev_color(f'[{sev.upper()}]')} {Utils.truncate(name, 60)}")
                    if len(lst) > 3:
                        print(f"      {Colors.dim(f'... и ещё {len(lst) - 3}')}")

        # Стресс
        if "stress" in mods:
            stress = mods["stress"]
            sl = stress.get("slowloris", {})
            hf = stress.get("http_flood", {})
            if sl or hf:
                parts = []
                if sl:
                    parts.append(f"Slowloris: {sl.get('connections', 0)}")
                if hf:
                    parts.append(f"HTTP-флуд: {hf.get('requests', 0)}")
                print(f"    {Colors.green('● Стресс:')}  {', '.join(parts)}")

    print(Colors.purple("  " + "─" * 66))
    print()


# ==============================================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ==============================================================================
def main():
    """Главная точка входа CASC-ANAYS"""
    parser = build_cli()
    args = parser.parse_args()

    # ---------- Тихий режим ----------
    if not args.quiet:
        print_banner()

    # ---------- Без аргументов — справка ----------
    if len(sys.argv) == 1:
        print_help_extended()
        return 0

    # ---------- Цвета ----------
    if args.no_color:
        global HAS_COLORAMA
        HAS_COLORAMA = False
        for attr in dir(Colors):
            if not attr.startswith('_') and attr.isupper():
                setattr(Colors, attr, '')

    # ---------- Расширенная справка ----------
    if args.print_help:
        print_help_extended()
        return 0

    # ---------- Диагностика (без инициализации приложения) ----------
    if args.deps:
        cmd_deps()
        return 0

    if args.system_info:
        cmd_system_info()
        return 0

    if args.check_git:
        cmd_check_git()
        return 0

    if args.self_test:
        success = run_self_tests()
        return 0 if success else 1

    # ---------- Создаём config.json, если нет ----------
    if not os.path.exists(args.config):
        created = create_default_config(args.config)
        if created and not args.quiet:
            print(Colors.green(f"  ✓ Создан конфиг: {args.config}"))

    # ---------- Инициализация приложения ----------
    try:
        app = CascAnalys(config_path=args.config)
    except Exception as e:
        print(Colors.red(f"\n  ✗ Ошибка инициализации: {e}"))
        if args.debug:
            traceback.print_exc()
        return 1

    # ---------- Применяем аргументы к конфигу ----------
    if args.log_level:
        app.set_log_level(args.log_level)
    if args.log_file:
        app.config.set('settings.log_file', args.log_file)
        app.logger.log_file = args.log_file
    if args.threads:
        app.config.set('settings.threads', args.threads)
    if args.timeout:
        app.config.set('settings.timeout', args.timeout)
    if args.output_dir:
        app.config.set('settings.output_dir', args.output_dir)
    if args.proxy:
        app.config.set('settings.use_proxy', True)
        app.config.set('settings.proxy_url', args.proxy)
    if args.user_agent:
        app.config.set('settings.user_agent', args.user_agent)
    if args.subdomain_brute:
        app.config.set('settings.subdomain_bruteforce', True)

    if args.debug:
        app.logger.set_level('DEBUG')
        app.logger.debug("Отладочный режим включён")

    # ---------- Обработка команд ----------
    try:
        # Список репозиториев
        if args.list_repos:
            cmd_list_repos(app)
            return 0

        # Очистка репозиториев
        if args.clean_repos:
            cmd_clean_repos(app, yes=args.yes)
            return 0

        # Список целей
        if args.list_targets:
            cmd_list_targets(app)
            return 0

        # Добавить цель
        if args.add_target:
            cmd_add_target(app, args.add_target)
            return 0

        # Удалить цель
        if args.remove_target:
            cmd_remove_target(app, args.remove_target)
            return 0

        # Инициализация репозиториев
        if args.init_repos or args.update_repos:
            cmd_init_repos(app, args)
            return 0

        # ---------- Интерактивный режим ----------
        if args.interactive:
            # Загружаем цели из конфига
            if not app.targets:
                for t in app.config.list_targets():
                    app.add_target(t)

            mode = InteractiveMode(app)
            mode.run()
            return 0

        # ---------- Анализ ----------
        if args.target or args.targets_file:
            if not (args.full or args.smart):
                print(Colors.yellow(
                    "\n  Укажите режим анализа: --full или --smart\n"
                    "  Пример: casc-anays -t example.com --full"
                ))
                return 1

            # Запуск
            results = app.run(args)

            # Вывод результатов
            if results and not args.quiet:
                print_results(app)

            # Открыть отчёт
            if args.open and not args.no_report:
                out_dir = app.config.get_output_dir()
                htmls = sorted(out_dir.glob("casc_anays_*.html"), key=os.path.getmtime)
                if htmls:
                    if open_in_browser(str(htmls[-1])):
                        print(Colors.green(f"  ✓ Отчёт открыт в браузере"))
                    else:
                        print(Colors.yellow(f"  Не удалось открыть браузер"))

            return 0

        # ---------- Нет команды — справка ----------
        print_help_extended()
        return 0

    except KeyboardInterrupt:
        print(Colors.yellow("\n\n  ⚠ Операция прервана пользователем"))
        return 130
    except Exception as e:
        print(Colors.red(f"\n  ✗ Ошибка: {e}"))
        if args.debug:
            traceback.print_exc()
        return 1


# ==============================================================================
# ТОЧКА ВХОДА
# ==============================================================================
if __name__ == "__main__":
    # Устанавливаем обработчики сигналов
    try:
        install_signal_handlers()
    except Exception:
        pass

    # Запуск
    try:
        exit_code = main()
        sys.exit(exit_code or 0)
    except KeyboardInterrupt:
        print(Colors.yellow("\n\n  ⚠ Прервано"))
        sys.exit(130)
    except Exception as e:
        print(Colors.red(f"\n  ✗ Критическая ошибка: {e}"))
        if os.environ.get("CASC_DEBUG") or "--debug" in sys.argv:
            traceback.print_exc()
        sys.exit(1)


# ==============================================================================
# ==============================================================================
# ПРИЛОЖЕНИЕ A: README.md (сохранить как README.md в корне проекта)
# ==============================================================================
# ==============================================================================
#
# # CASC-ANAYS v4.0
#
# > Глобальный аналитический комплекс для анализа веб-сайтов и IP
#
# [![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
# [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
#
# ## Возможности
#
# - 🔌 **Сканирование портов** — TCP + UDP, ~200 популярных портов, баннеры сервисов
# - 🌐 **HTTP-анализ** — заголовки, SSL/TLS, WAF, технологии, security headers
# - 🌍 **DNS-анализ** — A/AAAA/MX/NS/TXT/CNAME/SOA/CAA/SRV, DMARC, PTR
# - 🕵 **OSINT** — WHOIS, разведка
# - 🌐 **Поддомены** — crt.sh + Sublist3r + amass + subfinder + DNS-брутфорс
# - ⚠️ **Уязвимости** — CVE (NVD API), Nikto, SQLi, XSS, LFI
# - 💥 **Стресс-тесты** — Slowloris, HTTP-флуд, GoldenEye
# - 📦 **40 GitHub-репозиториев** — авто-клонирование, обновление, зависимости
# - 📄 **4 формата отчётов** — HTML (фиолетовая тема), JSON, CSV, Markdown
# - 🖥 **Интерактивный режим** — меню на 12 пунктов
#
# ## Установка
#
# ```bash
# # 1. Клонируем
# git clone https://github.com/seismon/casc-anays.git
# cd casc-anays
#
# # 2. Устанавливаем зависимости Python
# pip install -r requirements.txt
#
# # 3. (опционально) Инициализируем репозитории инструментов
# python casc_anays.py --init-repos
#
# # 4. Запускаем
# python casc_anays.py -i
# ```
#
# ## Быстрый старт
#
# ```bash
# # Полный анализ одного домена
# python casc_anays.py -t example.com --full
#
# # Умный анализ (авто-подбор модулей)
# python casc_anays.py -t example.com --smart
#
# # Интерактивный режим
# python casc_anays.py -i
#
# # Список целей из файла
# python casc_anays.py --targets-file targets.txt --smart
#
# # Только порты и HTTP
# python casc_anays.py -t example.com -m ports,http
# ```
#
# ## Документация
#
# Полная справка: `python casc_anays.py --print-help`
#
# ## Лицензия
#
# MIT © seismon
#
# ==============================================================================
# ПРИЛОЖЕНИЕ B: requirements.txt (сохранить как requirements.txt)
# ==============================================================================
# colorama>=0.4.6
# requests>=2.31.0
# beautifulsoup4>=4.12.0
# dnspython>=2.4.0
# python-whois>=0.9.4
# aiohttp>=3.9.0
# ==============================================================================
# ПРИЛОЖЕНИЕ C: Dockerfile (сохранить как Dockerfile)
# ==============================================================================
# FROM python:3.11-slim
#
# LABEL maintainer="seismon"
# LABEL description="CASC-ANAYS v4.0 — Global Analytical Complex"
#
# WORKDIR /app
#
# # Системные зависимости
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     git \
#     perl \
#     curl \
#     ca-certificates \
#     && rm -rf /var/lib/apt/lists/*
#
# # Python-зависимости
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt
#
# # Код
# COPY . .
#
# # Создаём директории
# RUN mkdir -p reports repos
#
# # Точка входа
# ENTRYPOINT ["python", "casc_anays.py"]
# CMD ["--print-help"]
# ==============================================================================
# ПРИЛОЖЕНИЕ D: docker-compose.yml (сохранить как docker-compose.yml)
# ==============================================================================
# version: '3.8'
#
# services:
#   casc-anays:
#     build: .
#     image: casc-anays:4.0
#     container_name: casc-anays
#     volumes:
#       - ./reports:/app/reports
#       - ./repos:/app/repos
#       - ./config.json:/app/config.json
#     stdin_open: true
#     tty: true
#     command: ["-i"]
# ==============================================================================
# ПРИЛОЖЕНИЕ E: build.sh (сохранить как build.sh, chmod +x)
# ==============================================================================
# #!/bin/bash
# # Собирает все части в один монолит casc_anays.py
#
# set -e
#
# echo "→ Сборка CASC-ANAYS..."
#
# cat part1_core.py \
#     part2_repos.py \
#     part3_analysis.py \
#     part4_vuln.py \
#     part5_integration.py \
#     part6_reports.py \
#     part7_cli.py > casc_anays.py
#
# LINES=$(wc -l < casc_anays.py)
# echo "✓ Готово: casc_anays.py ($LINES строк)"
# echo ""
# echo "Запуск: python casc_anays.py -i"
# ==============================================================================
# ПРИЛОЖЕНИЕ F: .gitignore (сохранить как .gitignore)
# ==============================================================================
# __pycache__/
# *.py[cod]
# *$py.class
# *.so
# .Python
# build/
# develop-eggs/
# dist/
# downloads/
# eggs/
# .eggs/
# lib/
# lib64/
# parts/
# sdist/
# var/
# wheels/
# *.egg-info/
# .installed.cfg
# *.egg
#
# # Virtual env
# venv/
# ENV/
# env/
#
# # IDE
# .vscode/
# .idea/
# *.swp
# *.swo
#
# # Project-specific
# config.json
# reports/
# repos/
# *.log
# proxies.txt
# ==============================================================================
# КОНЕЦ PART 7 — ПРОЕКТ ЗАВЕРШЁН
# ==============================================================================