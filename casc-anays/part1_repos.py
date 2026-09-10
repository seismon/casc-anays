#!/usr/bin/env python3
# ==============================================================================
# CASC-ANAYS v4.0 — ГЛОБАЛЬНЫЙ АНАЛИТИЧЕСКИЙ КОМПЛЕКС
# АВТОР: seismon
# ЛИЦЕНЗИЯ: MIT
# ==============================================================================
#
#  ██████╗  █████╗ ███████╗ ██████╗     █████╗ ███╗   ██╗ █████╗ ██╗   ██╗███████╗
# ██╔════╝ ██╔══██╗██╔════╝██╔════╝    ██╔══██╗████╗  ██║██╔══██╗╚██╗ ██╔╝██╔════╝
# ██║      ███████║███████╗██║         ███████║██╔██╗ ██║███████║ ╚████╔╝ ███████╗
# ██║      ██╔══██║╚════██║██║         ██╔══██║██║╚██╗██║██╔══██║  ╚██╔╝  ╚════██║
# ╚██████╗ ██║  ██║███████║╚██████╗    ██║  ██║██║ ╚████║██║  ██║   ██║   ███████║
#  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
#
#  CASC-ANAYS — ГЛОБАЛЬНЫЙ АНАЛИТИЧЕСКИЙ КОМПЛЕКС
#  АНАЛИЗ ВЕБ-САЙТОВ | OSINT | ПОДДОМЕНЫ | УЯЗВИМОСТИ | СТРЕСС-ТЕСТЫ
# ==============================================================================

import os
import sys
import json
import time
import socket
import shutil
import hashlib
import platform
import subprocess
import ipaddress
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from urllib.parse import urlparse, urljoin, quote, unquote

# ---------- МЯГКИЕ ИМПОРТЫ (не падаем, если нет пакета) ----------
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
        LIGHTMAGENTA_EX = ''
    class Style:
        BRIGHT = DIM = NORMAL = ''
    class Back:
        pass

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

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois as whois_lib
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    HAS_FUTURES = True
except ImportError:
    HAS_FUTURES = False


# ==============================================================================
# МЕТАДАННЫЕ ПРОЕКТА
# ==============================================================================
VERSION = "4.0.0"
PROJECT_NAME = "CASC-ANAYS"
AUTHOR = "seismon"
LICENSE = "MIT"
GITHUB_URL = "https://github.com/seismon/casc-anays"
DESCRIPTION = "Глобальный аналитический комплекс для анализа веб-сайтов и IP"

# ==============================================================================
# ЦВЕТОВАЯ СХЕМА (фиолетовая тема)
# ==============================================================================
class Colors:
    """
    Фиолетовая цветовая схема CASC-ANAYS
    Все методы возвращают строку с ANSI-кодами
    """

    PURPLE = Fore.MAGENTA
    LIGHT_PURPLE = Fore.LIGHTMAGENTA_EX
    DARK_PURPLE = Fore.MAGENTA
    CYAN = Fore.CYAN
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    BLUE = Fore.BLUE
    WHITE = Fore.WHITE
    RESET = Fore.RESET
    BOLD = Style.BRIGHT
    DIM = Style.DIM

    # ---------- Статические методы для удобного окрашивания ----------
    @staticmethod
    def purple(text: str) -> str:
        return f"{Colors.PURPLE}{text}{Colors.RESET}"

    @staticmethod
    def light_purple(text: str) -> str:
        return f"{Colors.LIGHT_PURPLE}{text}{Colors.RESET}"

    @staticmethod
    def dark_purple(text: str) -> str:
        return f"{Colors.DARK_PURPLE}{text}{Colors.RESET}"

    @staticmethod
    def cyan(text: str) -> str:
        return f"{Colors.CYAN}{text}{Colors.RESET}"

    @staticmethod
    def green(text: str) -> str:
        return f"{Colors.GREEN}{text}{Colors.RESET}"

    @staticmethod
    def yellow(text: str) -> str:
        return f"{Colors.YELLOW}{text}{Colors.RESET}"

    @staticmethod
    def red(text: str) -> str:
        return f"{Colors.RED}{text}{Colors.RESET}"

    @staticmethod
    def blue(text: str) -> str:
        return f"{Colors.BLUE}{text}{Colors.RESET}"

    @staticmethod
    def bold(text: str) -> str:
        return f"{Colors.BOLD}{text}{Colors.RESET}"

    @staticmethod
    def dim(text: str) -> str:
        return f"{Colors.DIM}{text}{Colors.RESET}"

    # ---------- Составные стили ----------
    @staticmethod
    def bold_purple(text: str) -> str:
        return f"{Colors.BOLD}{Colors.PURPLE}{text}{Colors.RESET}"

    @staticmethod
    def bold_cyan(text: str) -> str:
        return f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.RESET}"

    @staticmethod
    def bold_green(text: str) -> str:
        return f"{Colors.BOLD}{Colors.GREEN}{text}{Colors.RESET}"

    @staticmethod
    def bold_red(text: str) -> str:
        return f"{Colors.BOLD}{Colors.RED}{text}{Colors.RESET}"

    @staticmethod
    def bold_yellow(text: str) -> str:
        return f"{Colors.BOLD}{Colors.YELLOW}{text}{Colors.RESET}"

    # ---------- Хелперы для логов ----------
    @staticmethod
    def status_ok(text: str) -> str:
        return f"{Colors.GREEN}✓{Colors.RESET} {text}"

    @staticmethod
    def status_fail(text: str) -> str:
        return f"{Colors.RED}✗{Colors.RESET} {text}"

    @staticmethod
    def status_warn(text: str) -> str:
        return f"{Colors.YELLOW}⚠{Colors.RESET} {text}"

    @staticmethod
    def arrow(text: str) -> str:
        return f"{Colors.LIGHT_PURPLE}→{Colors.RESET} {text}"

    @staticmethod
    def bullet(text: str) -> str:
        return f"{Colors.CYAN}•{Colors.RESET} {text}"


# ==============================================================================
# БАННЕР
# ==============================================================================
def print_banner():
    """Выводит фиолетовый баннер CASC-ANAYS"""
    banner = f"""
{Colors.purple('  ██████╗  █████╗ ███████╗ ██████╗     █████╗ ███╗   ██╗ █████╗ ██╗   ██╗███████╗')}
{Colors.purple(' ██╔════╝ ██╔══██╗██╔════╝██╔════╝    ██╔══██╗████╗  ██║██╔══██╗╚██╗ ██╔╝██╔════╝')}
{Colors.purple(' ██║      ███████║███████╗██║         ███████║██╔██╗ ██║███████║ ╚████╔╝ ███████╗')}
{Colors.purple(' ██║      ██╔══██║╚════██║██║         ██╔══██║██║╚██╗██║██╔══██║  ╚██╔╝  ╚════██║')}
{Colors.purple(' ╚██████╗ ██║  ██║███████║╚██████╗    ██║  ██║██║ ╚████║██║  ██║   ██║   ███████║')}
{Colors.purple('  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚══════╝')}
                                                                             
{Colors.light_purple(f'  CASC-ANAYS v{VERSION} — ГЛОБАЛЬНЫЙ АНАЛИТИЧЕСКИЙ КОМПЛЕКС')}
{Colors.cyan('  АНАЛИЗ ВЕБ-САЙТОВ | OSINT | ПОДДОМЕНЫ | УЯЗВИМОСТИ | СТРЕСС-ТЕСТЫ')}
{Colors.yellow(f'  Автор: {AUTHOR} | GitHub: {GITHUB_URL}')}
{Colors.dark_purple('  ' + '=' * 60)}
"""
    print(banner)


def print_help_extended():
    """Расширенная справка с примерами (используется в CLI)"""
    help_text = f"""
{Colors.purple('╔══════════════════════════════════════════════════════════════════╗')}
{Colors.purple('║')}  {Colors.bold(Colors.light_purple('CASC-ANAYS'))} — Глобальный аналитический комплекс            {Colors.purple('║')}
{Colors.purple('║')}  {Colors.cyan('Анализ веб-сайтов | OSINT | Поддомены | Уязвимости | Стресс')}    {Colors.purple('║')}
{Colors.purple('╚══════════════════════════════════════════════════════════════════╝')}

{Colors.bold('ПРИМЕРЫ:')}

  {Colors.cyan('# Полный анализ')}
  casc-anays -t example.com --full

  {Colors.cyan('# Умный анализ (авто-подбор модулей)')}
  casc-anays -t example.com --smart

  {Colors.cyan('# Интерактивный режим')}
  casc-anays -i

  {Colors.cyan('# Анализ без стресс-тестов')}
  casc-anays -t example.com --full --no-stress

  {Colors.cyan('# Только порты и HTTP')}
  casc-anays -t example.com -m ports,http

  {Colors.cyan('# Список целей из файла')}
  casc-anays --targets-file targets.txt --full -o report.html

  {Colors.cyan('# Инициализация репозиториев')}
  casc-anays --init-repos

{Colors.bold('МОДУЛИ:')}
  {Colors.light_purple('ports')}       — Сканирование портов
  {Colors.light_purple('http')}        — HTTP-анализ (заголовки, SSL, технологии)
  {Colors.light_purple('dns')}         — DNS-анализ
  {Colors.light_purple('osint')}       — WHOIS, разведка
  {Colors.light_purple('subdomains')}  — Поиск поддоменов
  {Colors.light_purple('vuln')}        — Уязвимости (CVE, SQLi, XSS, LFI)
  {Colors.light_purple('stress')}      — Стресс-тесты (Slowloris, HTTP-флуд)

{Colors.bold('АВТОР:')} {AUTHOR}
{Colors.bold('GITHUB:')} {GITHUB_URL}
"""
    print(help_text)


# ==============================================================================
# ЛОГГЕР
# ==============================================================================
class Logger:
    """
    Система логирования CASC-ANAYS
    Пишет в консоль (с цветами) и в файл (если указан)
    """

    LOG_LEVELS = {
        'DEBUG': 0,
        'INFO': 1,
        'WARNING': 2,
        'ERROR': 3,
        'CRITICAL': 4
    }

    def __init__(self, log_file: Optional[str] = None, level: str = 'INFO'):
        self.level = self.LOG_LEVELS.get(level.upper(), 1)
        self.log_file = log_file
        self._lock = threading.Lock()

        if log_file:
            try:
                log_dir = Path(log_file).parent
                log_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                self.log_file = None

    def _log(self, level: str, message: str, color_func=None):
        if self.LOG_LEVELS.get(level, 1) < self.level:
            return

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        formatted_msg = f"[{timestamp}] [{level}] {message}"

        # Вывод в консоль
        try:
            if color_func:
                print(color_func(formatted_msg))
            else:
                print(formatted_msg)
        except Exception:
            print(formatted_msg)

        # Вывод в файл
        if self.log_file:
            with self._lock:
                try:
                    with open(self.log_file, 'a', encoding='utf-8') as f:
                        f.write(formatted_msg + '\n')
                except Exception:
                    pass

    def debug(self, message: str):
        self._log('DEBUG', message, Colors.dim)

    def info(self, message: str):
        self._log('INFO', message, Colors.cyan)

    def warning(self, message: str):
        self._log('WARNING', message, Colors.yellow)

    def error(self, message: str):
        self._log('ERROR', message, Colors.red)

    def critical(self, message: str):
        self._log('CRITICAL', message, Colors.bold_red)

    def success(self, message: str):
        """Не уровень, но удобный метод"""
        self._log('INFO', message, Colors.green)

    def set_level(self, level: str):
        """Меняет уровень логирования на лету"""
        self.level = self.LOG_LEVELS.get(level.upper(), 1)

    def banner(self, message: str):
        """Красивый заголовок секции"""
        self._log('INFO', '=' * 60)
        self._log('INFO', message)
        self._log('INFO', '=' * 60)


# ==============================================================================
# УТИЛИТЫ
# ==============================================================================
class Utils:
    """Утилиты для модулей анализа"""

    @staticmethod
    def is_url(target: str) -> bool:
        """Проверяет, является ли строка URL"""
        try:
            result = urlparse(target)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def normalize_target(target: str) -> str:
        """Приводит цель к нормальному виду (без протокола, пути, порта)"""
        if not target:
            return ''
        target = target.strip().lower()
        if '://' in target:
            target = target.split('://', 1)[1]
        if '/' in target:
            target = target.split('/', 1)[0]
        # Отрезаем порт (кроме IPv6)
        if ':' in target and target.count(':') == 1:
            host, _, port = target.partition(':')
            if port.isdigit():
                target = host
        return target

    @staticmethod
    def get_domain_from_url(url: str) -> str:
        """Извлекает домен из URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
        except Exception:
            return url

    @staticmethod
    def format_bytes(size: int) -> str:
        """Форматирует размер в байтах в читаемый вид"""
        if size is None:
            return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

    @staticmethod
    def format_duration(seconds: float) -> str:
        """Форматирует длительность в читаемый вид"""
        if seconds < 1:
            return f"{seconds * 1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.2f}s"
        elif seconds < 3600:
            m = int(seconds // 60)
            s = int(seconds % 60)
            return f"{m}m {s}s"
        else:
            h = int(seconds // 3600)
            m = int((seconds % 3600) // 60)
            return f"{h}h {m}m"

    @staticmethod
    def get_random_ua() -> str:
        """Возвращает случайный User-Agent"""
        import random
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) "
            "Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 "
            "Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
            "Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) "
            "Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        ]
        return random.choice(user_agents)

    @staticmethod
    def safe_int(value: Any, default: int = 0) -> int:
        """Безопасное преобразование в int"""
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def safe_str(value: Any, default: str = "") -> str:
        """Безопасное преобразование в str"""
        if value is None:
            return default
        try:
            return str(value)
        except Exception:
            return default

    @staticmethod
    def truncate(text: str, length: int = 100, suffix: str = "...") -> str:
        """Обрезает строку до length символов"""
        if not text:
            return ""
        text = str(text)
        if len(text) <= length:
            return text
        return text[:length - len(suffix)] + suffix

    @staticmethod
    def hash_string(text: str, algo: str = "md5") -> str:
        """Хеширует строку"""
        try:
            h = hashlib.new(algo)
            h.update(text.encode('utf-8'))
            return h.hexdigest()
        except Exception:
            return ""

    @staticmethod
    def ensure_dir(path: Union[str, Path]) -> Path:
        """Создаёт директорию, если её нет"""
        p = Path(path)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @staticmethod
    def file_exists(path: Union[str, Path]) -> bool:
        """Проверяет существование файла"""
        try:
            return Path(path).exists()
        except Exception:
            return False

    @staticmethod
    def read_file(path: Union[str, Path]) -> Optional[str]:
        """Читает файл, возвращает None при ошибке"""
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None

    @staticmethod
    def write_file(path: Union[str, Path], content: str) -> bool:
        """Пишет файл, возвращает True/False"""
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception:
            return False

    @staticmethod
    def which(command: str) -> Optional[str]:
        """Аналог `which` — ищет исполняемый файл в PATH"""
        return shutil.which(command)

    @staticmethod
    def has_command(command: str) -> bool:
        """Проверяет, доступна ли команда в системе"""
        return shutil.which(command) is not None

    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Возвращает информацию о системе"""
        return {
            "os": platform.system(),
            "os_release": platform.release(),
            "python": platform.python_version(),
            "arch": platform.machine(),
            "hostname": socket.gethostname(),
        }

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Проверяет, является ли строка IP-адресом"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Простая проверка домена"""
        if not domain or len(domain) > 253:
            return False
        if '.' not in domain:
            return False
        # Разрешённые символы
        import re
        pattern = re.compile(
            r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
            r'(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$'
        )
        return bool(pattern.match(domain))

    @staticmethod
    def parse_url(url: str) -> Dict[str, Any]:
        """Разбирает URL на компоненты"""
        try:
            p = urlparse(url)
            return {
                "scheme": p.scheme,
                "hostname": p.hostname,
                "port": p.port,
                "path": p.path,
                "query": p.query,
                "fragment": p.fragment,
            }
        except Exception:
            return {}

    @staticmethod
    def join_url(base: str, path: str) -> str:
        """Безопасно склеивает URL"""
        try:
            return urljoin(base, path)
        except Exception:
            return base + path

    @staticmethod
    def url_encode(text: str) -> str:
        return quote(text, safe='')

    @staticmethod
    def url_decode(text: str) -> str:
        return unquote(text)


# ==============================================================================
# ЦЕЛЬ
# ==============================================================================
class Target:
    """
    Представляет цель для анализа (домен или IP)
    Поддерживает IPv4, IPv6, домены, порты, протоколы
    """

    def __init__(self, target: str):
        self.original = target.strip()
        self.hostname: str = self.original
        self.ip: Optional[str] = None
        self.port: Optional[int] = None
        self.scheme: Optional[str] = None
        self.is_ip: bool = False
        self.is_ipv6: bool = False
        self.resolved: bool = False
        self._parse_target()

    # ---------- Парсинг ----------
    def _parse_target(self):
        """Разбирает цель на компоненты"""
        raw = self.original

        # Протокол
        if '://' in raw:
            self.scheme, raw = raw.split('://', 1)

        # Путь / query / fragment
        for sep in ('/', '?', '#'):
            if sep in raw:
                raw = raw.split(sep, 1)[0]

        # IPv6 в скобках [::1]:8080
        if raw.startswith('['):
            end = raw.find(']')
            if end != -1:
                host = raw[1:end]
                rest = raw[end + 1:]
                if rest.startswith(':'):
                    port_str = rest[1:]
                    if port_str.isdigit():
                        self.port = int(port_str)
                raw = host

        # IPv4 или домен с портом
        elif ':' in raw and raw.count(':') == 1:
            host, _, port_str = raw.partition(':')
            if port_str.isdigit():
                self.port = int(port_str)
                raw = host

        self.hostname = raw

        # Пытаемся понять, IP это или домен
        try:
            ip_obj = ipaddress.ip_address(raw)
            self.is_ip = True
            self.is_ipv6 = ip_obj.version == 6
            self.ip = str(ip_obj)
            self.resolved = True
        except ValueError:
            self.is_ip = False
            self._resolve()

    def _resolve(self):
        """Пытается разрешить домен в IP"""
        if not self.hostname:
            return
        try:
            # Для IPv6 тоже работает
            infos = socket.getaddrinfo(self.hostname, None)
            if infos:
                self.ip = infos[0][4][0]
                self.resolved = True
        except (socket.gaierror, UnicodeError, OSError):
            self.ip = None
            self.resolved = False

    # ---------- Проверки ----------
    def is_valid(self) -> bool:
        """Проверяет, валидна ли цель"""
        if not self.hostname:
            return False
        if self.is_ip:
            return True
        return len(self.hostname) > 0

    def is_resolved(self) -> bool:
        """Разрешён ли домен в IP"""
        return self.resolved and self.ip is not None

    # ---------- URL helpers ----------
    def base_url(self, scheme: Optional[str] = None, force_port: bool = False) -> str:
        """
        Возвращает базовый URL цели
        scheme — принудительный протокол ("http" / "https")
        force_port — добавлять порт, даже если стандартный
        """
        s = scheme or self.scheme
        if not s:
            s = "https" if self.port in (443, None) else "http"

        host = self.hostname
        # IPv6 требует скобок
        if self.is_ipv6:
            host = f"[{host}]"

        if self.port and (force_port or self.port not in (80, 443)):
            return f"{s}://{host}:{self.port}"
        return f"{s}://{host}"

    def http_url(self) -> str:
        return self.base_url("http")

    def https_url(self) -> str:
        return self.base_url("https")

    # ---------- Магические методы ----------
    def __str__(self) -> str:
        if self.ip and self.hostname != self.ip:
            return f"{self.hostname} ({self.ip})"
        return self.hostname or self.original

    def __repr__(self) -> str:
        return f"<Target {self}>"

    def __eq__(self, other) -> bool:
        if isinstance(other, Target):
            return self.hostname == other.hostname
        if isinstance(other, str):
            return self.hostname == other or self.original == other
        return False

    def __hash__(self) -> int:
        return hash(self.hostname)

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация для JSON"""
        return {
            "original": self.original,
            "hostname": self.hostname,
            "ip": self.ip,
            "port": self.port,
            "scheme": self.scheme,
            "is_ip": self.is_ip,
            "is_ipv6": self.is_ipv6,
            "resolved": self.resolved,
        }


# ==============================================================================
# КОНФИГУРАЦИЯ
# ==============================================================================
class Config:
    """
    Управление конфигурацией CASC-ANAYS
    Работает с config.json, поддерживает вложенные ключи через точку
    """

    DEFAULT_CONFIG = {
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
        },
        "repos": {}
    }

    def __init__(self, config_path: str = "config.json"):
        self.config_path = config_path
        self.config = self._load()

    # ---------- Загрузка / сохранение ----------
    def _load(self) -> dict:
        """Загружает конфиг из файла, дополняя дефолтным"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                # Дополняем недостающие ключи
                self._merge_defaults(cfg, self.DEFAULT_CONFIG)
                return cfg
            except Exception as e:
                print(Colors.red(f"Ошибка загрузки конфига: {e}"))
                return json.loads(json.dumps(self.DEFAULT_CONFIG))
        else:
            cfg = json.loads(json.dumps(self.DEFAULT_CONFIG))
            self._save(cfg)
            return cfg

    def _merge_defaults(self, target: dict, defaults: dict):
        """Рекурсивно дополняет target значениями из defaults"""
        for key, value in defaults.items():
            if key not in target:
                target[key] = value
            elif isinstance(value, dict) and isinstance(target[key], dict):
                self._merge_defaults(target[key], value)

    def _save(self, config: Optional[dict] = None):
        """Сохраняет конфиг в файл"""
        if config is None:
            config = self.config
        try:
            p = Path(self.config_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(Colors.red(f"Ошибка сохранения конфига: {e}"))

    def save(self):
        """Публичный метод сохранения"""
        self._save()

    # ---------- Доступ по ключу ----------
    def get(self, key: str, default=None):
        """
        Возвращает значение по ключу с поддержкой вложенности через точку
        Пример: config.get('settings.timeout', 10)
        """
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value):
        """
        Устанавливает значение по ключу с поддержкой вложенности через точку
        Пример: config.set('settings.timeout', 30)
        """
        keys = key.split('.')
        target = self.config
        for k in keys[:-1]:
            if k not in target or not isinstance(target[k], dict):
                target[k] = {}
            target = target[k]
        target[keys[-1]] = value
        self._save()

    # ---------- Работа с целями ----------
    def add_target(self, target: str) -> bool:
        """Добавляет цель в список (без дубликатов)"""
        target = Utils.normalize_target(target)
        if not target:
            return False
        if target not in self.config['targets']:
            self.config['targets'].append(target)
            self._save()
            return True
        return False

    def remove_target(self, target: str) -> bool:
        """Удаляет цель из списка"""
        target = Utils.normalize_target(target)
        if target in self.config['targets']:
            self.config['targets'].remove(target)
            self._save()
            return True
        return False

    def list_targets(self) -> List[str]:
        """Возвращает список целей"""
        return list(self.config.get('targets', []))

    def clear_targets(self):
        """Очищает список целей"""
        self.config['targets'] = []
        self._save()

    # ---------- Прокси ----------
    def load_proxies(self) -> List[str]:
        """Загружает список прокси из файла"""
        if not self.get('settings.use_proxy', False):
            return []
        proxy_file = self.get('settings.proxy_file', 'proxies.txt')
        content = Utils.read_file(proxy_file)
        if not content:
            return []
        proxies = []
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                proxies.append(line)
        return proxies

    # ---------- Хелперы ----------
    def get_timeout(self) -> int:
        return Utils.safe_int(self.get('settings.timeout', 10), 10)

    def get_threads(self) -> int:
        return Utils.safe_int(self.get('settings.threads', 10), 10)

    def get_output_dir(self) -> Path:
        return Path(self.get('settings.output_dir', 'reports'))

    def get_log_level(self) -> str:
        return self.get('settings.log_level', 'INFO')

    def get_log_file(self) -> Optional[str]:
        return self.get('settings.log_file', None)

    def is_module_enabled(self, name: str) -> bool:
        return bool(self.get(f'modules.{name}', True))

    def to_dict(self) -> dict:
        return self.config

    def __repr__(self):
        return f"<Config targets={len(self.list_targets())} path={self.config_path}>"


# ==============================================================================
# СОСТОЯНИЕ ПРИЛОЖЕНИЯ
# ==============================================================================
class AppState:
    """
    Глобальное состояние приложения
    Хранит флаги, счётчики, временные метки
    """

    def __init__(self):
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.targets_processed: int = 0
        self.targets_total: int = 0
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self._lock = threading.Lock()

    def start(self):
        self.start_time = datetime.now()

    def stop(self):
        self.end_time = datetime.now()

    def duration(self) -> float:
        """Длительность в секундах"""
        if not self.start_time:
            return 0.0
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    def duration_str(self) -> str:
        return Utils.format_duration(self.duration())

    def add_error(self, msg: str):
        with self._lock:
            self.errors.append(msg)

    def add_warning(self, msg: str):
        with self._lock:
            self.warnings.append(msg)

    def inc_targets(self):
        with self._lock:
            self.targets_processed += 1

    def summary(self) -> Dict[str, Any]:
        return {
            "duration": self.duration(),
            "duration_str": self.duration_str(),
            "targets_processed": self.targets_processed,
            "targets_total": self.targets_total,
            "errors": len(self.errors),
            "warnings": len(self.warnings),
        }


# ==============================================================================
# ПРОГРЕСС-БАР
# ==============================================================================
class ProgressBar:
    """
    Простой прогресс-бар для длительных операций
    Пример:
        with ProgressBar(total=40, prefix="Клонирование") as pb:
            for i, item in enumerate(items, 1):
                pb.update(i, item)
    """

    def __init__(self, total: int, prefix: str = "", width: int = 30,
                 color_func=None):
        self.total = max(total, 1)
        self.prefix = prefix
        self.width = width
        self.color_func = color_func or Colors.light_purple
        self.start_time = time.time()

    def _render(self, current: int, suffix: str = ""):
        percent = current / self.total
        filled = int(self.width * percent)
        bar = "█" * filled + "░" * (self.width - filled)
        elapsed = time.time() - self.start_time
        eta = (elapsed / current) * (self.total - current) if current > 0 else 0

        line = (
            f"\r  {self.prefix} "
            f"[{self.color_func(bar)}] "
            f"{current}/{self.total} "
            f"({percent * 100:.0f}%) "
            f"ETA {Utils.format_duration(eta)}"
        )
        if suffix:
            line += f"  {suffix}"
        # Обрезаем до 120 символов
        sys.stdout.write(line[:120])
        sys.stdout.flush()

    def update(self, current: int, suffix: str = ""):
        self._render(current, suffix)

    def finish(self):
        self._render(self.total, "✓")
        sys.stdout.write("\n")
        sys.stdout.flush()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.finish()


# ==============================================================================
# ПРОВЕРКА ЗАВИСИМОСТЕЙ
# ==============================================================================
def check_dependencies() -> Dict[str, bool]:
    """
    Проверяет наличие всех зависимостей
    Возвращает: {name: bool}
    """
    deps = {
        "colorama": HAS_COLORAMA,
        "requests": HAS_REQUESTS,
        "beautifulsoup4": HAS_BS4,
        "dnspython": HAS_DNS,
        "python-whois": HAS_WHOIS,
        "aiohttp": HAS_AIOHTTP,
    }
    return deps


def print_dependencies_status(logger: Optional[Logger] = None):
    """Выводит статус зависимостей"""
    deps = check_dependencies()
    missing = [name for name, ok in deps.items() if not ok]

    if logger:
        for name, ok in deps.items():
            if ok:
                logger.debug(f"  ✓ {name}")
            else:
                logger.warning(f"  ✗ {name} (не установлен)")
    else:
        for name, ok in deps.items():
            mark = Colors.green("✓") if ok else Colors.red("✗")
            print(f"  {mark} {name}")

    if missing:
        print(Colors.yellow(
            f"\n  Установите отсутствующие пакеты:\n"
            f"  pip install {' '.join(missing)}"
        ))
    return deps


# ==============================================================================
# ИНФО О СИСТЕМЕ
# ==============================================================================
def print_system_info(logger: Optional[Logger] = None):
    """Выводит информацию о системе"""
    info = Utils.get_system_info()
    lines = [
        f"  OS:      {info['os']} {info['os_release']}",
        f"  Python:  {info['python']}",
        f"  Arch:    {info['arch']}",
        f"  Host:    {info['hostname']}",
    ]
    for line in lines:
        if logger:
            logger.debug(line)
        else:
            print(Colors.dim(line))


# ==============================================================================
# СИГНАЛЫ (graceful shutdown)
# ==============================================================================
_SHUTDOWN = threading.Event()


def install_signal_handlers():
    """Устанавливает обработчики Ctrl+C"""
    import signal

    def handler(signum, frame):
        if _SHUTDOWN.is_set():
            print(Colors.red("\n  Повторный Ctrl+C — принудительный выход"))
            sys.exit(1)
        _SHUTDOWN.set()
        print(Colors.yellow("\n  Ctrl+C получен, завершаю работу..."))

    try:
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
    except (ValueError, AttributeError):
        # Не главный поток — пропускаем
        pass


def is_shutdown_requested() -> bool:
    """Проверяет, был ли запрошен shutdown"""
    return _SHUTDOWN.is_set()


# ==============================================================================
# ПРОВЕРКА GIT
# ==============================================================================
def check_git() -> bool:
    """Проверяет наличие git в системе"""
    return Utils.has_command("git")


def check_git_or_fail(logger: Optional[Logger] = None) -> bool:
    """Проверяет git и выводит понятную ошибку, если его нет"""
    if check_git():
        if logger:
            logger.debug("git: найден")
        return True

    msg = (
        "git не найден в PATH. Установите его:\n"
        "  Ubuntu/Debian: sudo apt install git\n"
        "  CentOS/RHEL:   sudo yum install git\n"
        "  macOS:         brew install git\n"
        "  Windows:       https://git-scm.com/download/win"
    )
    if logger:
        logger.error(msg)
    else:
        print(Colors.red(msg))
    return False


# ==============================================================================
# КОНЕЦ PART 1
# ==============================================================================
# В следующей части (part2_repos.py):
#   - class RepoManager (40 репозиториев)
#   - клонирование, обновление, целостность, зависимости
#   - прогресс-бар, статистика, параллельный режим
# ==============================================================================