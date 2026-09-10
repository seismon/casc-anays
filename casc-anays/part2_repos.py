# ==============================================================================
# PART 2 — REPO MANAGER
# Управление 40 GitHub-репозиториями CASC-ANAYS
# ==============================================================================
# Требует: part1_core.py (Colors, Logger, Config, Utils, ProgressBar, check_git)
# ==============================================================================

import os
import sys
import json
import time
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed


# ==============================================================================
# РЕЕСТР РЕПОЗИТОРИЕВ (40 штук)
# ==============================================================================
DEFAULT_REPOS: Dict[str, Dict[str, Any]] = {

    # --------------------------------------------------------------------------
    # OSINT (12)
    # --------------------------------------------------------------------------
    "sherlock": {
        "url": "https://github.com/sherlock-project/sherlock.git",
        "branch": "master",
        "category": "osint",
        "lang": "python",
        "size_hint": "small",
        "desc": "Поиск username по соцсетям"
    },
    "whatsmyname": {
        "url": "https://github.com/WebBreacher/WhatsMyName.git",
        "branch": "main",
        "category": "osint",
        "lang": "json",
        "size_hint": "small",
        "desc": "База данных username → сайты"
    },
    "maigret": {
        "url": "https://github.com/soxoj/maigret.git",
        "branch": "main",
        "category": "osint",
        "lang": "python",
        "size_hint": "medium",
        "desc": "Поиск username по 3000+ сайтам"
    },
    "theharvester": {
        "url": "https://github.com/laramies/theHarvester.git",
        "branch": "master",
        "category": "osint",
        "lang": "python",
        "size_hint": "medium",
        "desc": "Сбор email, субдоменов, хостов"
    },
    "spiderfoot": {
        "url": "https://github.com/smicallef/spiderfoot.git",
        "branch": "master",
        "category": "osint",
        "lang": "python",
        "size_hint": "large",
        "desc": "Автоматизированная OSINT-разведка"
    },
    "ghunt": {
        "url": "https://github.com/mxrch/GHunt.git",
        "branch": "main",
        "category": "osint",
        "lang": "python",
        "size_hint": "small",
        "desc": "OSINT по Google-аккаунтам"
    },
    "photon": {
        "url": "https://github.com/s0md3v/Photon.git",
        "branch": "master",
        "category": "osint",
        "lang": "python",
        "size_hint": "small",
        "desc": "Быстрый краулер для OSINT"
    },
    "osintgram": {
        "url": "https://github.com/Datalux/Osintgram.git",
        "branch": "main",
        "category": "osint",
        "lang": "python",
        "size_hint": "small",
        "desc": "OSINT для Instagram"
    },
    "h8mail": {
        "url": "https://github.com/khast3x/h8mail.git",
        "branch": "master",
        "category": "osint",
        "lang": "python",
        "size_hint": "small",
        "desc": "Поиск утечек email"
    },
    "holehe": {
        "url": "https://github.com/megadose/holehe.git",
        "branch": "master",
        "category": "osint",
        "lang": "python",
        "size_hint": "small",
        "desc": "Проверка email на 120+ сайтах"
    },
    "trape": {
        "url": "https://github.com/jofpin/trape.git",
        "branch": "master",
        "category": "osint",
        "lang": "python",
        "size_hint": "medium",
        "desc": "Tracking и OSINT по людям"
    },
    "torbot": {
        "url": "https://github.com/DedSecInside/TorBot.git",
        "branch": "main",
        "category": "osint",
        "lang": "python",
        "size_hint": "small",
        "desc": "OSINT через Tor"
    },

    # --------------------------------------------------------------------------
    # ПОДДОМЕНЫ (9)
    # --------------------------------------------------------------------------
    "sublist3r": {
        "url": "https://github.com/aboul3la/Sublist3r.git",
        "branch": "master",
        "category": "subdomains",
        "lang": "python",
        "size_hint": "small",
        "desc": "Быстрый поиск поддоменов"
    },
    "amass": {
        "url": "https://github.com/owasp-amass/amass.git",
        "branch": "master",
        "category": "subdomains",
        "lang": "go",
        "size_hint": "large",
        "desc": "Мощный фреймворк для subdomain enum"
    },
    "subfinder": {
        "url": "https://github.com/projectdiscovery/subfinder.git",
        "branch": "main",
        "category": "subdomains",
        "lang": "go",
        "size_hint": "medium",
        "desc": "Пассивный поиск поддоменов"
    },
    "findomain": {
        "url": "https://github.com/Findomain/Findomain.git",
        "branch": "master",
        "category": "subdomains",
        "lang": "rust",
        "size_hint": "medium",
        "desc": "Быстрый subdomain enumerator"
    },
    "subcat": {
        "url": "https://github.com/duty1g/subcat.git",
        "branch": "main",
        "category": "subdomains",
        "lang": "python",
        "size_hint": "small",
        "desc": "Subdomain takeover checker"
    },
    "subdomain-enumerator": {
        "url": "https://github.com/ryuukhagetsu/subdomain-enumerator.git",
        "branch": "main",
        "category": "subdomains",
        "lang": "python",
        "size_hint": "small",
        "desc": "Простой subdomain enumerator"
    },
    "subdomain-enum-tool": {
        "url": "https://github.com/Sergios9494/subdomain-enum-tool.git",
        "branch": "main",
        "category": "subdomains",
        "lang": "python",
        "size_hint": "small",
        "desc": "Ещё один subdomain enum tool"
    },
    "dnsrecon": {
        "url": "https://github.com/darkoperator/dnsrecon.git",
        "branch": "master",
        "category": "subdomains",
        "lang": "python",
        "size_hint": "small",
        "desc": "DNS enumeration и разведка"
    },
    "certinfo": {
        "url": "https://github.com/rix4uni/certinfo.git",
        "branch": "main",
        "category": "subdomains",
        "lang": "python",
        "size_hint": "small",
        "desc": "Инфа из SSL-сертификатов"
    },

    # --------------------------------------------------------------------------
    # УЯЗВИМОСТИ (12)
    # --------------------------------------------------------------------------
    "nikto": {
        "url": "https://github.com/sullo/nikto.git",
        "branch": "master",
        "category": "vuln",
        "lang": "perl",
        "size_hint": "small",
        "desc": "Web server scanner"
    },
    "nuclei": {
        "url": "https://github.com/projectdiscovery/nuclei.git",
        "branch": "main",
        "category": "vuln",
        "lang": "go",
        "size_hint": "large",
        "desc": "Шаблонный сканер уязвимостей"
    },
    "web-vuln-scanner": {
        "url": "https://github.com/HoangZuzi-14/Web-Vulnerability-Scanner.git",
        "branch": "main",
        "category": "vuln",
        "lang": "python",
        "size_hint": "small",
        "desc": "Простой web vuln scanner"
    },
    "wpscan": {
        "url": "https://github.com/wpscanteam/wpscan.git",
        "branch": "master",
        "category": "vuln",
        "lang": "ruby",
        "size_hint": "medium",
        "desc": "WordPress scanner"
    },
    "joomscan": {
        "url": "https://github.com/rezasp/joomscan.git",
        "branch": "master",
        "category": "vuln",
        "lang": "perl",
        "size_hint": "small",
        "desc": "Joomla scanner"
    },
    "cmsmap": {
        "url": "https://github.com/dionach/CMSmap.git",
        "branch": "master",
        "category": "vuln",
        "lang": "python",
        "size_hint": "small",
        "desc": "CMS scanner"
    },
    "cmseek": {
        "url": "https://github.com/Tuhinshubhra/CMSeeK.git",
        "branch": "master",
        "category": "vuln",
        "lang": "python",
        "size_hint": "small",
        "desc": "CMS detection и сканирование"
    },
    "cms-vuln-scanner": {
        "url": "https://github.com/Lordozer/cms-scanner.git",
        "branch": "main",
        "category": "vuln",
        "lang": "python",
        "size_hint": "small",
        "desc": "Ещё один CMS scanner"
    },
    "jaeles": {
        "url": "https://github.com/jaeles-project/jaeles.git",
        "branch": "main",
        "category": "vuln",
        "lang": "go",
        "size_hint": "large",
        "desc": "Web app scanner на шаблонах"
    },
    "gitleaks": {
        "url": "https://github.com/gitleaks/gitleaks.git",
        "branch": "master",
        "category": "vuln",
        "lang": "go",
        "size_hint": "medium",
        "desc": "Поиск секретов в git"
    },
    "trufflehog": {
        "url": "https://github.com/trufflesecurity/trufflehog.git",
        "branch": "main",
        "category": "vuln",
        "lang": "go",
        "size_hint": "large",
        "desc": "Поиск и верификация секретов"
    },
    "wordpress-plugins": {
        "url": "https://github.com/rix4uni/wordpress-plugins.git",
        "branch": "main",
        "category": "vuln",
        "lang": "python",
        "size_hint": "small",
        "desc": "WordPress plugin scanner"
    },

    # --------------------------------------------------------------------------
    # СТРЕСС-ТЕСТЫ (4)
    # --------------------------------------------------------------------------
    "floodles": {
        "url": "https://github.com/franckferman/Floodles.git",
        "branch": "main",
        "category": "stress",
        "lang": "python",
        "size_hint": "small",
        "desc": "L7 DDoS-инструмент"
    },
    "ddos-attack": {
        "url": "https://github.com/karthik558/ddos-attack.git",
        "branch": "main",
        "category": "stress",
        "lang": "python",
        "size_hint": "small",
        "desc": "Простой DDoS-скрипт"
    },
    "slowloris": {
        "url": "https://github.com/gkbrk/slowloris.git",
        "branch": "master",
        "category": "stress",
        "lang": "python",
        "size_hint": "small",
        "desc": "Slowloris-атака"
    },
    "goldeneye": {
        "url": "https://github.com/jseidl/GoldenEye.git",
        "branch": "master",
        "category": "stress",
        "lang": "python",
        "size_hint": "small",
        "desc": "HTTP DoS-инструмент"
    },

    # --------------------------------------------------------------------------
    # СЛОВАРИ (2)
    # --------------------------------------------------------------------------
    "seclists": {
        "url": "https://github.com/danielmiessler/SecLists.git",
        "branch": "master",
        "category": "wordlists",
        "lang": "text",
        "size_hint": "huge",
        "desc": "Огромная коллекция словарей (~1.5GB)",
        "skip_integrity": True,
        "shallow": False
    },
    "fuzzdb": {
        "url": "https://github.com/fuzzdb-project/fuzzdb.git",
        "branch": "master",
        "category": "wordlists",
        "lang": "text",
        "size_hint": "medium",
        "desc": "Словари для фаззинга"
    },

    # --------------------------------------------------------------------------
    # ВСПОМОГАТЕЛЬНЫЕ (1)
    # --------------------------------------------------------------------------
    "behindthecdn": {
        "url": "https://github.com/Neved4/behindTheCDN.git",
        "branch": "main",
        "category": "auxiliary",
        "lang": "python",
        "size_hint": "small",
        "desc": "Поиск реального IP за CDN"
    },
}


# ==============================================================================
# REPO MANAGER
# ==============================================================================
class RepoManager:
    """
    Управление 40 репозиториями CASC-ANAYS

    Возможности:
        - Клонирование (shallow clone, --depth 1)
        - Обновление (git pull)
        - Проверка целостности
        - Установка зависимостей (pip / npm / go)
        - Прогресс-бар
        - Параллельный режим
        - Статистика по размерам
        - Graceful shutdown
    """

    REPOS_DIR = "repos"
    CLONE_TIMEOUT = 600          # 10 минут на клон
    PULL_TIMEOUT = 120           # 2 минуты на pull
    INSTALL_TIMEOUT = 900        # 15 минут на установку зависимостей
    PARALLEL_WORKERS = 4         # одновременно клонируемых репо

    # Репозитории, которые НЕ клонируем без явного запроса (слишком тяжёлые)
    HEAVY_REPOS = {"seclists", "spid

erfoot", "nuclei", "trufflehog", "amass"}

    def __init__(self, config: "Config", logger: "Logger",
                 base_dir: Optional[Path] = None):
        self.config = config
        self.logger = logger
        self.base_dir = Path(base_dir) if base_dir else (Path(__file__).parent / self.REPOS_DIR)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # Статусы репозиториев
        self.status: Dict[str, str] = {}
        self._status_lock = threading.Lock()

        # Загружаем репозитории: DEFAULT + из конфига
        self.repos: Dict[str, Dict[str, Any]] = dict(DEFAULT_REPOS)
        config_repos = config.get('repos', {}) or {}
        for name, data in config_repos.items():
            if isinstance(data, dict) and "url" in data:
                merged = dict(self.repos.get(name, {}))
                merged.update(data)
                self.repos[name] = merged

        # Проверяем git при инициализации
        self._git_ok = check_git()
        if not self._git_ok:
            self.logger.warning("git не найден — клонирование недоступно")

    # ==========================================================================
    # ВНУТРЕННИЕ ХЕЛПЕРЫ
    # ==========================================================================
    def _set_status(self, name: str, status: str):
        """Потокобезопасная установка статуса"""
        with self._status_lock:
            self.status[name] = status

    def _get_status(self, name: str) -> str:
        with self._status_lock:
            return self.status.get(name, "not_loaded")

    def _run_command(self, cmd: str, cwd: Optional[Path] = None,
                     timeout: int = 300) -> Tuple[bool, str, str]:
        """
        Выполняет shell-команду
        Возвращает: (success: bool, stdout: str, stderr: str)
        """
        try:
            result = subprocess.run(
                cmd,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                shell=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore',
            )
            return result.returncode == 0, result.stdout or "", result.stderr or ""
        except subprocess.TimeoutExpired:
            return False, "", f"Timeout ({timeout}s)"
        except FileNotFoundError as e:
            return False, "", f"Command not found: {e}"
        except Exception as e:
            return False, "", str(e)

    def _repo_path(self, name: str) -> Path:
        return self.base_dir / name

    def _repo_exists(self, name: str) -> bool:
        return self._repo_path(name).exists()

    def _is_heavy(self, name: str) -> bool:
        return name in self.HEAVY_REPOS

    def _get_repo_data(self, name: str) -> Dict[str, Any]:
        return self.repos.get(name, {})

    # ==========================================================================
    # КЛОНИРОВАНИЕ
    # ==========================================================================
    def clone_repo(self, name: str, url: Optional[str] = None,
                   branch: Optional[str] = None,
                   shallow: bool = True,
                   timeout: Optional[int] = None) -> bool:
        """
        Клонирует один репозиторий

        name     — имя (папка)
        url      — URL (если None — берётся из self.repos)
        branch   — ветка (если None — берётся из self.repos)
        shallow  — использовать --depth 1 (быстрее, но без истории)
        timeout  — таймаут в секундах
        """
        if not self._git_ok:
            self.logger.error(f"git недоступен, не могу клонировать {name}")
            self._set_status(name, "git_missing")
            return False

        data = self._get_repo_data(name)
        url = url or data.get('url', '')
        branch = branch or data.get('branch', 'master')
        timeout = timeout or self.CLONE_TIMEOUT

        if not url:
            self.logger.warning(f"Не указан URL для {name}")
            self._set_status(name, "no_url")
            return False

        target = self._repo_path(name)

        # Уже есть?
        if target.exists():
            self.logger.debug(f"{name}: уже существует")
            self._set_status(name, "exists")
            return True

        self.logger.info(f"Клонирование {name} ({branch})...")

        # Формируем команду
        depth_flag = "--depth 1 " if shallow else ""
        cmd = f'git clone {depth_flag}--branch "{branch}" --single-branch "{url}" "{target}"'

        start = time.time()
        ok, out, err = self._run_command(cmd, timeout=timeout)
        elapsed = time.time() - start

        if ok and target.exists():
            self._set_status(name, "cloned")
            self.logger.success(
                f"  {name}: клонирован за {Utils.format_duration(elapsed)}"
            )
            return True
        else:
            self._set_status(name, "error")
            self.logger.error(
                f"  {name}: ошибка клонирования — {Utils.truncate(err, 150)}"
            )
            # Убираем частичный клон
            if target.exists():
                try:
                    shutil.rmtree(target)
                except Exception:
                    pass
            return False

    # ==========================================================================
    # ОБНОВЛЕНИЕ
    # ==========================================================================
    def update_repo(self, name: str, timeout: Optional[int] = None) -> bool:
        """
        Обновляет репозиторий через git pull
        Если папки нет — клонирует
        """
        target = self._repo_path(name)
        timeout = timeout or self.PULL_TIMEOUT

        # Нет папки — клонируем
        if not target.exists():
            return self.clone_repo(name)

        # Нет .git — нечего пуллить, переклонируем
        if not (target / ".git").exists():
            self.logger.warning(f"{name}: нет .git, переклонирую")
            try:
                shutil.rmtree(target)
            except Exception:
                pass
            return self.clone_repo(name)

        self.logger.debug(f"Обновление {name}...")
        ok, out, err = self._run_command("git pull --ff-only", cwd=target, timeout=timeout)

        if ok:
            # Проверяем, были ли изменения
            if "Already up to date" in out or "Already up-to-date" in out:
                self._set_status(name, "up_to_date")
            else:
                self._set_status(name, "updated")
            return True
        else:
            self._set_status(name, "update_error")
            self.logger.warning(
                f"  {name}: ошибка обновления — {Utils.truncate(err, 150)}"
            )
            return False

    # ==========================================================================
    # ПРОВЕРКА ЦЕЛОСТНОСТИ
    # ==========================================================================
    def check_integrity(self, name: str) -> bool:
        """
        Проверяет, что репозиторий скачан корректно
        Ищет README, .git, файлы зависимостей
        """
        data = self._get_repo_data(name)
        if data.get('skip_integrity'):
            return True

        target = self._repo_path(name)

        # Нет папки — плохо
        if not target.exists():
            return False

        # Нет .git — подозрительно
        if not (target / ".git").exists():
            self.logger.warning(f"  {name}: нет .git")
            return False

        # Ищем признаки "живого" репо
        markers = [
            "README.md", "README.rst", "README.txt", "README",
            "requirements.txt", "setup.py", "pyproject.toml",
            "package.json", "go.mod", "Cargo.toml", "Gemfile",
            "LICENSE", "LICENSE.txt", "LICENSE.md",
        ]

        found = any((target / m).exists() for m in markers)

        if not found:
            # Может быть просто папка с данными (например, SecLists)
            # Проверяем, есть ли хоть какие-то файлы
            try:
                has_files = any(target.iterdir())
            except Exception:
                has_files = False

            if not has_files:
                self.logger.warning(f"  {name}: пустой репозиторий")
                return False

        return True

    def verify_all(self) -> Dict[str, bool]:
        """Проверяет целостность всех репозиториев"""
        self.logger.info("Проверка целостности репозиториев...")
        results = {}
        for name in self.repos.keys():
            results[name] = self.check_integrity(name)
        return results

    # ==========================================================================
    # УСТАНОВКА ЗАВИСИМОСТЕЙ
    # ==========================================================================
    def install_dependencies(self, name: str,
                             timeout: Optional[int] = None) -> bool:
        """
        Устанавливает зависимости репозитория
        Поддерживает: Python (requirements.txt, setup.py),
                      Node.js (package.json),
                      Go (go.mod),
                      Ruby (Gemfile)
        """
        target = self._repo_path(name)
        if not target.exists():
            return False

        timeout = timeout or self.INSTALL_TIMEOUT

        # Python
        if (target / "requirements.txt").exists():
            self.logger.info(f"  {name}: pip install -r requirements.txt")
            ok, _, err = self._run_command(
                f'"{sys.executable}" -m pip install -r requirements.txt',
                cwd=target,
                timeout=timeout
            )
            if not ok:
                self.logger.warning(f"  {name}: pip ошибка — {Utils.truncate(err, 150)}")
            return ok

        if (target / "pyproject.toml").exists() or (target / "setup.py").exists():
            self.logger.info(f"  {name}: pip install -e .")
            ok, _, err = self._run_command(
                f'"{sys.executable}" -m pip install -e .',
                cwd=target,
                timeout=timeout
            )
            if not ok:
                self.logger.debug(f"  {name}: pip -e ошибка — {Utils.truncate(err, 150)}")
            return ok

        # Node.js
        if (target / "package.json").exists():
            if not Utils.has_command("npm"):
                self.logger.warning(f"  {name}: npm не найден, пропускаю")
                return False
            self.logger.info(f"  {name}: npm install")
            ok, _, err = self._run_command("npm install", cwd=target, timeout=timeout)
            if not ok:
                self.logger.warning(f"  {name}: npm ошибка — {Utils.truncate(err, 150)}")
            return ok

        # Go
        if (target / "go.mod").exists():
            if not Utils.has_command("go"):
                self.logger.debug(f"  {name}: go не найден, пропускаю")
                return False
            self.logger.info(f"  {name}: go mod download")
            ok, _, err = self._run_command("go mod download", cwd=target, timeout=timeout)
            return ok

        # Ruby
        if (target / "Gemfile").exists():
            if not Utils.has_command("bundle"):
                self.logger.debug(f"  {name}: bundler не найден, пропускаю")
                return False
            self.logger.info(f"  {name}: bundle install")
            ok, _, err = self._run_command("bundle install", cwd=target, timeout=timeout)
            return ok

        self.logger.debug(f"  {name}: нет файла зависимостей")
        return True

    # ==========================================================================
    # ИНИЦИАЛИЗАЦИЯ ВСЕХ РЕПОЗИТОРИЕВ
    # ==========================================================================
    def init_all(self,
                 only: Optional[List[str]] = None,
                 skip_heavy: bool = True,
                 parallel: bool = False,
                 install_deps: bool = False,
                 check_integrity: bool = True) -> Dict[str, str]:
        """
        Инициализирует все репозитории

        only         — список имён (если None — все)
        skip_heavy   — пропускать тяжёлые (seclists, spiderfoot и т.д.)
        parallel     — параллельное клонирование
        install_deps — устанавливать зависимости
        check_integrity — проверять целостность
        """
        if not self._git_ok:
            self.logger.error("git недоступен — инициализация репозиториев невозможна")
            return self.status

        # Определяем список
        names = only if only else list(self.repos.keys())

        if skip_heavy and not only:
            skipped = [n for n in names if self._is_heavy(n)]
            names = [n for n in names if not self._is_heavy(n)]
            if skipped:
                self.logger.info(
                    f"Пропускаю тяжёлые репозитории ({len(skipped)}): "
                    f"{', '.join(skipped)}"
                )
                self.logger.info(
                    "  (используйте --init-repos --all, чтобы клонировать их тоже)"
                )

        total = len(names)
        self.logger.info(f"Инициализация {total} репозиториев...")
        start = time.time()

        if parallel and HAS_FUTURES:
            self._init_parallel(names, install_deps, check_integrity)
        else:
            self._init_sequential(names, install_deps, check_integrity)

        elapsed = time.time() - start
        self._print_init_summary(elapsed)
        return self.status

    def _init_sequential(self, names: List[str],
                         install_deps: bool, check_integrity: bool):
        """Последовательная инициализация с прогресс-баром"""
        total = len(names)
        with ProgressBar(total, prefix="Репозитории", color_func=Colors.light_purple) as pb:
            for i, name in enumerate(names, 1):
                if is_shutdown_requested():
                    self.logger.warning("Прерывание по Ctrl+C")
                    break
                self._process_one(name, install_deps, check_integrity)
                pb.update(i, name)

    def _init_parallel(self, names: List[str],
                       install_deps: bool, check_integrity: bool):
        """Параллельная инициализация"""
        total = len(names)
        done = 0
        lock = threading.Lock()

        def task(name: str):
            nonlocal done
            if is_shutdown_requested():
                return
            self._process_one(name, install_deps, check_integrity)
            with lock:
                done += 1
                print(f"\r  Прогресс: {done}/{total}  {name[:40]:40}", end="", flush=True)

        with ThreadPoolExecutor(max_workers=self.PARALLEL_WORKERS) as ex:
            futures = [ex.submit(task, n) for n in names]
            for _ in as_completed(futures):
                pass

        print()

    def _process_one(self, name: str, install_deps: bool, check_integrity: bool):
        """Обрабатывает один репозиторий: clone/update + опционально deps + integrity"""
        try:
            if self._repo_exists(name):
                self.update_repo(name)
            else:
                self.clone_repo(name)

            if install_deps:
                self.install_dependencies(name)

            if check_integrity:
                self.check_integrity(name)
        except Exception as e:
            self._set_status(name, "exception")
            self.logger.error(f"  {name}: исключение — {e}")

    def _print_init_summary(self, elapsed: float):
        """Выводит итоговую статистику инициализации"""
        stats = self.get_status_summary()
        print()
        self.logger.info("=" * 60)
        self.logger.info("ИТОГИ ИНИЦИАЛИЗАЦИИ")
        self.logger.info("=" * 60)
        self.logger.info(f"  Всего:      {stats['total']}")
        self.logger.success(f"  Клонировано:{stats['cloned']:>4}")
        self.logger.success(f"  Обновлено:  {stats['updated']:>4}")
        self.logger.info(f"  Уже было:   {stats['exists']:>4}")
        if stats['errors']:
            self.logger.error(f"  Ошибок:     {stats['errors']:>4}")
        self.logger.info(f"  Время:      {Utils.format_duration(elapsed)}")
        self.logger.info(f"  Размер:     {Utils.format_bytes(self.get_total_size())}")
        self.logger.info("=" * 60)

    # ==========================================================================
    # ПУБЛИЧНЫЕ МЕТОДЫ УПРАВЛЕНИЯ
    # ==========================================================================
    def get_repo_path(self, name: str) -> Optional[Path]:
        """Возвращает путь к репозиторию, если он существует"""
        p = self._repo_path(name)
        return p if p.exists() else None

    def get_repo_size(self, name: str) -> int:
        """Размер репозитория в байтах"""
        target = self._repo_path(name)
        if not target.exists():
            return 0
        return self._dir_size(target)

    def get_total_size(self) -> int:
        """Общий размер всех репозиториев"""
        if not self.base_dir.exists():
            return 0
        return self._dir_size(self.base_dir)

    def _dir_size(self, path: Path) -> int:
        """Рекурсивно считает размер директории"""
        total = 0
        try:
            for item in path.rglob('*'):
                if item.is_file():
                    try:
                        total += item.stat().st_size
                    except (OSError, FileNotFoundError):
                        pass
        except Exception:
            pass
        return total

    def list_repos(self) -> List[str]:
        """Возвращает список имён всех репозиториев"""
        return list(self.repos.keys())

    def list_downloaded(self) -> List[str]:
        """Возвращает список уже скачанных репозиториев"""
        return [n for n in self.repos.keys() if self._repo_exists(n)]

    def list_by_category(self) -> Dict[str, List[str]]:
        """Группирует репозитории по категориям"""
        result: Dict[str, List[str]] = {}
        for name, data in self.repos.items():
            cat = data.get('category', 'other')
            result.setdefault(cat, []).append(name)
        return result

    def get_status(self) -> Dict[str, str]:
        """Возвращает текущие статусы"""
        return dict(self.status)

    def get_status_summary(self) -> Dict[str, int]:
        """Возвращает сводку по статусам"""
        summary = {
            "total": len(self.repos),
            "cloned": 0,
            "updated": 0,
            "up_to_date": 0,
            "exists": 0,
            "errors": 0,
            "not_loaded": 0,
        }
        for name in self.repos.keys():
            st = self._get_status(name)
            if st in ("cloned",):
                summary["cloned"] += 1
            elif st in ("updated",):
                summary["updated"] += 1
            elif st in ("up_to_date",):
                summary["up_to_date"] += 1
            elif st in ("exists",):
                summary["exists"] += 1
            elif st in ("error", "update_error", "exception", "git_missing", "no_url"):
                summary["errors"] += 1
            else:
                summary["not_loaded"] += 1
        return summary

    def update_all(self, **kwargs) -> Dict[str, str]:
        """Алиас для init_all (обновление всех)"""
        return self.init_all(**kwargs)

    def clean(self, only: Optional[List[str]] = None) -> bool:
        """
        Удаляет репозитории
        only — список имён (если None — все)
        """
        try:
            if only:
                for name in only:
                    target = self._repo_path(name)
                    if target.exists():
                        shutil.rmtree(target)
                        self._set_status(name, "removed")
                        self.logger.info(f"Удалён: {name}")
            else:
                if self.base_dir.exists():
                    shutil.rmtree(self.base_dir)
                    self.base_dir.mkdir(parents=True, exist_ok=True)
                    self.status.clear()
                    self.logger.info("Все репозитории удалены")
            return True
        except Exception as e:
            self.logger.error(f"Ошибка удаления: {e}")
            return False

    def find_executable(self, name: str,
                        candidates: Optional[List[str]] = None) -> Optional[Path]:
        """
        Ищет исполняемый файл внутри репозитория
        Полезно для интеграции (например, nikto.pl, sublist3r.py)
        """
        target = self.get_repo_path(name)
        if not target:
            return None

        if candidates is None:
            candidates = [
                f"{name}.py", f"{name}.pl", f"{name}.rb",
                f"{name}.sh", name,
                "main.py", "run.py", "start.py",
                "nikto.pl", "sublist3r.py",
            ]

        for cand in candidates:
            # В корне
            p = target / cand
            if p.exists() and p.is_file():
                return p
            # В подпапках (глубина 2)
            for sub in target.iterdir():
                if sub.is_dir():
                    p = sub / cand
                    if p.exists() and p.is_file():
                        return p

        return None

    def has_repo(self, name: str) -> bool:
        """Проверяет, скачан ли репозиторий"""
        return self._repo_exists(name)

    def repo_info(self, name: str) -> Dict[str, Any]:
        """Возвращает полную информацию о репозитории"""
        data = dict(self._get_repo_data(name))
        data["name"] = name
        data["path"] = str(self._repo_path(name))
        data["exists"] = self._repo_exists(name)
        data["size"] = self.get_repo_size(name)
        data["size_str"] = Utils.format_bytes(data["size"])
        data["status"] = self._get_status(name)
        return data

    def all_info(self) -> List[Dict[str, Any]]:
        """Информация по всем репозиториям"""
        return [self.repo_info(n) for n in self.repos.keys()]

    # ==========================================================================
    # ИНФОРМАЦИОННЫЙ ВЫВОД
    # ==========================================================================
    def print_list(self, show_size: bool = True, show_status: bool = True,
                   group_by_category: bool = True):
        """Красиво выводит список репозиториев"""
        if group_by_category:
            grouped = self.list_by_category()
            for cat, names in sorted(grouped.items()):
                print(Colors.bold_purple(f"\n  [{cat.upper()}]"))
                for name in sorted(names):
                    self._print_repo_line(name, show_size, show_status)
        else:
            print(Colors.bold_purple("\n  [РЕПОЗИТОРИИ]"))
            for name in sorted(self.repos.keys()):
                self._print_repo_line(name, show_size, show_status)

    def _print_repo_line(self, name: str, show_size: bool, show_status: bool):
        parts = [f"    {Colors.cyan('•')} {name:32}"]

        if show_size:
            size = Utils.format_bytes(self.get_repo_size(name))
            parts.append(f"{size:>10}")

        if show_status:
            st = self._get_status(name)
            color = {
                "cloned": Colors.green,
                "updated": Colors.green,
                "up_to_date": Colors.green,
                "exists": Colors.cyan,
                "not_loaded": Colors.dim,
                "error": Colors.red,
                "update_error": Colors.red,
                "exception": Colors.red,
                "git_missing": Colors.red,
                "no_url": Colors.yellow,
            }.get(st, Colors.dim)
            parts.append(f"  {color(f'[{st}]')}")

        print(" ".join(parts))

    def print_status_table(self):
        """Выводит таблицу статусов всех репозиториев"""
        print(Colors.bold_purple("\n  СТАТУС РЕПОЗИТОРИЕВ"))
        print(Colors.dim("  " + "-" * 70))
        print(f"  {'Имя':<28} {'Категория':<14} {'Статус':<14} {'Размер'}")
        print(Colors.dim("  " + "-" * 70))

        for name in sorted(self.repos.keys()):
            data = self._get_repo_data(name)
            cat = data.get('category', '-')
            st = self._get_status(name)
            size = Utils.format_bytes(self.get_repo_size(name))

            color = {
                "cloned": Colors.green,
                "updated": Colors.green,
                "up_to_date": Colors.green,
                "exists": Colors.cyan,
            }.get(st, Colors.red if "error" in st else Colors.dim)

            print(f"  {name:<28} {cat:<14} {color(st):<24} {size}")

        print(Colors.dim("  " + "-" * 70))

    # ==========================================================================
    # ИНТЕГРАЦИЯ С МОДУЛЯМИ АНАЛИЗА
    # ==========================================================================
    def run_tool(self, name: str, args: List[str],
                 cwd: Optional[Path] = None,
                 timeout: int = 300) -> Tuple[bool, str, str]:
        """
        Запускает инструмент из репозитория
        Автоматически определяет интерпретатор по расширению
        """
        exe = self.find_executable(name)
        if not exe:
            return False, "", f"Не найден исполняемый файл для {name}"

        cwd = cwd or exe.parent
        cmd = self._build_command(exe, args)

        self.logger.debug(f"Запуск: {cmd}")
        return self._run_command(cmd, cwd=cwd, timeout=timeout)

    def _build_command(self, exe: Path, args: List[str]) -> str:
        """Собирает команду с правильным интерпретатором"""
        args_str = " ".join(f'"{a}"' if " " in a else a for a in args)
        ext = exe.suffix.lower()

        if ext == ".py":
            return f'"{sys.executable}" "{exe}" {args_str}'
        elif ext == ".pl":
            perl = Utils.which("perl") or "perl"
            return f'{perl} "{exe}" {args_str}'
        elif ext == ".rb":
            ruby = Utils.which("ruby") or "ruby"
            return f'{ruby} "{exe}" {args_str}'
        elif ext == ".sh":
            bash = Utils.which("bash") or "bash"
            return f'{bash} "{exe}" {args_str}'
        elif ext == ".go":
            go = Utils.which("go") or "go"
            return f'{go} run "{exe}" {args_str}'
        else:
            return f'"{exe}" {args_str}'

    # ==========================================================================
    # КОНТЕКСТНЫЙ МЕНЕДЖЕР (для with)
    # ==========================================================================
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Ничего не чистим — репозитории должны остаться
        pass

    def __repr__(self):
        return f"<RepoManager repos={len(self.repos)} dir={self.base_dir}>"


# ==============================================================================
# ХЕЛПЕР: ИНИЦИАЛИЗАЦИЯ ИЗ КОНФИГА
# ==============================================================================
def create_repo_manager(config: "Config", logger: "Logger") -> RepoManager:
    """Удобная фабрика RepoManager"""
    return RepoManager(config, logger)


# ==============================================================================
# КОНЕЦ PART 2
# ==============================================================================
# В следующей части (part3_analysis.py):
#   - class PortScanner  (TCP + UDP, top-1000, async)
#   - class HTTPAnalyzer (заголовки, SSL, WAF, технологии, aiohttp)
#   - class DNSAnalyzer  (A/AAAA/MX/NS/TXT/CNAME/SOA/PTR)
#   - class OSINTModule  (WHOIS, DNS-history)
#   - class SubdomainModule (crt.sh + Sublist3r + amass + subfinder)
# ==============================================================================