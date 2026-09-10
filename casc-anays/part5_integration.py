# ==============================================================================
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
# ==============================================================================