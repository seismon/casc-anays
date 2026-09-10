# 🏗 Архитектура CASC-ANAYS

Расширенная документация для разработчиков.

---

## Ядро — part1_repos.py

- Colors — фиолетовая цветовая схема
- Logger — логирование (6 уровней)
- Config — загрузка config.json
- Utils — 25+ утилит
- Target — представление цели (IPv4/IPv6/домен)
- AppState — глобальное состояние
- ProgressBar — прогресс-бар

---

## RepoManager — part2_repos.py

Клонирует, обновляет и управляет 40 GitHub-репозиториями.

Ключевые методы:
- clone_repo(name) — клонировать
- update_repo(name) — обновить
- check_integrity(name) — проверить целостность
- install_dependencies(name) — установить зависимости
- init_all() — клонировать всё
- run_tool(name, args) — запустить инструмент из репо

---

## Модули анализа — part3_analysis.py

- PortScanner — TCP + UDP, ~200 портов, баннеры
- HTTPAnalyzer — aiohttp, SSL/TLS, WAF (10 сигнатур)
- DNSAnalyzer — A/AAAA/MX/NS/TXT/CNAME/SOA + DMARC + PTR
- OSINTModule — WHOIS
- SubdomainModule — crt.sh + Sublist3r + amass + subfinder

---

## Уязвимости — part4_vuln.py

Все наследуются от VulnBase — единый формат.

- CVEScanner — NVD API + offline-база
- NiktoScanner — реальный запуск nikto.pl
- SQLiScanner — 13 payload'ов × 22 сигнатуры
- XSSScanner — 12 payload'ов (reflected)
- LfiScanner — 13 payload'ов (path traversal)
- StressTester — Slowloris + HTTP-флуд + GoldenEye

---

## Интеграция — part5_integration.py

Главный класс CascAnalys:
- Инициализирует 14 модулей
- analyze_target() — полный анализ
- smart_analyze() — авто-подбор модулей
- run(args) — обработка CLI
- get_stats() — статистика

---

## Отчёты — part6_reports.py

- HTMLReportGenerator — HTML с фиолетовой темой
- JSONReportGenerator — JSON с метаданными
- CSVReportGenerator — плоская таблица
- MarkdownReportGenerator — Markdown

---

## CLI — part7_cli.py

- build_cli() — argparse (35+ аргументов)
- main() — точка входа
- run_self_tests() — 20 тестов

---

## Как добавить свой модуль

class MyScanner(VulnBase):
    NAME = "myscanner"
    def scan(self, target):
        self._start()
        self.reset()
        if found_vuln:
            self.add_vuln(name="Vuln", severity="high")
        return self.finalize()

Затем добавь в CascAnalys.__init__ и в ALL_MODULES.

---

## Лицензия

MIT © seismon
