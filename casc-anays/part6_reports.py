# ==============================================================================
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
# ==============================================================================