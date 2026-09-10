# 📄 Примеры отчётов CASC-ANAYS

Здесь лежат реальные отчёты после сканирования тестового стенда
DVWA (Damn Vulnerable Web App), поднятого локально через Docker.

Все уязвимости — настоящие, стенд специально создан для их демонстрации.

---

## 📂 Что внутри

- report_dvwa.html — полный HTML-отчёт (фиолетовая тема)
- report_dvwa.json — структурированный JSON
- report_dvwa.csv — плоская таблица уязвимостей
- report_dvwa.md — Markdown-версия

---

## 🚀 Как воспроизвести

docker run -d -p 80:80 vulnerables/web-dvwa
python3 casc_anays.py -t 127.0.0.1 --smart --format all

⚠️ Не запускай стресс-тесты против DVWA — используй --no-stress.
