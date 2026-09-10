=#!/bin/bash
set -e
echo "→ Сборка CASC-ANAYS..."
cat part1_repos.py \
    part2_repos.py \
    part3_analysis.py \
    part4_vuln.py \
    part5_integration.py \
    part6_reports.py \
    part7_cli.py > casc_anays.py
LINES=$(wc -l < casc_anays.py)
echo "✓ Готово: casc_anays.py ($LINES строк)"
