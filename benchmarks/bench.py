#!/usr/bin/env python3
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from casc_anays import (
    Logger, Target, PortScanner,
    SQLiScanner, XSSScanner, LfiScanner,
)


def bench_ports():
    print("=" * 60)
    print("PortScanner")
    print("=" * 60)
    logger = Logger(level="ERROR")
    scanner = PortScanner(logger, timeout=0.5)
    target = Target("127.0.0.1")
    ports = list(range(1, 1001))
    start = time.time()
    result = scanner.scan(target, ports=ports, grab_banners=False)
    elapsed = time.time() - start
    speed = len(ports) / elapsed if elapsed > 0 else 0
    print(f"  Просканировано: {len(ports)} портов")
    print(f"  Время:          {elapsed:.2f} сек")
    print(f"  Скорость:       {speed:.0f} портов/сек")
    print(f"  Открыто:        {result.get('open_count', 0)}")


def count_payloads():
    print()
    print("=" * 60)
    print("Payloads")
    print("=" * 60)
    print(f"  SQLi payloads:  {len(SQLiScanner.ERROR_PAYLOADS)}")
    print(f"  SQL ошибок:     {len(SQLiScanner.SQL_ERRORS)}")
    print(f"  XSS payloads:   {len(XSSScanner.PAYLOADS)}")
    print(f"  LFI payloads:   {len(LfiScanner.PAYLOADS)}")
    print(f"  LFI сигнатур:   {len(LfiScanner.LFI_SIGNATURES)}")


if __name__ == "__main__":
    bench_ports()
    count_payloads()
    print()
