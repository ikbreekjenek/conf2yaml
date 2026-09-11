#!/usr/bin/env python3
"""
awg2clash.py — конвертер AmneziaWG .conf -> Mihomo/Clash proxy YAML

Использование:
    python3 awg2clash.py input.conf [-o output.yaml] [-n имя_прокси] [--keepalive-mode avg|range]

Ничего никуда не отправляет — работает полностью локально.
"""

import argparse
import configparser
import re
import sys
from pathlib import Path


def parse_range_avg(value: str) -> int:
    """'25-35' -> 30 (округление до целого), '25' -> 25"""
    value = value.strip()
    if "-" in value:
        a, b = value.split("-", 1)
        return round((float(a) + float(b)) / 2)
    return int(float(value))


def read_conf(path: Path) -> dict:
    cp = configparser.ConfigParser(strict=False)
    cp.optionxform = str  # не приводить ключи к нижнему регистру
    cp.read(path, encoding="utf-8")

    if "Interface" not in cp or "Peer" not in cp:
        sys.exit("Ошибка: в файле нет секций [Interface] и/или [Peer]")

    iface = dict(cp["Interface"])
    peer = dict(cp["Peer"])
    return {"iface": iface, "peer": peer}


def build_yaml(data: dict, name: str, keepalive_mode: str) -> str:
    iface = data["iface"]
    peer = data["peer"]

    # --- Interface ---
    address = iface.get("Address", "").split("/")[0].strip()
    private_key = iface.get("PrivateKey", "").strip()

    dns_raw = iface.get("DNS", "").strip()
    dns_list = [d.strip() for d in dns_raw.split(",") if d.strip()] if dns_raw else []

    # --- Peer ---
    public_key = peer.get("PublicKey", "").strip()
    preshared_key = peer.get("PresharedKey", "").strip()
    allowed_ips_raw = peer.get("AllowedIPs", "0.0.0.0/0, ::/0")
    allowed_ips = [a.strip() for a in allowed_ips_raw.split(",") if a.strip()]

    endpoint = peer.get("Endpoint", "").strip()
    if ":" not in endpoint:
        sys.exit("Ошибка: не удалось разобрать Endpoint (ожидался формат host:port)")
    server, port = endpoint.rsplit(":", 1)

    keepalive_raw = peer.get("PersistentKeepalive", "25").strip()
    if keepalive_mode == "avg":
        keepalive_val = str(parse_range_avg(keepalive_raw))
    else:
        keepalive_val = f'"{keepalive_raw}"' if "-" in keepalive_raw else keepalive_raw

    # --- AWG-специфичные поля ---
    awg_fields = {}
    simple_int_fields = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]
    for f in simple_int_fields:
        if f in iface:
            awg_fields[f.lower()] = iface[f].strip()

    if "I1" in iface:
        awg_fields["i1"] = iface["I1"].strip()
    for extra in ["I2", "I3", "I4", "I5"]:
        if extra in iface:
            awg_fields[extra.lower()] = iface[extra].strip()

    if "HeaderProtectionKey" in iface:
        awg_fields["header-protection-key"] = iface["HeaderProtectionKey"].strip()

    range_or_bool_fields = {
        "RekeyAfterTime": "rekey-after-time",
        "RekeyTimeout": "rekey-timeout",
        "RejectAfterTime": "reject-after-time",
        "KeepaliveTimeout": "keepalive-timeout",
        "MaxHandshakeAttempts": "max-handshake-attempts",
    }
    for src, dst in range_or_bool_fields.items():
        if src in iface:
            awg_fields[dst] = iface[src].strip()

    for src, dst in [("RandomTrailers", "random-trailers"), ("DisableCookies", "disable-cookies")]:
        if src in iface:
            val = iface[src].strip().lower()
            awg_fields[dst] = "true" if val in ("on", "true", "1", "yes") else "false"

    # версия: если есть поля v3+ (header-protection-key, rekey-*, reject-*, keepalive-timeout,
    # max-handshake-attempts, random-trailers, disable-cookies) -> version: 3, иначе v1/v1.5
    v3_markers = [
        "header-protection-key", "rekey-after-time", "rekey-timeout",
        "reject-after-time", "keepalive-timeout", "max-handshake-attempts",
        "random-trailers", "disable-cookies",
    ]
    version = 3 if any(m in awg_fields for m in v3_markers) else 1

    # --- Сборка YAML ---
    lines = []
    lines.append("proxies:")
    lines.append(f'- name: "{name}"')
    lines.append("  type: wireguard")
    lines.append(f"  private-key: {private_key}")
    lines.append(f"  server: {server}")
    lines.append(f"  port: {port}")
    lines.append(f"  ip: {address}")
    lines.append(f"  public-key: {public_key}")
    ips_str = ", ".join(f"'{ip}'" for ip in allowed_ips)
    lines.append(f"  allowed-ips: [{ips_str}]")
    if preshared_key:
        lines.append(f"  pre-shared-key: {preshared_key}")
    lines.append(f"  persistent-keepalive: {keepalive_val}")
    lines.append("  udp: true")
    if dns_list:
        lines.append("  remote-dns-resolve: true")
        lines.append(f"  dns: [{', '.join(dns_list)}]")

    if awg_fields:
        lines.append("  amnezia-wg-option:")
        lines.append(f"    version: {version}")
        order = [
            "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
            "h1", "h2", "h3", "h4",
            "i1", "i2", "i3", "i4", "i5",
            "header-protection-key",
            "rekey-after-time", "rekey-timeout", "reject-after-time",
            "keepalive-timeout", "max-handshake-attempts",
            "random-trailers", "disable-cookies",
        ]
        for key in order:
            if key in awg_fields:
                val = awg_fields[key]
                if key == "header-protection-key":
                    lines.append(f"    {key}: >-")
                    lines.append(f"      {val}")
                elif key.startswith("i") and key != "i" and val.startswith("<"):
                    # i1..i5 могут содержать спецсимволы <> — оставляем как есть
                    lines.append(f"    {key}: {val}")
                else:
                    lines.append(f"    {key}: {val}")

    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Конвертер AmneziaWG .conf в Mihomo/Clash YAML")
    ap.add_argument("input", type=Path, help="путь к .conf файлу")
    ap.add_argument("-o", "--output", type=Path, default=None, help="путь к выходному .yaml (по умолчанию рядом с входным)")
    ap.add_argument("-n", "--name", default=None, help="имя proxy в YAML (по умолчанию берётся из имени файла)")
    ap.add_argument(
        "--keepalive-mode", choices=["avg", "range"], default="avg",
        help="как обрабатывать PersistentKeepalive-диапазон: avg (среднее число) или range (строка 'a-b')",
    )
    args = ap.parse_args()

    if not args.input.exists():
        sys.exit(f"Файл не найден: {args.input}")

    name = args.name or re.sub(r"[^A-Za-z0-9_-]+", "_", args.input.stem)
    output = args.output or args.input.with_suffix(".yaml")

    data = read_conf(args.input)
    yaml_text = build_yaml(data, name, args.keepalive_mode)

    output.write_text(yaml_text, encoding="utf-8")
    print(f"Готово: {output}")


if __name__ == "__main__":
    main()
