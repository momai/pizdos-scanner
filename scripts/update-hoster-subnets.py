#!/usr/bin/env python3
"""Fetch announced IPv4 prefixes from RIPEstat and write hoster subnet lists."""

from __future__ import annotations

import ipaddress
import json
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "subnets"

HOSTERS: dict[str, dict[str, object]] = {
    "yandex-cloud": {
        "title": "Yandex Cloud",
        "asns": [200350, 210656, 215013],
        "note": "Yandex.Cloud LLC; см. https://yandex.cloud/ru/docs/overview/concepts/public-ips",
    },
    "vk-cloud": {
        "title": "VK Cloud",
        "asns": [47764],
        "note": "LLC VK (VK-AS); включает VK Cloud и другие сервисы VK",
    },
    "regru": {
        "title": "REG.RU",
        "asns": [197695],
        "note": 'Domain names registrar REG.RU, Ltd (AS-REG)',
    },
    "timeweb": {
        "title": "Timeweb",
        "asns": [9123, 51789],
        "note": "JSC TIMEWEB + TimewebCloud",
    },
    "selectel": {
        "title": "Selectel",
        "asns": [50340, 49505, 61976],
        "note": "SELECTEL-MSK, SELECTEL, SELECTEL-NSK",
    },
}


def fetch_ipv4_prefixes(asn: int) -> list[str]:
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    with urllib.request.urlopen(url, timeout=60) as response:
        payload = json.load(response)
    prefixes = payload.get("data", {}).get("prefixes", [])
    return sorted(
        entry["prefix"]
        for entry in prefixes
        if ":" not in entry["prefix"]
    )


def normalize_prefixes(prefixes: list[str]) -> list[str]:
    """Убрать вложенные/перекрывающиеся CIDR, слить смежные блоки."""
    networks = [ipaddress.ip_network(prefix, strict=False) for prefix in prefixes]
    collapsed = ipaddress.collapse_addresses(networks)
    return sorted(
        str(network) for network in collapsed
    )


def sort_prefixes(prefixes: list[str]) -> list[str]:
    return normalize_prefixes(prefixes)


def count_slash24(prefixes: list[str]) -> int:
    total = 0
    for prefix in prefixes:
        mask = int(prefix.split("/")[1])
        total += 1 << max(0, 24 - mask)
    return total


def write_list(path: Path, title: str, asns: list[int], note: str, prefixes: list[str]) -> None:
    today = date.today().isoformat()
    asn_part = ", ".join(f"AS{asn}" for asn in asns)
    lines = [
        f"# {title}",
        f"# ASN: {asn_part}",
        f"# Источник: RIPEstat announced-prefixes, {today}",
        f"# CIDR: {len(prefixes)}, ~{count_slash24(prefixes)} /24",
        f"# {note}",
        "",
    ]
    lines.extend(prefixes)
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    combined: list[str] = []

    for slug, meta in HOSTERS.items():
        title = str(meta["title"])
        asns = list(meta["asns"])  # type: ignore[arg-type]
        note = str(meta["note"])
        prefixes: list[str] = []

        for asn in asns:
            try:
                fetched = fetch_ipv4_prefixes(asn)
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                print(f"ERROR AS{asn}: {exc}", file=sys.stderr)
                return 1
            print(f"{slug} AS{asn}: {len(fetched)} prefixes", file=sys.stderr)
            prefixes.extend(fetched)

        prefixes = normalize_prefixes(prefixes)
        combined.extend(prefixes)
        write_list(OUT_DIR / f"{slug}.txt", title, asns, note, prefixes)
        print(
            f"{slug}: {len(prefixes)} CIDR, ~{count_slash24(prefixes)} /24",
            file=sys.stderr,
        )

    combined = normalize_prefixes(combined)
    write_list(
        OUT_DIR / "all-known-hosters.txt",
        "Все известные хостеры",
        [asn for meta in HOSTERS.values() for asn in meta["asns"]],  # type: ignore[union-attr]
        "Объединение yandex-cloud, vk-cloud, regru, timeweb, selectel",
        combined,
    )
    print(
        f"all-known-hosters: {len(combined)} CIDR, ~{count_slash24(combined)} /24",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
