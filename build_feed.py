#!/usr/bin/env python3
"""
NW AI Domains Feed builder.

Pobiera listy domen AI/LLM z repozytoriow zdefiniowanych w sources.yaml,
parsuje je, klasyfikuje (threat.category / threat.desc) i zapisuje plik CSV
w formacie feeda NetWitness F.07:

    host,threat.category,threat.desc,threat.source

Bez naglowka, separator przecinek - gotowe do importu jako Non-IP Callback Feed
na Decoderze (index = host, callback key = alias.host).

Zaleznosci: requests, pyyaml  (pip install requests pyyaml)
"""

import csv
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "sources.yaml"

# prefiks hosta -> rola
ROLE_PREFIX = {
    "api.": "api",
    "chat.": "chat",
    "console.": "web",
    "platform.": "web",
    "developer.": "web",
    "docs.": "web",
    "help.": "web",
    "status.": "web",
    "cdn.": "web",
    "www.": "web",
    "support.": "web",
    "community.": "web",
    "forum.": "web",
    "beta.": "web",
    "playground.": "web",
    "labs.": "web",
    "cookbook.": "web",
    "auth": "web",
}

BANNER = re.compile(r"^#+\s*$")            # linie typu ############
SKIP_COMMENT = re.compile(r"(updated|pulled from|blocklist|add your own|http)", re.I)


def strip_emoji(text: str) -> str:
    out = []
    for ch in text:
        if unicodedata.category(ch).startswith("S"):  # symbole/emoji
            continue
        out.append(ch)
    return out and "".join(out).strip() or text.strip()


def normalize_provider(raw: str) -> str:
    name = strip_emoji(raw)
    name = name.split("/")[0].split("(")[0].strip()   # "Anthropic / Claude" -> "Anthropic"
    return name.lower()


def detect_role(host: str) -> str:
    for prefix, role in ROLE_PREFIX.items():
        if host.startswith(prefix):
            return role
    return "other"


def classify(host: str, role: str, provider: str, cfg_classify: dict, default_cat: str) -> str:
    h = host.lower()
    # 1. Asystenci kodu -> llm-coding  (regula llm coding source upload)
    if any(marker in h for marker in cfg_classify.get("coding_markers", [])):
        return "llm-coding"
    # 2. Interfejsy chatowe / konsumenckie -> llm-provider
    if h in {c.lower() for c in cfg_classify.get("consumer_hosts", [])}:
        return "llm-provider"
    if role == "chat":
        return "llm-provider"
    # 3. Endpointy API/programmatyczne -> llm-enterprise
    #    (reguly C2, beaconing, server outbound, LOLBAS matchuja oba: llm-provider + llm-enterprise)
    if role == "api":
        return "llm-enterprise"
    # 4. Pozostale (console, docs, web, other) -> llm-provider
    return default_cat


def parse_hosts(text: str):
    """Parser formatu hosts: '0.0.0.0 domena' + naglowki sekcji '# Provider'."""
    provider = "unknown"
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if BANNER.match(line) or SKIP_COMMENT.search(line):
                continue
            candidate = normalize_provider(line.lstrip("#"))
            if candidate:
                provider = candidate
            continue
        parts = line.split()
        host = parts[-1].lower().rstrip(".")
        if "." in host and " " not in host:
            yield host, provider


def parse_domains(text: str):
    """Parser prostej listy: jedna domena na linie, '#' = komentarz."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = line.split()[0].lower().rstrip(".")
        if "." in host:
            yield host, "unknown"


PARSERS = {"hosts": parse_hosts, "domains": parse_domains}


def load_overrides():
    add_path = ROOT / "overrides" / "manual_add.csv"
    excl_path = ROOT / "overrides" / "exclude.txt"
    manual = {}
    if add_path.exists():
        with add_path.open(encoding="utf-8") as f:
            for row in csv.reader(f):
                if not row or row[0].strip().startswith("#"):
                    continue
                host = row[0].strip().lower()
                cat = row[1].strip() if len(row) > 1 else "llm-provider"
                desc = row[2].strip() if len(row) > 2 else host
                manual[host] = (cat, desc)
    exclude = set()
    if excl_path.exists():
        with excl_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    exclude.add(line)
    return manual, exclude


def excluded(host: str, exclude: set) -> bool:
    if host in exclude:
        return True
    # wzorce z gwiazdka na koncu, np. "status.*"
    for pat in exclude:
        if pat.endswith("*") and host.startswith(pat[:-1]):
            return True
    return False


def main():
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    feed_cfg = cfg["feed"]
    source_tag = feed_cfg["threat_source"]
    out_path = ROOT / feed_cfg["output"]
    include_roles = set(feed_cfg.get("include_roles", ["api", "chat", "web", "other"]))
    cfg_classify = cfg.get("classify", {})

    records = {}   # host -> (category, desc)  (pierwsze zrodlo wygrywa)
    for src in cfg["sources"]:
        parser = PARSERS.get(src["format"])
        if not parser:
            print(f"!! nieznany format '{src['format']}' dla {src['name']}", file=sys.stderr)
            continue
        try:
            resp = requests.get(src["url"], timeout=30)
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            print(f"!! blad pobierania {src['name']}: {exc}", file=sys.stderr)
            continue
        default_cat = src.get("default_category", "llm-provider")
        count = 0
        for host, provider in parser(resp.text):
            if provider == "unknown":
                provider = src.get("name", "ai")
            role = detect_role(host)
            if role not in include_roles:
                continue
            if host in records:
                continue
            category = classify(host, role, provider, cfg_classify, default_cat)
            desc = f"{provider} {role}".strip() if role in ("api", "chat") else provider
            records[host] = (category, desc)
            count += 1
        print(f"   {src['name']}: +{count} hostow")

    manual, exclude = load_overrides()
    records = {h: v for h, v in records.items() if not excluded(h, exclude)}
    for host, val in manual.items():       # nadpisania reczne maja priorytet
        records[host] = val

    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(records.items())
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        for host, (cat, desc) in rows:
            writer.writerow([host, cat, desc, source_tag])

    # statystyki do job summary
    by_cat = {}
    for _, (cat, _desc) in rows:
        by_cat[cat] = by_cat.get(cat, 0) + 1
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"\n== zapisano {len(rows)} hostow do {out_path.name} ({stamp}) ==")
    for cat, n in sorted(by_cat.items()):
        print(f"   {cat}: {n}")

    summary = Path("feed_summary.md")
    summary.write_text(
        f"## NW AI Domains Feed\n\n"
        f"- Wpisow: **{len(rows)}**\n"
        f"- threat.source: `{source_tag}`\n"
        f"- Aktualizacja: {stamp}\n\n"
        + "\n".join(f"- `{c}`: {n}" for c, n in sorted(by_cat.items())) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
