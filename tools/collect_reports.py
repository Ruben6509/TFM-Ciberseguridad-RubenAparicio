from __future__ import annotations

import argparse
from bs4 import BeautifulSoup
from datetime import datetime, timezone
import hashlib
import httpx
from io import BytesIO
import json
from pathlib import Path
from pypdf import PdfReader
import time
import trafilatura
from urllib.parse import urljoin, urlsplit
import urllib.robotparser


USER_AGENT = "TFM-CTI-Research-Collector/1.0 (academic research)"

# Fuentes permitidas
SOURCES = {
    "mandiant": {
        "discovery": "https://cloud.google.com/transform/sitemapsummary/cloudblog",
        "host": "cloud.google.com",
        "path": "/blog/topics/threat-intelligence/",
    },
    "unit42": {
        "discovery": "https://unit42.paloaltonetworks.com/wp-json/wp/v2/posts",
        "host": "unit42.paloaltonetworks.com",
    },
}


# Utilidades
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def links(document: str, base: str) -> list[str]:
    soup = BeautifulSoup(document, "xml")
    values = [node.get_text(strip=True) for node in soup.find_all("loc")]
    if not values:
        soup = BeautifulSoup(document, "html.parser")
        values = [urljoin(base, node.get("href")) for node in soup.find_all("a", href=True)]
    return list(dict.fromkeys(values))


# Descubrimiento de informes
def discover_mandiant(client: httpx.Client, start: str) -> list[str]:
    first = client.get(SOURCES["mandiant"]["discovery"])
    first.raise_for_status()
    candidates = links(first.text, str(first.url))
    pages: list[str] = []
    for candidate in candidates:
        if SOURCES["mandiant"]["path"] in urlsplit(candidate).path:
            pages.append(candidate)
        elif "sitemap" in candidate.lower():
            response = client.get(candidate)
            if response.is_success:
                pages.extend(
                    url for url in links(response.text, str(response.url))
                    if SOURCES["mandiant"]["path"] in urlsplit(url).path
                )
    return sorted(set(pages))


def discover_unit42(client: httpx.Client, start: str) -> list[str]:
    pages: list[str] = []
    page = 1
    while True:
        response = client.get(
            SOURCES["unit42"]["discovery"],
            params={"per_page": 100, "page": page, "after": f"{start}T00:00:00", "_fields": "link"},
        )
        if response.status_code == 400:
            break
        response.raise_for_status()
        batch = response.json()
        if not batch:
            break
        pages.extend(item["link"] for item in batch)
        page += 1
    return sorted(set(pages))


# Comprobación de robots.txt
def allowed(url: str, cache: dict[str, urllib.robotparser.RobotFileParser]) -> bool:
    parsed = urlsplit(url)
    if parsed.hostname not in {item["host"] for item in SOURCES.values()}:
        return False
    if parsed.hostname not in cache:
        robots = urllib.robotparser.RobotFileParser(f"{parsed.scheme}://{parsed.hostname}/robots.txt")
        robots.read()
        cache[parsed.hostname] = robots
    return cache[parsed.hostname].can_fetch(USER_AGENT, url)


# Parser de HTML y PDF
def extract(raw: bytes, content_type: str, url: str) -> tuple[str, str]:
    if "pdf" in content_type.lower() or urlsplit(url).path.lower().endswith(".pdf"):
        pages = [(page.extract_text() or "") for page in PdfReader(BytesIO(raw)).pages]
        return "\n\n".join(pages), "pypdf"
    html = raw.decode("utf-8", errors="replace")
    text = trafilatura.extract(html, include_links=False, include_tables=True)
    if text:
        return text, "trafilatura"
    soup = BeautifulSoup(html, "html.parser")
    for node in soup(["script", "style", "nav", "footer", "header"]):
        node.decompose()
    return soup.get_text("\n", strip=True), "beautifulsoup"


# Crawler
def main() -> int:
    parser = argparse.ArgumentParser(description="Descarga y prepara informes CTI públicos")
    parser.add_argument("source", choices=SOURCES)
    parser.add_argument("--since", default="2023-01-01")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--output", type=Path, default=Path("collected_reports"))
    parser.add_argument("--delay", type=float, default=0.75)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    robots: dict[str, urllib.robotparser.RobotFileParser] = {}
    with httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=30) as client:
        discover = discover_mandiant if args.source == "mandiant" else discover_unit42
        candidates = discover(client, args.since)
        for url in candidates:
            if len(records) >= args.limit or not allowed(url, robots):
                continue
            response = client.get(url)
            time.sleep(args.delay)
            if not response.is_success:
                continue
            text, extractor = extract(response.content, response.headers.get("content-type", ""), str(response.url))
            text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
            if len(text.split()) < 800:
                continue
            report_id = f"{args.source}-{len(records) + 1:03d}"
            text_path = args.output / f"{report_id}.txt"
            text_path.write_text(text + "\n", encoding="utf-8")
            records.append({
                "report_id": report_id,
                "requested_url": url,
                "final_url": str(response.url),
                "http_status": response.status_code,
                "content_type": response.headers.get("content-type"),
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "extractor": extractor,
                "raw_sha256": sha256(response.content),
                "text_sha256": sha256(text.encode("utf-8")),
                "text_path": text_path.name,
            })

    manifest = args.output / "manifest.jsonl"
    manifest.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records), encoding="utf-8"
    )
    print(f"Informes preparados: {len(records)}; manifiesto: {manifest}")
    return 0 if records else 1


if __name__ == "__main__":
    raise SystemExit(main())
