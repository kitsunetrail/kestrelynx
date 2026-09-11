"""Check hreflang and language selectors after building both sites.

Usage: python scripts/check_doc_alternates.py site
Build English into site/ and Japanese into site/ja/ before running this.
"""

from html.parser import HTMLParser
from pathlib import Path
import sys
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET


class PageLinks(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.language = None
        self.canonical = []
        self.alternates = {}
        self.selector = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "html":
            self.language = attrs.get("lang")
        if tag == "link" and attrs.get("rel") == "canonical":
            self.canonical.append(attrs["href"])
        if tag == "link" and attrs.get("rel") == "alternate" and "hreflang" in attrs:
            language = attrs["hreflang"]
            assert language not in self.alternates, f"Duplicate hreflang: {language}"
            self.alternates[language] = attrs["href"]
        if tag == "a" and "md-select__link" in attrs.get("class", "").split():
            self.selector[attrs["hreflang"]] = attrs["href"]


def main(site_dir):
    pages = {}
    for sitemap in (site_dir / "sitemap.xml", site_dir / "ja/sitemap.xml"):
        urls = ET.parse(sitemap).findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
        assert urls, f"Empty sitemap: {sitemap}"
        for entry in urls:
            url = entry.text
            output = site_dir / urlsplit(url).path.lstrip("/")
            if output.is_dir():
                output /= "index.html"
            pages[url] = PageLinks(output.read_text())

    for url, page in pages.items():
        assert page.canonical == [url], f"Incorrect canonical: {url}"
        assert page.alternates.get(page.language) == url, f"Missing self hreflang: {url}"
        assert page.selector == page.alternates, f"Language selector differs: {url}"
        for language, target in page.alternates.items():
            assert target in pages, f"Missing translation: {url} -> {target}"
            translation = pages[target]
            assert translation.language == language, f"Wrong language: {target}"
            assert translation.alternates == page.alternates, f"Nonreciprocal translations: {url} -> {target}"

    for output in (site_dir / "404.html", site_dir / "ja/404.html"):
        assert not PageLinks(output.read_text()).alternates, f"Unexpected hreflang: {output}"

    print(f"Verified canonical URLs, reciprocal hreflang, and language selectors on {len(pages)} pages.")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "site"))
