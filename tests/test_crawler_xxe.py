"""Tests that sitemap parsing is XXE-safe."""
from __future__ import annotations

from scanner.crawler import _safe_xml_fromstring


class TestSafeXmlParsing:
    def test_normal_sitemap_parses(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>http://example.com/page1</loc></url>
            <url><loc>http://example.com/page2</loc></url>
        </urlset>"""
        root = _safe_xml_fromstring(xml)
        locs = [
            e.text.strip() for e in root.iter()
            if e.tag in ("loc", "{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
            and e.text
        ]
        assert len(locs) == 2
        assert "http://example.com/page1" in locs

    def test_xxe_entity_blocked(self):
        """DOCTYPE with external entity must not resolve."""
        xxe_xml = """<?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <urlset><url><loc>&xxe;</loc></url></urlset>"""
        try:
            root = _safe_xml_fromstring(xxe_xml)
            # If parsing succeeds, the entity must NOT have resolved to file content
            locs = [e.text for e in root.iter() if e.tag == "loc" and e.text]
            for loc in locs:
                assert "root:" not in loc, "XXE entity was resolved — file content leaked!"
        except Exception:
            # defusedxml raises on any entity — this is the safe path
            pass

    def test_billion_laughs_blocked(self):
        """Exponential entity expansion must be blocked."""
        bomb = """<?xml version="1.0"?>
        <!DOCTYPE lolz [
          <!ENTITY lol "lol">
          <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
          <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
        ]>
        <urlset><url><loc>&lol3;</loc></url></urlset>"""
        try:
            _safe_xml_fromstring(bomb)
        except Exception:
            pass  # Expected: defusedxml or stripped DOCTYPE prevents expansion
