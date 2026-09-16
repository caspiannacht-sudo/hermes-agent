"""Target-direct text extraction; no remote scraper, proxy, redirect or rescue.

10s is an HTTP I/O timeout, not a total page deadline (DNS may take longer).
The decoded body is capped at 2 MiB. Compressed responses are refused before
iteration, avoiding a decompressor expansion allocation ahead of the counter.
HTML is rendered as text, not markdown; scripts/styles/refresh are not executed.
"""
from html.parser import HTMLParser
from urllib.parse import urlsplit

from agent.web_search_provider import WebSearchProvider

MAX_BODY_BYTES = 2 * 1024 * 1024
IO_TIMEOUT_SECONDS = 10.0


class _PageText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.title = [], []
        self.hidden = []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "template", "noscript"}:
            self.hidden.append(tag)
        if tag == "title":
            self.in_title = True
        if not self.hidden and tag in {"p", "div", "br", "li", "h1", "h2", "h3", "tr", "section"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if self.hidden and tag == self.hidden[-1]:
            self.hidden.pop()
        if tag == "title":
            self.in_title = False
        if not self.hidden and tag in {"p", "div", "li", "h1", "h2", "h3", "tr", "section"}:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            (self.title if self.in_title else self.parts).append(data)

    def text(self):
        return "\n".join(" ".join(line.split()) for line in "".join(self.parts).splitlines() if line.strip())


class DirectWebProvider(WebSearchProvider):
    name = "direct"
    display_name = "Direct HTTP (text/HTML only)"

    def is_available(self):
        from importlib.util import find_spec
        return find_spec("httpx") is not None

    def supports_search(self):
        return False

    def supports_extract(self):
        return True

    def extract(self, urls, **kwargs):
        return [self._extract_one(url) for url in urls]

    def _extract_one(self, url):
        from tools.web_tools_extract import _validate_extract_urls, _result_entry
        from tools.web_tools_policy import website_denial
        from tools.url_safety import create_ssrf_safe_client, is_safe_url, sensitive_query_param_name
        import httpx
        result = _result_entry(url, None)
        try:
            normalized, _, invalid, blocked = _validate_extract_urls([url])
            if blocked or invalid:
                raise ValueError("Blocked: invalid or secret-bearing URL")
            url = normalized[0]
            parsed = urlsplit(url)
            if parsed.username is not None or parsed.password is not None or sensitive_query_param_name(url):
                raise ValueError("Blocked: credential-bearing URL")
            denial = website_denial(url)
            if denial is not None:
                result.update(error=denial.get("message", "Blocked by website policy"), blocked_by_policy=denial)
                return result
            # Serialize the engine's builtin-IDNA authority, not HTTPX's Unicode
            # authority (UTS46 can select a different DNS name, e.g. sharp-s).
            from tools.website_policy import _extract_host_from_urlish
            from urllib.parse import urlunsplit
            host = _extract_host_from_urlish(url)
            authority = "[" + host + "]" if ":" in host else host
            if parsed.port is not None:
                authority += ":" + str(parsed.port)
            canonical = urlunsplit((parsed.scheme, authority, parsed.path, parsed.query, ""))
            effective = httpx.URL(canonical)
            if effective.raw_host.decode("ascii") != host:
                raise ValueError("Blocked: ambiguous serialized request hostname")
            denial = website_denial(str(effective))
            if denial is not None:
                result.update(error=denial.get("message", "Blocked by website policy"), blocked_by_policy=denial)
                return result
            if not is_safe_url(str(effective)):
                raise ValueError("Blocked: URL targets a private or internal network address")
            url = effective  # Send the exact checked HTTPX URL object.
            # A fresh client per URL prevents cookies/auth crossing origins. No
            # user supplied client, mounts or proxy; connect-time guard is intact.
            with create_ssrf_safe_client(trust_env=False, follow_redirects=False,
                                        timeout=httpx.Timeout(IO_TIMEOUT_SECONDS),
                                        headers={"Accept": "text/html, text/plain", "Accept-Encoding": "identity"}) as client:
                with client.stream("GET", url) as response:
                    if 300 <= response.status_code < 400:
                        raise ValueError("Direct extraction refuses all redirects")
                    response.raise_for_status()
                    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    if content_type not in {"text/html", "text/plain"}:
                        raise ValueError("Direct extraction supports text/html and text/plain only (no PDF/binary)")
                    if response.headers.get("content-encoding", "identity").strip().lower() not in {"", "identity"}:
                        raise ValueError("Direct extraction refuses compressed content")
                    body = bytearray()
                    for chunk in response.iter_bytes(chunk_size=16384):
                        if len(body) + len(chunk) > MAX_BODY_BYTES:
                            raise ValueError("Direct extraction body exceeds decoded byte limit")
                        body.extend(chunk)
                    text = body.decode(response.encoding or "utf-8", errors="replace")
                    if "\x00" in text:
                        raise ValueError("Direct extraction refuses binary content")
            if content_type == "text/html":
                parser = _PageText()
                parser.feed(text)
                parser.close()
                result["title"] = " ".join("".join(parser.title).split())
                text = parser.text()
            result.update(content=text, raw_content=text)
        except Exception as exc:
            # Do not include exception URLs/headers/body in diagnostics.
            from tools.url_safety import SSRFConnectionBlocked
            if isinstance(exc, SSRFConnectionBlocked):
                result["error"] = "Blocked: SSRF connect-time safety refusal"
            elif isinstance(exc, ValueError):
                result["error"] = str(exc)
            else:
                result["error"] = "Direct extraction failed (HTTP, decoding or I/O error)"
        return result
