"""Extracts readable text from CTI reports (PDF, HTML, plain text/markdown)
so they can be turned into a CIR by the LLM pipeline."""

from __future__ import annotations

import io
import re
from html.parser import HTMLParser

MAX_DOCUMENT_BYTES = 20 * 1024 * 1024
MAX_PDF_PAGES = 150
# What is sent to the LLM; long reports are truncated (the attack chain is
# usually described in the first sections).
MAX_TEXT_CHARS = 30_000


class DocumentError(ValueError):
    pass


class _TextExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "template", "nav", "footer", "header", "form", "iframe"}
    BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "section", "article", "td", "th", "code"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.main_parts: list[str] = []
        self.title = ""
        self._skip = 0
        self._main = 0
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip += 1
        elif tag in ("article", "main"):
            self._main += 1
        elif tag == "title":
            self._in_title = True
        if tag in self.BLOCK:
            self._emit("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        elif tag in ("article", "main") and self._main:
            self._main -= 1
        elif tag == "title":
            self._in_title = False
        if tag in self.BLOCK:
            self._emit("\n")

    def handle_data(self, data):
        if self._in_title:
            self.title += data
            return
        if not self._skip:
            self._emit(data)

    def _emit(self, text: str) -> None:
        self.parts.append(text)
        if self._main:
            self.main_parts.append(text)


def _clean(text: str) -> str:
    text = text.replace("\x00", "")
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip()


def html_to_text(html: str) -> tuple[str, str]:
    """Returns (title, text). Prefers <article>/<main> content when present."""
    parser = _TextExtractor()
    parser.feed(html)
    parser.close()
    main = _clean("".join(parser.main_parts))
    body = main if len(main) > 500 else _clean("".join(parser.parts))
    return _clean(parser.title), body


def pdf_to_text(data: bytes) -> str:
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError

    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted and not reader.decrypt(""):
            raise DocumentError("Encrypted PDFs are not supported")
        if len(reader.pages) > MAX_PDF_PAGES:
            raise DocumentError(f"PDF has more than {MAX_PDF_PAGES} pages")
        pages = []
        total = 0
        for page in reader.pages:
            text = page.extract_text() or ""
            pages.append(text)
            total += len(text)
            if total > MAX_TEXT_CHARS * 2:
                break
    except DocumentError:
        raise
    except (PdfReadError, ValueError, KeyError, TypeError, RecursionError) as error:
        raise DocumentError(f"Could not read PDF: {type(error).__name__}") from error
    return _clean("\n\n".join(pages))


def _decode(data: bytes, content_type: str = "") -> str:
    match = re.search(r"charset=([\w-]+)", content_type)
    for encoding in filter(None, [match.group(1) if match else None, "utf-8"]):
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("latin-1")


def extract_text(data: bytes, filename: str = "", content_type: str = "") -> tuple[str, str]:
    """Returns (title, text) for a PDF / HTML / text document."""
    if len(data) > MAX_DOCUMENT_BYTES:
        raise DocumentError(f"Document exceeds {MAX_DOCUMENT_BYTES // (1024 * 1024)} MB")
    lowered = filename.lower()
    if data[:5] == b"%PDF-" or lowered.endswith(".pdf") or "application/pdf" in content_type:
        title, text = filename, pdf_to_text(data)
    else:
        decoded = _decode(data, content_type)
        if "html" in content_type or lowered.endswith((".html", ".htm")) or re.search(r"<html|<body|<article", decoded[:5000], re.I):
            title, text = html_to_text(decoded)
        else:
            title, text = filename, _clean(decoded)
    if len(text) < 80:
        raise DocumentError("Not enough readable text in the document (scanned PDF or empty page?)")
    return title, text


def truncate_for_llm(text: str) -> tuple[str, bool]:
    if len(text) <= MAX_TEXT_CHARS:
        return text, False
    cut = text[:MAX_TEXT_CHARS]
    boundary = cut.rfind("\n\n")
    return (cut[:boundary] if boundary > MAX_TEXT_CHARS * 0.8 else cut), True
