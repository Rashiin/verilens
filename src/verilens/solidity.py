"""A lightweight, dependency-free structural model of Solidity source code.

This is *not* a full parser. It recovers just enough structure (contracts,
functions, modifiers, state variables, pragma) for pattern-based detectors to
reason about scope, while keeping every offset aligned with the original text so
that findings can be reported with exact line numbers.

The key trick is ``masked`` text: comments and string literals are replaced by
spaces (newlines are preserved), so regular expressions never match inside them
and character offsets in ``masked`` are identical to offsets in ``text``.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from functools import cached_property

_KEYWORDS = {
    "public",
    "external",
    "internal",
    "private",
    "view",
    "pure",
    "constant",
    "payable",
    "virtual",
    "override",
    "returns",
    "memory",
    "storage",
    "calldata",
    "immutable",
    "anonymous",
    "indexed",
}
_VISIBILITY = ("public", "external", "internal", "private")


def mask_comments_and_strings(text: str) -> str:
    """Blank out comments and string-literal contents, preserving offsets."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        elif c in ("'", '"'):
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def strip_comments(text: str) -> str:
    """Remove comment text (keeping strings and line numbers intact)."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c in ("'", '"'):
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            i = j + 1
        elif c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "\n".join(line.rstrip() for line in "".join(out).split("\n"))


def match_brace(s: str, open_idx: int, open_ch: str = "{", close_ch: str = "}") -> int:
    """Return the index of the bracket closing the one at ``open_idx`` (or len(s))."""
    depth = 0
    for i in range(open_idx, len(s)):
        ch = s[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return len(s)


@dataclass
class StateVar:
    name: str
    type: str
    offset: int


@dataclass
class Function:
    name: str
    kind: str  # function | constructor | fallback | receive | modifier
    contract: Contract
    header: str
    start: int  # offset of the declaration keyword
    body_start: int  # offset of "{" (or -1 when there is no body)
    body_end: int  # offset of matching "}"
    params: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)

    @property
    def has_body(self) -> bool:
        return self.body_start >= 0

    @property
    def visibility(self) -> str:
        for v in _VISIBILITY:
            if re.search(rf"\b{v}\b", self.header):
                return v
        # Solidity < 0.5 defaults to public.
        return "public"

    @property
    def is_public(self) -> bool:
        return self.kind in ("fallback", "receive") or (
            self.kind == "function" and self.visibility in ("public", "external")
        )

    @property
    def is_readonly(self) -> bool:
        return bool(re.search(r"\b(view|pure|constant)\b", self.header))

    @property
    def is_constructor(self) -> bool:
        return self.kind == "constructor"


@dataclass
class Contract:
    name: str
    kind: str  # contract | library | interface
    start: int
    body_start: int
    body_end: int
    bases: list[str] = field(default_factory=list)
    state_vars: list[StateVar] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)

    @property
    def state_var_names(self) -> set[str]:
        return {v.name for v in self.state_vars}

    def modifier(self, name: str) -> Function | None:
        for f in self.functions:
            if f.kind == "modifier" and f.name == name:
                return f
        return None


_CONTRACT_RE = re.compile(r"\b(?:abstract\s+)?(contract|library|interface)\s+([A-Za-z_]\w*)([^{;]*)\{")
_FUNC_RE = re.compile(
    r"\b(?:(function)\s*([A-Za-z_]\w*)?|(constructor)|(fallback)|(receive)|(modifier)\s+([A-Za-z_]\w*))\s*\("
)
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


class SourceUnit:
    """A parsed Solidity file."""

    def __init__(self, text: str, path: str = "<memory>"):
        self.text = text
        self.path = path
        self.masked = mask_comments_and_strings(text)
        self._line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
        self.contracts: list[Contract] = []
        self._parse()

    # ------------------------------------------------------------------ utils
    def line_of(self, offset: int) -> int:
        """1-based line number of a character offset."""
        return bisect.bisect_right(self._line_starts, offset)

    def line_text(self, line: int) -> str:
        lines = self.text.split("\n")
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    @cached_property
    def pragma_min_version(self) -> tuple[int, int, int] | None:
        """Lowest compiler version allowed by the first pragma (best effort)."""
        m = _PRAGMA_RE.search(self.masked)
        if not m:
            return None
        versions = [(int(a), int(b), int(c or 0)) for a, b, c in _VERSION_RE.findall(m.group(1))]
        return min(versions) if versions else None

    @property
    def has_checked_arithmetic(self) -> bool:
        """True when the compiler (>= 0.8) reverts on overflow by default."""
        v = self.pragma_min_version
        return v is not None and v >= (0, 8, 0)

    def functions(self) -> list[Function]:
        return [f for c in self.contracts for f in c.functions]

    def body(self, fn: Function) -> str:
        """Masked body of a function, *including* the braces."""
        if not fn.has_body:
            return ""
        return self.masked[fn.body_start : fn.body_end + 1]

    # ---------------------------------------------------------------- parsing
    def _parse(self) -> None:
        s = self.masked
        pos = 0
        while True:
            m = _CONTRACT_RE.search(s, pos)
            if not m:
                break
            body_start = m.end() - 1
            body_end = match_brace(s, body_start)
            bases = []
            inherit = re.search(r"\bis\b(.*)", m.group(3), re.S)
            if inherit:
                bases = re.findall(r"([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*(?:,|$)", inherit.group(1).strip())
            c = Contract(
                name=m.group(2),
                kind=m.group(1),
                start=m.start(),
                body_start=body_start,
                body_end=body_end,
                bases=bases,
            )
            self._parse_members(c)
            self.contracts.append(c)
            pos = body_end + 1

    def _parse_members(self, c: Contract) -> None:
        s = self.masked
        i = c.body_start + 1
        end = c.body_end
        stmt_start = i
        while i < end:
            ch = s[i]
            m = (
                _FUNC_RE.match(s, i)
                if ch.isalpha() and (i == 0 or not (s[i - 1].isalnum() or s[i - 1] == "_"))
                else None
            )
            if m:
                fn, i = self._parse_function(c, m)
                c.functions.append(fn)
                stmt_start = i
                continue
            if ch == "{":
                # struct / enum / assembly block at contract level: skip it
                i = match_brace(s, i) + 1
                stmt_start = i
                continue
            if ch == ";":
                self._maybe_state_var(c, s[stmt_start:i], stmt_start)
                stmt_start = i + 1
            i += 1

    def _parse_function(self, c: Contract, m: re.Match) -> tuple[Function, int]:
        s = self.masked
        if m.group(1):
            name = m.group(2) or ""
            kind = "function"
            if not name:
                name, kind = "fallback", "fallback"  # pre-0.6 `function () payable`
            elif name == c.name:
                kind = "constructor"  # pre-0.4.22 constructor syntax
        elif m.group(3):
            name, kind = "constructor", "constructor"
        elif m.group(4):
            name, kind = "fallback", "fallback"
        elif m.group(5):
            name, kind = "receive", "receive"
        else:
            name, kind = m.group(7), "modifier"

        paren_open = m.end() - 1
        paren_close = match_brace(s, paren_open, "(", ")")
        params_text = s[paren_open + 1 : paren_close]
        params = []
        for p in params_text.split(","):
            toks = re.findall(r"[A-Za-z_]\w*", p)
            toks = [t for t in toks if t not in _KEYWORDS]
            if len(toks) >= 2:
                params.append(toks[-1])

        # Header runs until the body "{" or a ";" (no body).
        j = paren_close + 1
        while j < len(s) and s[j] not in "{;":
            if s[j] == "(":
                j = match_brace(s, j, "(", ")")
            j += 1
        header = s[m.start() : j]
        tail = s[paren_close + 1 : j]
        tail = re.sub(r"\breturns\s*\([^)]*\)", " ", tail)
        modifiers = [t for t in re.findall(r"\b([A-Za-z_]\w*)\s*(?:\([^)]*\))?", tail) if t not in _KEYWORDS]
        if j < len(s) and s[j] == "{":
            body_start, body_end = j, match_brace(s, j)
            nxt = body_end + 1
        else:
            body_start, body_end = -1, -1
            nxt = j + 1
        fn = Function(
            name=name,
            kind=kind,
            contract=c,
            header=header,
            start=m.start(),
            body_start=body_start,
            body_end=body_end,
            params=params,
            modifiers=modifiers,
        )
        return fn, nxt

    def _maybe_state_var(self, c: Contract, stmt: str, offset: int) -> None:
        stmt = stmt.strip()
        if not stmt or re.match(r"(using|event|error|import|pragma|type)\b", stmt):
            return
        decl = re.split(r"=(?!>)", stmt, maxsplit=1)[0]
        decl = re.sub(r"mapping\s*\(.*\)", "mapping", decl, flags=re.S)
        toks = [t for t in re.findall(r"[A-Za-z_]\w*", decl) if t not in _KEYWORDS]
        if len(toks) >= 2:
            name = toks[-1]
            type_text = decl[: decl.rfind(name)]
            type_text = " ".join(t for t in re.findall(r"[A-Za-z_]\w*|\[[^\]]*\]", type_text) if t not in _KEYWORDS)
            c.state_vars.append(StateVar(name=name, type=type_text, offset=offset))

    def function_at(self, offset: int) -> Function | None:
        for f in self.functions():
            if f.has_body and f.body_start <= offset <= f.body_end:
                return f
        return None


def statement_start(s: str, idx: int, floor: int = 0) -> int:
    """Offset just after the previous statement boundary (``;``, ``{`` or ``}``)."""
    k = idx - 1
    while k >= floor and s[k] not in ";{}":
        k -= 1
    return k + 1


def statement_end(s: str, idx: int) -> int:
    """Offset of the ``;`` ending the statement that contains ``idx``."""
    depth = 0
    for k in range(idx, len(s)):
        ch = s[k]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == ";" and depth <= 0:
            return k
        elif ch in "{}" and depth <= 0:
            return k
    return len(s)
