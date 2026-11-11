"""A JSON reader that remembers where every value came from.

``json.loads`` gives you a dict and throws the bytes away. A policy reviewer
cannot work like that: "line 14, the Action list" is the whole difference
between a finding somebody fixes and a finding somebody argues about. This
module is a hand-written recursive-descent parser (stdlib only) that keeps, for
every value, its line, its column and its JSON Pointer.

It is deliberately stricter than the Python ``json`` module about the things
AWS IAM also rejects, and reports them with a location instead of a bare
"Expecting property name enclosed in double quotes":

* duplicate keys in one object (JSON allows them, IAM silently keeps the last)
* trailing commas, ``//`` and ``/* */`` comments, single-quoted strings

Complexity is O(n) in the input; positions come from a line-start table built
once, so ``line_col(index)`` is a binary search rather than a rescan.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Any

# RFC 8259 number grammar, enforced in full: the scanner is greedy so that
# `1-2` stops at the right place, but `01` and `5.` are not JSON (AWS rejects
# them too) and must not parse as 1 and 5.0.
_JSON_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?\Z")


class JsonError(Exception):
    """A syntax-level problem, carrying the byte address of the offending token."""

    def __init__(self, message: str, line: int, col: int) -> None:
        super().__init__(f"{message} (line {line}, column {col})")
        self.message = message
        self.line = line
        self.col = col


@dataclass
class Node:
    """A parsed value plus its address."""

    value: Any
    line: int
    col: int
    path: str = ""
    # Only meaningful when this node is an object member: where the key token is.
    key_line: int = 0
    key_col: int = 0
    # Array elements / object member values, in document order.
    items: list[Node] = field(default_factory=list)
    # For objects: member name -> (line, col) of the key token.
    keys: dict[str, tuple[int, int]] = field(default_factory=dict)
    # Keys seen more than once in this object: (name, line, col) of each extra one.
    dupes: list[tuple[str, int, int]] = field(default_factory=list)

    def get(self, name: str) -> Node | None:
        """Look up an object member by name, case-insensitively.

        IAM treats ``Statement`` and ``statement`` the same in practice, and a
        policy written by a human will eventually contain ``statement``.
        """
        if not isinstance(self.value, dict):
            return None
        for key, node in self._members().items():
            if key.lower() == name.lower():
                return node
        return None

    def _members(self) -> dict[str, Node]:
        out: dict[str, Node] = {}
        for node in self.items:
            name = _member_name(node)
            if name is not None:
                out[name] = node
        return out

    def member(self, name: str) -> Node | None:
        return self.get(name)

    def is_object(self) -> bool:
        return isinstance(self.value, dict)

    def is_array(self) -> bool:
        return isinstance(self.value, list)

    def is_str(self) -> bool:
        return isinstance(self.value, str)


def _member_name(node: Node) -> str | None:
    # A member node stores its own name in ``path`` after the last slash.
    if not node.path:
        return None
    return node.path.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")


_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.i = 0
        self.n = len(text)
        self._starts = [0]
        for idx, ch in enumerate(text):  # line-start table, built once
            if ch == "\n":
                self._starts.append(idx + 1)

    # -- position helpers ------------------------------------------------
    def line_col(self, index: int) -> tuple[int, int]:
        line = bisect.bisect_right(self._starts, index)
        return line, index - self._starts[line - 1] + 1

    def fail(self, message: str, index: int | None = None) -> JsonError:
        idx = self.i if index is None else index
        line, col = self.line_col(min(idx, self.n))
        return JsonError(message, line, col)

    # -- scanning --------------------------------------------------------
    def ws(self) -> None:
        while self.i < self.n:
            ch = self.text[self.i]
            if ch in " \t\r\n":
                self.i += 1
            elif ch == "/" and self.i + 1 < self.n:
                nxt = self.text[self.i + 1]
                if nxt == "/":
                    raise self.fail("comments are not valid JSON (AWS rejects them)")
                if nxt == "*":
                    raise self.fail("comments are not valid JSON (AWS rejects them)")
                raise self.fail("unexpected '/'")
            else:
                return

    def peek(self) -> str:
        return self.text[self.i] if self.i < self.n else ""

    def expect(self, ch: str) -> None:
        if self.peek() != ch:
            raise self.fail(f"expected {ch!r}")
        self.i += 1

    # -- grammar ---------------------------------------------------------
    def parse(self) -> Node:
        self.ws()
        if self.i >= self.n:
            raise self.fail("empty document")
        node = self.value("")
        self.ws()
        if self.i < self.n:
            raise self.fail("trailing content after the document")
        return node

    def value(self, path: str) -> Node:
        ch = self.peek()
        if ch == "{":
            return self.obj(path)
        if ch == "[":
            return self.arr(path)
        if ch == '"':
            return self.string(path)
        if ch == "'":
            raise self.fail("single-quoted strings are not valid JSON")
        if ch == "t":
            return self.literal("true", True, path)
        if ch == "f":
            return self.literal("false", False, path)
        if ch == "n":
            return self.literal("null", None, path)
        if ch == "-" or ch.isdigit():
            return self.number(path)
        raise self.fail("unexpected character")

    def literal(self, word: str, val: Any, path: str) -> Node:
        line, col = self.line_col(self.i)
        if self.text[self.i : self.i + len(word)] != word:
            raise self.fail(f"expected {word!r}")
        self.i += len(word)
        return Node(val, line, col, path)

    def number(self, path: str) -> Node:
        line, col = self.line_col(self.i)
        start = self.i
        if self.peek() == "-":
            self.i += 1
        while self.i < self.n and (self.text[self.i].isdigit() or self.text[self.i] in ".eE+-"):
            # A bare scanner would swallow '1-2'; the int/float call below is the
            # real validator, so an impossible number surfaces exactly here.
            self.i += 1
        raw = self.text[start : self.i]
        if not _JSON_NUMBER.match(raw):
            # point at the start of the number, where the violation begins
            raise self.fail(f"malformed number: {raw}", index=start)
        val: Any = int(raw) if "." not in raw and "e" not in raw and "E" not in raw else float(raw)
        return Node(val, line, col, path)

    def string(self, path: str) -> Node:
        line, col = self.line_col(self.i)
        self.expect('"')
        out: list[str] = []
        while True:
            if self.i >= self.n:
                raise self.fail("unterminated string")
            ch = self.text[self.i]
            if ch == '"':
                self.i += 1
                break
            if ch == "\\":
                self.i += 1
                if self.i >= self.n:
                    raise self.fail("unterminated escape")
                esc = self.text[self.i]
                if esc == "u":
                    hexpart = self.text[self.i + 1 : self.i + 5]
                    if len(hexpart) < 4:
                        raise self.fail("truncated \\u escape")
                    try:
                        code = int(hexpart, 16)
                    except ValueError as exc:
                        raise self.fail(f"bad \\u escape: {hexpart}") from exc
                    self.i += 5
                    # A high surrogate immediately followed by its low
                    # surrogate is one astral character. Emitting two lone
                    # surrogates instead would crash every later
                    # .encode("utf-8") on this value (SARIF and JSON reports
                    # both encode it), while json.loads pairs them.
                    if 0xD800 <= code <= 0xDBFF and self.text[self.i : self.i + 2] == "\\u":
                        low_hex = self.text[self.i + 2 : self.i + 6]
                        try:
                            low = int(low_hex, 16)
                        except ValueError:
                            low = -1
                        if 0xDC00 <= low <= 0xDFFF:
                            self.i += 6
                            code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                    out.append(chr(code))
                    continue
                if esc not in _ESCAPES:
                    raise self.fail(f"unknown escape: \\{esc}")
                out.append(_ESCAPES[esc])
                self.i += 1
                continue
            if ch == "\n":
                raise self.fail("raw newline inside a string")
            out.append(ch)
            self.i += 1
        return Node("".join(out), line, col, path)

    def obj(self, path: str) -> Node:
        line, col = self.line_col(self.i)
        self.expect("{")
        out: dict[str, Any] = {}
        items: list[Node] = []
        keys: dict[str, tuple[int, int]] = {}
        dupes: list[tuple[str, int, int]] = []
        self.ws()
        if self.peek() == "}":
            self.i += 1
            return Node(out, line, col, path, items=items, keys=keys, dupes=dupes)
        while True:
            self.ws()
            if self.peek() == "}":
                # A trailing comma is the single most common hand-written-policy
                # defect; name it instead of "expecting property name".
                raise self.fail("trailing comma before '}'")
            if self.peek() != '"':
                raise self.fail("object keys must be double-quoted strings")
            kline, kcol = self.line_col(self.i)
            key_node = self.string("")
            key = key_node.value
            self.ws()
            if self.peek() != ":":
                raise self.fail("expected ':' after an object key")
            self.i += 1
            self.ws()
            child_path = f"{path}/{key.replace('~', '~0').replace('/', '~1')}"
            child = self.value(child_path)
            child.key_line, child.key_col = kline, kcol
            if key in keys:
                dupes.append((key, kline, kcol))
            keys[key] = (kline, kcol)
            out[key] = child.value
            items.append(child)
            self.ws()
            ch = self.peek()
            if ch == ",":
                self.i += 1
                continue
            if ch == "}":
                self.i += 1
                break
            raise self.fail("expected ',' or '}'")
        return Node(out, line, col, path, items=items, keys=keys, dupes=dupes)

    def arr(self, path: str) -> Node:
        line, col = self.line_col(self.i)
        self.expect("[")
        out: list[Any] = []
        items: list[Node] = []
        self.ws()
        if self.peek() == "]":
            self.i += 1
            return Node(out, line, col, path, items=items)
        index = 0
        while True:
            self.ws()
            if self.peek() == "]":
                raise self.fail("trailing comma before ']'")
            child = self.value(f"{path}/{index}")
            out.append(child.value)
            items.append(child)
            index += 1
            self.ws()
            ch = self.peek()
            if ch == ",":
                self.i += 1
                continue
            if ch == "]":
                self.i += 1
                break
            raise self.fail("expected ',' or ']'")
        return Node(out, line, col, path, items=items)


def loads(text: str) -> Node:
    """Parse ``text`` into a :class:`Node` tree, or raise :class:`JsonError`."""
    return _Parser(text).parse()


def pointer_escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def snippet(text: str, line: int, col: int, width: int = 96) -> str:
    """The source line a finding points at, trimmed to something terminal-width."""
    lines = text.splitlines()
    if not 1 <= line <= len(lines):
        return ""
    raw = lines[line - 1]
    if len(raw) <= width:
        return raw.strip()
    start = max(0, min(col - 1, len(raw) - width))
    return raw[start : start + width].strip()
