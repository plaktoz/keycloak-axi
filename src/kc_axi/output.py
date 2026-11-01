"""Output encoders (spec sections 4.3 and 4.5).

A list of rows is a `Records` value, or a plain list of mappings. The compact form prints a header
`key[shown of total]{columns}:` and one CSV row per record. The JSON form prints the same rows with full values.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TextIO

from .errors import KcAxiError

SCHEMA_VERSION = 1
DEFAULT_LIMIT = 20
MAX_CELL_CHARS = 200


@dataclass(frozen=True)
class Records:
    """Rows of one list. `items` holds the rows shown. `total` counts every row."""

    items: tuple[Mapping[str, Any], ...]
    total: int
    columns: tuple[str, ...]

    @property
    def shown(self) -> int:
        return len(self.items)


def resolve_limit(value: int | None) -> int:
    """`--limit` must be 1 or more. Without the flag, the default of section 4.5 applies."""
    if value is None:
        return DEFAULT_LIMIT
    if value < 1:
        raise KcAxiError("flag_not_valid", f"--limit must be 1 or more, got {value}")
    return value


def page(rows: Iterable[Mapping[str, Any]], *, columns: Sequence[str] | None = None, limit: int | None = None) -> Records:
    """Cut `rows` to `limit`. `limit=None` shows every row, as `plan` and `apply` do (section 4.3)."""
    rows = list(rows)
    cols = tuple(columns) if columns is not None else _union_keys(rows)
    shown = rows if limit is None else rows[:limit]
    return Records(items=tuple(shown), total=len(rows), columns=cols)


def list_payload(
    kind: str,
    rows: Iterable[Mapping[str, Any]],
    *,
    columns: Sequence[str],
    checked: str,
    limit: int = DEFAULT_LIMIT,
    more_help: str | None = None,
) -> dict[str, Any]:
    """A read result (section 4.3). An empty list says what it checked. A cut list names the next command."""
    rows = list(rows)
    if not rows:
        return {"status": "empty", "total": 0, "items": Records((), 0, tuple(columns)), kind: f"none ({checked})"}
    records = page(rows, columns=columns, limit=limit)
    payload: dict[str, Any] = {"status": "active", "total": records.total, "items": records}
    if records.shown < records.total and more_help:
        payload["help"] = [more_help]
    return payload


def _union_keys(rows: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for row in rows:
        for key in row:
            seen.setdefault(key, None)
    return tuple(seen)


def _scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return " ".join(str(value).split("\n"))


def _cell(value: Any, limit: int = MAX_CELL_CHARS) -> str:
    """One compact value on one line. A value longer than `limit` is cut (section 4.5, rule 1)."""
    text = _scalar(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}… ({len(text)} chars total)"


def _csv_row(cells: Sequence[str]) -> str:
    """CSV quoting keeps a comma, a space or a quote inside one cell, so the row still parses."""
    buf = io.StringIO()
    csv.writer(buf, lineterminator="").writerow(cells)
    return buf.getvalue()


def _records_block(key: str, records: Records, limit: int) -> list[str]:
    lines = [f"{key}[{records.shown} of {records.total}]{{{','.join(records.columns)}}}:"]
    for row in records.items:
        lines.append("  " + _csv_row([_cell(row[c], limit) if c in row else "" for c in records.columns]))
    return lines


def render_compact(data: Mapping[str, Any], max_cell_chars: int = MAX_CELL_CHARS) -> str:
    """The default view: `key: value` lines, a `key[N]:` block of text, and a `key[shown of total]{...}:` block of rows.

    Rows must arrive as `Records` (see `page`), so every list states its count. A `Records` value with no rows
    prints nothing. Its empty note, set by `list_payload`, says why.
    """
    lines: list[str] = []
    for key, value in data.items():
        if isinstance(value, Records):
            if value.total:
                lines.extend(_records_block(key, value, max_cell_chars))
        elif isinstance(value, Sequence) and not isinstance(value, str):
            if any(isinstance(item, Mapping) for item in value):
                raise TypeError(f"{key}: wrap rows with page() so the list states shown of total")
            lines.append(f"{key}[{len(value)}]:")
            for item in value:
                lines.append(f"  {item}")
        else:
            lines.append(f"{key}: {_cell(value, max_cell_chars)}")
    return "\n".join(lines)


def _json_ready(value: Any) -> Any:
    if isinstance(value, Records):
        return [{c: row[c] for c in value.columns if c in row} for row in value.items]
    return value


def render_json(data: Mapping[str, Any]) -> str:
    """Full values. Each `Records` value adds `shown` (section 4.3 keys) if the result has none."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        out[key] = _json_ready(value)
        if isinstance(value, Records):
            out.setdefault("shown", value.shown)
    return json.dumps(out, ensure_ascii=False)


def emit(data: Mapping[str, Any], *, as_json: bool, stream: TextIO, max_cell_chars: int = MAX_CELL_CHARS) -> None:
    """Write one result. `data` holds the default-view keys. JSON adds `schema_version` and `command`."""
    if as_json:
        print(render_json(data), file=stream)
    else:
        print(render_compact(data, max_cell_chars), file=stream)


def result_payload(command: str, body: Mapping[str, Any], *, as_json: bool) -> dict[str, Any]:
    if as_json:
        return {"schema_version": SCHEMA_VERSION, "command": command, **body}
    return dict(body)


def error_payload(err: KcAxiError, command: str, *, as_json: bool) -> dict[str, Any]:
    """Errors go to stdout in the same form as results (spec 4.3, 4.5 rule 5). `err.fields` add keys such as `refusals`."""
    if as_json:
        error: dict[str, Any] = {"code": err.code, "message": err.message, "help": "\n".join(err.help)}
        error.update({key: _json_ready(value) for key, value in err.fields.items()})
        return {"schema_version": SCHEMA_VERSION, "command": command, "error": error}
    payload: dict[str, Any] = {"error": err.code, "message": err.message}
    payload.update(err.fields)
    if err.help:
        payload["help"] = list(err.help[:3])
    return payload
