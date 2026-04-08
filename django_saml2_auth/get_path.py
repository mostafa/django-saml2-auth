"""Safe lookup of values in nested JSON-like structures by string path.

Use :func:`get_path` to walk arbitrary nesting of mappings (e.g. ``dict``) and
sequences (e.g. ``list``, ``tuple``)—for example Django settings or SAML attribute
dictionaries. Split the path with ``pathsep`` (default ``"."``); use another
separator such as ``"|"`` when a single segment must contain dots (e.g. a key
named ``user.email`` followed by a list index).

Traversal order differs from ``dictor`` 0.1.12's ``_findval``: we test
:class:`~collections.abc.Mapping` before sequences, whereas ``dictor`` tests
``list``/``tuple`` first; both agree on ordinary ``dict``/``list`` nesting.
Features not carried over (unused here): ``ignorecase``, ``search``, backslash-escaped
dots in the path, ``checknone``, ``rtype``, and ``pretty``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

__all__ = ["get_path"]


def get_path(
    data: Any,
    path: str,
    default: Any = None,
    *,
    pathsep: str = ".",
) -> Any:
    """Return the value at ``path`` in nested ``data``, or ``default`` if any segment is missing.

    * ``path`` is split on ``pathsep`` (``"."`` by default, or e.g. ``"|"`` when keys contain dots).
    * If the current value is a :class:`~collections.abc.Mapping`, the segment is used as a
      string key (including keys that look numeric, e.g. ``"0"``).
    * Otherwise, if the current value is a :class:`~collections.abc.Sequence` and not
      :class:`str` or :class:`bytes`, the segment is parsed with :func:`int` and used as an index
      (including negatives and signs, e.g. ``"-1"``, ``"+1"``, ``"01"``). Out-of-range indices
      yield ``default``.
    * If a key is missing or an index is out of range, ``default`` is returned.
    * If the path resolves successfully and the value is ``None``, ``None`` is returned
      (``default`` is not substituted).

    Args:
        data: Root object (typically a ``dict``).
        path: Path string; use ``pathsep`` to split segments.
        default: Value to return when the path cannot be resolved.
        pathsep: Separator between segments (``"."`` or ``"|"``).

    Returns:
        The resolved value, or ``default``.
    """
    if path is None or path == "":
        return default

    current: Any = data
    for part in path.split(pathsep):
        match current:
            case Mapping():
                if part not in current:
                    return default
                current = current[part]
            case str() | bytes():
                return default
            case Sequence():
                try:
                    idx = int(part)
                except ValueError:
                    return default
                try:
                    current = current[idx]
                except IndexError:
                    return default
            case _:
                return default

    return current
