"""Tests for :func:`django_saml2_auth.get_path.get_path`."""

import pytest

from django_saml2_auth.get_path import get_path


@pytest.mark.parametrize(
    ("data", "path", "default", "pathsep", "expected"),
    [
        ({}, "a", "DEF", ".", "DEF"),
        ({"a": 1}, "a", None, ".", 1),
        ({"a": {"b": 2}}, "a.b", None, ".", 2),
        ({"a": {"b": None}}, "a.b", "DEF", ".", None),
        ({"next": ["http://x"]}, "next.0", None, ".", "http://x"),
        ({"x": [{"y": 1}]}, "x.0.y", None, ".", 1),
        ({"0": "letter"}, "0", None, ".", "letter"),
        ({"user.email": ["e@example.com"]}, "user.email|0", None, "|", "e@example.com"),
        ({"a": {"b": 1}}, "a..b", "DEF", ".", "DEF"),
    ],
)
def test_get_path_parametrized(
    data: object,
    path: str,
    default: object,
    pathsep: str,
    expected: object,
) -> None:
    assert get_path(data, path, default, pathsep=pathsep) == expected


def test_get_path_empty_path_returns_default() -> None:
    assert get_path({"a": 1}, "", "MISSING") == "MISSING"


def test_get_path_out_of_range_list_returns_default() -> None:
    assert get_path({"x": ["a"]}, "x.1", "DEF") == "DEF"


def test_get_path_non_digit_segment_on_list_returns_default() -> None:
    assert get_path({"x": ["a"]}, "x.foo", "DEF") == "DEF"


def test_get_path_string_not_traversable_returns_default() -> None:
    assert get_path({"a": "s"}, "a.b", "DEF") == "DEF"


def test_get_path_leading_zero_index() -> None:
    assert get_path({"x": ["a", "b"]}, "x.01", None) == "b"


def test_get_path_negative_list_index_matches_int_semantics() -> None:
    assert get_path([1, 2, 3], "-1", None) == 3
    assert get_path({"x": [10, 20]}, "x.-1", None) == 20


def test_get_path_explicit_sign_list_index() -> None:
    assert get_path([1, 2, 3], "+1", None) == 2


def test_get_path_pipe_separator_preserves_dots_in_keys() -> None:
    data = {"user.email": ["value"]}
    assert get_path(data, "user.email|0", None, pathsep="|") == "value"


def test_get_path_non_container_leaf_returns_default() -> None:
    assert get_path({"a": 42}, "a.b", "DEF") == "DEF"
