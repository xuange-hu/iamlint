"""The parser is the foundation: if the addresses are wrong, every finding lies."""

from __future__ import annotations

import pytest

from iamlint.jsonloc import JsonError, loads, snippet


def test_scalars_keep_their_address():
    node = loads('{\n  "a": 1,\n  "b": true,\n  "c": null\n}')
    values = node.value
    assert values == {"a": 1, "b": True, "c": None}
    by_key = {n.path.rsplit("/", 1)[-1]: n for n in node.items}
    assert by_key["a"].line == 2
    assert by_key["b"].line == 3
    assert by_key["c"].line == 4


def test_object_keys_carry_the_key_token_position():
    text = '{\n  "Sid": "x"\n}'
    node = loads(text)
    member = node.items[0]
    assert member.key_line == 2
    assert member.key_col == 3


def test_nested_arrays_get_pointers():
    node = loads('{"Statement": [{"Action": ["a", "b"]}]}')
    action = node.get("Statement").items[0].get("Action")
    assert action.path == "/Statement/0/Action"
    assert [n.path for n in action.items] == ["/Statement/0/Action/0", "/Statement/0/Action/1"]
    assert action.value == ["a", "b"]


def test_member_lookup_is_case_insensitive():
    node = loads('{"statement": [{"effect": "Allow"}]}')
    assert node.get("Statement") is not None
    assert node.get("Statement").items[0].get("Effect").value == "Allow"


def test_escapes_and_unicode():
    node = loads('{"a": "line\\nbreak \\u00e9 \\"q\\" \\\\ tab\\t"}')
    assert node.value["a"] == 'line\nbreak \u00e9 "q" \\ tab\t'


def test_numbers_int_and_float():
    node = loads('{"i": 12, "f": 1.5, "e": 1e3, "neg": -2}')
    assert node.value == {"i": 12, "f": 1.5, "e": 1000.0, "neg": -2}


def test_duplicate_keys_are_recorded_not_ignored():
    node = loads('{\n  "Id": "first",\n  "Id": "second"\n}')
    assert node.value["Id"] == "second"
    assert node.dupes == [("Id", 3, 3)]


def test_duplicate_keys_are_found_in_nested_objects():
    node = loads('{"S": [{"Action": "a", "Action": "b"}]}')
    assert node.items[0].items[0].dupes == [("Action", 1, 24)]


def test_trailing_comma_is_reported_with_a_location():
    with pytest.raises(JsonError) as exc:
        loads('{\n  "a": 1,\n}')
    assert "trailing comma" in str(exc.value)
    assert exc.value.line == 3


def test_comments_are_rejected():
    for text in ('{\n // hi\n "a": 1}', '{\n /* hi */ "a": 1}'):
        with pytest.raises(JsonError) as exc:
            loads(text)
        assert "comment" in str(exc.value)


def test_single_quotes_are_rejected():
    with pytest.raises(JsonError) as exc:
        loads("{\"a\": 'b'}")
    assert "single-quoted" in str(exc.value)
    with pytest.raises(JsonError):
        loads("{'a': 1}")


def test_unterminated_string_reports_its_start():
    with pytest.raises(JsonError) as exc:
        loads('{\n  "a": "oops')
    assert "unterminated" in str(exc.value)


def test_empty_document_and_trailing_content():
    with pytest.raises(JsonError):
        loads("   ")
    with pytest.raises(JsonError):
        loads('{"a": 1} {"b": 2}')


def test_malformed_number_is_rejected():
    with pytest.raises(JsonError):
        loads('{"a": 1-2}')


def test_raw_newline_inside_string_is_rejected():
    with pytest.raises(JsonError):
        loads('{"a": "one\ntwo"}')


def test_unknown_escape_is_rejected():
    with pytest.raises(JsonError):
        loads('{"a": "\\x"}')


def test_empty_containers():
    node = loads('{"a": {}, "b": []}')
    assert node.value == {"a": {}, "b": []}


def test_snippet_returns_the_source_line_trimmed():
    text = '{\n    "Action": "*"\n}'
    assert snippet(text, 2, 5) == '"Action": "*"'
    assert snippet(text, 99, 1) == ""


def test_snippet_truncates_very_long_lines():
    long_line = '{"a": "' + "x" * 300 + '"}'
    out = snippet(long_line, 1, 1, width=40)
    assert len(out) == 40


def test_pointer_escaping_of_slashes():
    node = loads('{"a/b": 1}')
    assert node.items[0].path == "/a~1b"
