import pytest

from guardian_runtime.jsonutil import DuplicateJSONKeyError, loads_unique


def test_unique_json_accepts_normal_document():
    assert loads_unique('{"outer":{"value":1},"items":[1,2]}') == {
        "outer": {"value": 1},
        "items": [1, 2],
    }


def test_unique_json_rejects_duplicate_top_level_key():
    with pytest.raises(DuplicateJSONKeyError, match="duplicate JSON key"):
        loads_unique('{"format":"a","format":"b"}')


def test_unique_json_rejects_duplicate_nested_key():
    with pytest.raises(DuplicateJSONKeyError, match="duplicate JSON key"):
        loads_unique('{"checkpoint":{"event_count":1,"event_count":2}}')


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e9999", "-1e9999"])
def test_nonfinite_json_numbers_are_rejected(token):
    with pytest.raises(ValueError, match="finite|numeric constant"):
        loads_unique('{"value":' + token + '}')


def test_deep_json_reports_an_input_error():
    with pytest.raises(ValueError, match="nesting"):
        loads_unique("[" * 10000 + "0" + "]" * 10000)


@pytest.mark.parametrize("container", ["array", "object"])
def test_json_nesting_limit_has_a_stable_boundary(container):
    opening, closing = ("[", "]") if container == "array" else ('{"value":', "}")
    assert loads_unique(opening * 128 + "0" + closing * 128) is not None
    with pytest.raises(ValueError, match="nesting exceeds 128"):
        loads_unique(opening * 129 + "0" + closing * 129)
