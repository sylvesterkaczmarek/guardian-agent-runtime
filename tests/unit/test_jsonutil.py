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
