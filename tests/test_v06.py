import json
from pathlib import Path
from auditor.checks.flows import _get_path

def test_flow_path_reader():
    data = {"data": {"amount": 5000, "items": [{"id": "x"}]}}
    assert _get_path(data, "data.amount") == (5000, True)
    assert _get_path(data, "data.items.0.id") == ("x", True)
    assert _get_path(data, "data.missing") == (None, False)
