from auditor.core.models import Finding
from auditor.plugins.runner import list_checks
from auditor.reporting import render_markdown

def test_finding_has_stable_metadata():
    f=Finding("high","auth","Example","e","r",check_id="AUTH-1")
    assert f.fingerprint and f.as_dict()["check_id"] == "AUTH-1"

def test_registry_and_report():
    assert list_checks()
    data={"summary":{"total":1},"findings":[Finding("LOW","x","T","E","R",check_id="X-1").as_dict()]}
    assert "X-1" in render_markdown(data)

def test_v05_registry_contains_business_and_payments():
    ids = {c.id for c in list_checks()}
    assert "business.surface" in ids
    assert "payments.surface" in ids
