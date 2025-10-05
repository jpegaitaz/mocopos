from mcp_scanner.analysis.classifier import classify
from mcp_scanner.core.result_types import Finding

def test_classify_safe():
    c, s = classify([])
    assert c == "Safe"

def test_classify_threat():
    fs = [Finding(path="x", scanner="s", rule_id="r", severity="high", reason="")]
    c, _ = classify(fs)
    assert c == "Threat"
