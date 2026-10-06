import importlib.util
import json
from pathlib import Path

import pytest
import requests


@pytest.fixture
def live_check():
    path = Path(__file__).resolve().parents[1] / ".gitea/scripts/test-live-notify.py"
    spec = importlib.util.spec_from_file_location("live_notify_check", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("error", ["apikey not available", "apikey not found", "signature not valid", "timestamp is too old", "message not sent"])
def test_reports_known_api_errors(live_check, error):
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps({"status": "error", "errors": [error]}).encode()
    with pytest.raises(live_check.TestFailure, match=error):
        live_check.check_response(response, "delivery", "ok")


def test_does_not_log_arbitrary_response_values(live_check):
    secret = "sensitive-value-do-not-log"
    result = {"status": secret, "errors": [secret, {"token": secret}, "message not sent"], "token": secret}
    summary = live_check.describe_result(result)
    assert secret not in summary
    assert "message not sent" in summary
    assert "<unrecognized error>" in summary
