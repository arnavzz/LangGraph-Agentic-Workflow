import pytest
from graph_agent import handle_failure

def test_handle_failure_max_retries():
    task = {"command": "invalidcommand"}
    result = handle_failure(task, attempt=2)
    assert result["status"] == "failed"
    assert "Max retries reached" in result["output"]
