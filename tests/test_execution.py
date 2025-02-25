import pytest
from Scripts.graph_agent import run_command

def test_run_command_success():
    result = run_command("echo Hello")
    assert result["status"] == "success"
    assert "Hello" in result["output"]

def test_run_command_failure():
    result = run_command("invalidcommand")
    assert result["status"] == "error"
