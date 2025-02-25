import pytest
from Scripts.graph_agent import validate_scope


def test_validate_scope_allowed():
    assert validate_scope("scanme.nmap.org") == True

def test_validate_scope_blocked():
    assert validate_scope("example.com") == False
