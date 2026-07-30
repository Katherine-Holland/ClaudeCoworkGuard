import importlib
import pytest
import sys
from pathlib import Path

sys.path.insert(0, "pro/licence")

def test_keygen_raises_without_secret(monkeypatch):
    monkeypatch.delenv("CWG_LICENCE_SECRET", raising=False)
    monkeypatch.setattr(Path, "exists", lambda self: False)

    with pytest.raises(RuntimeError):
        import keygen
        importlib.reload(keygen)
    
def test_keygen_succeeds_with_secret(monkeypatch):
    monkeypatch.setenv("CWG_LICENCE_SECRET", "test-secret-value")
    import keygen
    importlib.reload(keygen)
    assert keygen._SIGNING_SECRET== "test-secret-value"

    