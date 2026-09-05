from utils.crypto_trace import trace_event


def test_crypto_trace_is_disabled_by_default(monkeypatch, capsys):
    monkeypatch.delenv("FACULTY_CRYPTO_TRACE", raising=False)
    trace_event("CRYPTO", "TEST", purpose="RSA_PROFILE")
    assert capsys.readouterr().out == ""


def test_crypto_trace_emits_structured_safe_events(monkeypatch, capsys):
    monkeypatch.setenv("FACULTY_CRYPTO_TRACE", "true")
    trace_event(
        "AUTH",
        "TEST",
        purpose="CMAC_SESSION",
        password="never-print-this",
        session_id="never-print-this-either",
        result="VALID",
    )
    output = capsys.readouterr().out
    assert "[TRACE][AUTH][TEST]" in output
    assert "CMAC_SESSION" in output
    assert "never-print-this" not in output
    assert "[REDACTED]" in output
