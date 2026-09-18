from unsafe_c_finder.cli import main


def test_quiet_suppresses_missing_key_error(monkeypatch, capsys) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    exit_code = main(["--stdin", "--quiet"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == ""
