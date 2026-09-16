"""Hosted-only qualification of the native initialization credential display.

Install at tests/agent/test_credential_banner.py in a disposable public checkout.
Run via scripts/run_tests.sh, with synthetic HOME and the pinned hosted venv.
No full AIAgent, SDK construction, source extraction, or dependency-module stubs.
"""

import pytest


@pytest.mark.parametrize("label,warn_missing", [("API key", True), ("token", False)])
def test_banner_does_not_disclose_credential_fragments(capsys, label, warn_missing):
    # Import after the canonical runner/conftest has isolated Hermes state.
    from agent.agent_init import _print_key_banner

    # Different lengths, same generic display; all credentials are invented.
    keys = (
        "SYNTH001-middle-only-TAIL",
        "SYNTH002-a-different-and-longer-middle-ZEND",
        "abcdefghijklm",  # first length above the existing short-key boundary
    )
    outputs = []
    for key in keys:
        _print_key_banner(key, label, warn_missing=warn_missing)
        captured = capsys.readouterr()
        assert captured.err == ""
        assert key not in captured.out, "banner disclosed a complete credential"
        assert key[:8] not in captured.out, "banner disclosed a credential prefix"
        assert key[-4:] not in captured.out, "banner disclosed a credential suffix"
        assert label in captured.out
        assert "configured" in captured.out
        assert "Warning" not in captured.out
        outputs.append(captured.out)
    assert outputs[0] == outputs[1] == outputs[2], "display depends on credential bytes"


def test_banner_preserves_callable_identity_and_missing_key_behavior(capsys):
    from agent.agent_init import _print_key_banner

    class SyntheticTokenProvider:
        def __call__(self):
            raise AssertionError("display must not mint a token")

        def __str__(self):
            raise AssertionError("display must not stringify a credential provider")

        def __repr__(self):
            raise AssertionError("display must not inspect a credential provider")

        def __len__(self):
            raise AssertionError("display must not measure a credential provider")

        def __getitem__(self, key):
            raise AssertionError("display must not slice a credential provider")

    provider = SyntheticTokenProvider()
    for label, warn_missing in (("API key", True), ("token", False)):
        _print_key_banner(provider, label, warn_missing=warn_missing)
        captured = capsys.readouterr()
        assert "Microsoft Entra ID" in captured.out
        assert "Warning" not in captured.out
        assert captured.err == ""

    # Preserve existing diagnostics rather than silently changing key validation.
    for key in (None, "", "none", "dummy-key", "abcdefghijkl"):
        _print_key_banner(key, "API key", warn_missing=True)
        captured = capsys.readouterr()
        assert "Warning: API key appears invalid or missing" in captured.out
        assert "configured" not in captured.out
        assert captured.err == ""
        _print_key_banner(key, "token", warn_missing=False)
        captured = capsys.readouterr()
        assert captured.out == captured.err == ""
