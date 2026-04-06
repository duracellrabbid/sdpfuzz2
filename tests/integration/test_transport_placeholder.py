import pytest


@pytest.mark.integration
def test_integration_placeholder() -> None:
    status = "ok"
    assert status == "ok"
