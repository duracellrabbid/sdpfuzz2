from typer.testing import CliRunner

from sdpfuzz2.cli import app


def test_version_command_returns_package_version() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "0.1.0" in result.stdout
