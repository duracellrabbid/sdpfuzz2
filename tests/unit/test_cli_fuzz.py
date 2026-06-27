from pathlib import Path

import pytest
from typer.testing import CliRunner

from sdpfuzz2.bluetooth.probe import ProbeResult
from sdpfuzz2.cli import app
from sdpfuzz2.domain.models import Device
from sdpfuzz2.orchestration.session import SessionState


@pytest.fixture
def mock_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_probe(target: Device, response_timeout_ms: int) -> ProbeResult:
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x03"],
            continuation_states=[b"\x01\x02"],
        )

    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe)


@pytest.fixture
def mock_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run(self) -> None:
        self.state = SessionState.STOPPED
        self.stats.packets_sent = 10
        self.stats.packets_received = 9
        self.stats.timeouts = 1
        self.stats.errors = 0
        self.stats.crashes_detected = 0
        if self.run_logger:
            self.run_logger.log_request(1, b"\x01")
            self.run_logger.log_response(1, b"\x02", 0)
            self.run_logger.finalize()

    monkeypatch.setattr("sdpfuzz2.orchestration.runner.FuzzRunner.run", fake_run)


def test_fuzz_command_invalid_mode(mock_probe, mock_runner) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["fuzz", "--mode", "invalid-mode", "--target", "00:11:22:33:44:55"])
    assert result.exit_code != 0
    assert "Invalid fuzzing mode" in (result.stderr or "")


def test_fuzz_command_invalid_concurrency(mock_probe, mock_runner) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55", "--concurrency", "0"],
    )
    assert result.exit_code != 0
    assert "concurrency must be >= 1" in (result.stderr or "")


def test_fuzz_command_invalid_queue_size(mock_probe, mock_runner) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55", "--queue-size", "0"],
    )
    assert result.exit_code != 0
    assert "queue-size must be >= 1" in (result.stderr or "")


def test_fuzz_command_invalid_max_length(mock_probe, mock_runner) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55", "--max-length", "10"],
    )
    assert result.exit_code != 0
    assert "max-length must be >= 16" in (result.stderr or "")


def test_fuzz_command_invalid_delay(mock_probe, mock_runner) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app, ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55", "--delay", "-1.0"]
    )
    assert result.exit_code != 0
    assert "delay must be >= 0.0" in (result.stderr or "")


def test_fuzz_command_invalid_rate_limit(mock_probe, mock_runner) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55", "--rate-limit", "-5"],
    )
    assert result.exit_code != 0
    assert "rate-limit must be >= 0" in (result.stderr or "")


def test_fuzz_command_invalid_target_mac(mock_probe, mock_runner) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["fuzz", "--mode", "random-bytes", "--target", "invalid-mac"])
    assert result.exit_code != 0
    assert "Invalid MAC address" in (result.stderr or "")


def test_fuzz_command_happy_path(mock_probe, mock_runner, tmp_path: Path) -> None:
    runner = CliRunner()
    log_file = tmp_path / "test_run.json"
    result = runner.invoke(
        app,
        [
            "fuzz",
            "--mode",
            "random-bytes",
            "--target",
            "00:11:22:33:44:55",
            "--concurrency",
            "2",
            "--queue-size",
            "10",
            "--max-length",
            "32",
            "--delay",
            "1.5",
            "--rate-limit",
            "20",
            "--seed",
            "12345",
            "--output",
            str(log_file),
        ],
    )
    assert result.exit_code == 0
    assert "SDP probe completed successfully" in result.stdout
    assert "Fuzzing Session Summary" in result.stdout
    assert "Packets Sent:       10" in result.stdout
    assert "Responses Received: 9" in result.stdout
    assert "Timeouts:           1" in result.stdout


def test_fuzz_command_interactive_mode_selection(mock_probe, mock_runner, tmp_path: Path) -> None:
    runner = CliRunner()
    log_file = tmp_path / "test_run.json"
    result = runner.invoke(
        app, ["fuzz", "--target", "00:11:22:33:44:55", "--output", str(log_file)], input="1\n"
    )
    assert result.exit_code == 0
    assert "Available fuzzing modes:" in result.stdout
    assert "Select fuzzing mode" in result.stdout
    assert "Fuzz Mode:          random-bytes" in result.stdout


def test_fuzz_command_interactive_device_discovery(
    monkeypatch: pytest.MonkeyPatch, mock_probe, mock_runner, tmp_path: Path
) -> None:
    runner = CliRunner()
    log_file = tmp_path / "test_run.json"

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)

    result = runner.invoke(
        app, ["fuzz", "--mode", "random-bytes", "--output", str(log_file)], input="1\n"
    )
    assert result.exit_code == 0
    assert "Selected target: Alpha (00:11:22:33:44:55)" in result.stdout
    assert "Target MAC:         00:11:22:33:44:55" in result.stdout


def test_fuzz_command_continuation_bytes_fails_when_no_states(
    monkeypatch: pytest.MonkeyPatch, mock_runner
) -> None:
    runner = CliRunner()

    def fake_probe(target: Device, response_timeout_ms: int) -> ProbeResult:
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x03"],
            continuation_states=[],  # EMPTY
        )

    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe)

    result = runner.invoke(
        app, ["fuzz", "--mode", "continuation-bytes", "--target", "00:11:22:33:44:55"]
    )
    assert result.exit_code == 1
    assert "Error: No continuation states collected" in result.stdout


def test_fuzz_command_verbose_mode(mock_probe, mock_runner, tmp_path: Path) -> None:
    runner = CliRunner()
    log_file = tmp_path / "test_run_verbose.json"
    result = runner.invoke(
        app,
        [
            "fuzz",
            "--mode",
            "random-bytes",
            "--target",
            "00:11:22:33:44:55",
            "--verbose",
            "--output",
            str(log_file),
        ],
    )
    assert result.exit_code == 0
    assert "Starting fuzzing session against" in result.stdout


def test_fuzz_command_default_output_path(
    monkeypatch: pytest.MonkeyPatch, mock_probe, mock_runner, tmp_path: Path
) -> None:
    runner = CliRunner()
    monkeypatch.setenv("SDPFUZZ2_LOG_DIR", str(tmp_path))

    result = runner.invoke(
        app,
        [
            "fuzz",
            "--mode",
            "random-bytes",
            "--target",
            "00:11:22:33:44:55",
        ],
    )
    assert result.exit_code == 0
    # Check that a log file was written in tmp_path
    log_files = list(tmp_path.glob("fuzz_*.json"))
    assert len(log_files) == 1
    assert "00-11-22-33-44-55" in log_files[0].name


def test_fuzz_command_crash_stop_returns_code_2(
    monkeypatch: pytest.MonkeyPatch, mock_probe
) -> None:
    runner = CliRunner()

    async def fake_run_with_crash(self) -> None:
        self.state = SessionState.STOPPED
        self.stats.packets_sent = 5
        self.stats.packets_received = 4
        self.stats.crashes_detected = 1

    monkeypatch.setattr("sdpfuzz2.orchestration.runner.FuzzRunner.run", fake_run_with_crash)

    result = runner.invoke(
        app,
        [
            "fuzz",
            "--mode",
            "random-bytes",
            "--target",
            "00:11:22:33:44:55",
        ],
    )
    assert result.exit_code == 2
    assert "Session stopped due to crash detection" in result.stdout
