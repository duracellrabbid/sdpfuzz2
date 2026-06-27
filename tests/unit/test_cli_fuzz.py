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
    async def fake_run(self: object) -> None:
        self.state = SessionState.STOPPED  # type: ignore[attr-defined]
        self.stats.packets_sent = 10  # type: ignore[attr-defined]
        self.stats.packets_received = 9  # type: ignore[attr-defined]
        self.stats.timeouts = 1  # type: ignore[attr-defined]
        self.stats.errors = 0  # type: ignore[attr-defined]
        self.stats.crashes_detected = 0  # type: ignore[attr-defined]
        if self.run_logger:  # type: ignore[attr-defined]
            self.run_logger.log_request(1, b"\x01")  # type: ignore[attr-defined]
            self.run_logger.log_response(1, b"\x02", 0)  # type: ignore[attr-defined]
            self.run_logger.finalize()  # type: ignore[attr-defined]

    monkeypatch.setattr("sdpfuzz2.orchestration.runner.FuzzRunner.run", fake_run)


def test_fuzz_command_invalid_mode(mock_probe: None, mock_runner: None) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["fuzz", "--mode", "invalid-mode", "--target", "00:11:22:33:44:55"])
    assert result.exit_code != 0
    assert "Invalid fuzzing mode" in (result.stderr or "")


def test_fuzz_command_invalid_concurrency(mock_probe: None, mock_runner: None) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55", "--concurrency", "0"],
    )
    assert result.exit_code != 0
    assert "concurrency must be >= 1" in (result.stderr or "")


def test_fuzz_command_invalid_queue_size(mock_probe: None, mock_runner: None) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55", "--queue-size", "0"],
    )
    assert result.exit_code != 0
    assert "queue-size must be >= 1" in (result.stderr or "")


def test_fuzz_command_invalid_max_length(mock_probe: None, mock_runner: None) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55", "--max-length", "10"],
    )
    assert result.exit_code != 0
    assert "max-length must be >= 16" in (result.stderr or "")


def test_fuzz_command_invalid_delay(mock_probe: None, mock_runner: None) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app, ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55", "--delay", "-1.0"]
    )
    assert result.exit_code != 0
    assert "delay must be >= 0.0" in (result.stderr or "")


def test_fuzz_command_invalid_rate_limit(mock_probe: None, mock_runner: None) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55", "--rate-limit", "-5"],
    )
    assert result.exit_code != 0
    assert "rate-limit must be >= 0" in (result.stderr or "")


def test_fuzz_command_invalid_target_mac(mock_probe: None, mock_runner: None) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["fuzz", "--mode", "random-bytes", "--target", "invalid-mac"])
    assert result.exit_code != 0
    assert "Invalid MAC address" in (result.stderr or "")


def test_fuzz_command_happy_path(mock_probe: None, mock_runner: None, tmp_path: Path) -> None:
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


def test_fuzz_command_interactive_mode_selection(
    mock_probe: None, mock_runner: None, tmp_path: Path
) -> None:
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
    monkeypatch: pytest.MonkeyPatch, mock_probe: None, mock_runner: None, tmp_path: Path
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
    monkeypatch: pytest.MonkeyPatch, mock_runner: None
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


def test_fuzz_command_verbose_mode(mock_probe: None, mock_runner: None, tmp_path: Path) -> None:
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
    monkeypatch: pytest.MonkeyPatch, mock_probe: None, mock_runner: None, tmp_path: Path
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
    monkeypatch: pytest.MonkeyPatch, mock_probe: None
) -> None:
    runner = CliRunner()

    async def fake_run_with_crash(self: object) -> None:
        self.state = SessionState.STOPPED  # type: ignore[attr-defined]
        self.stats.packets_sent = 5  # type: ignore[attr-defined]
        self.stats.packets_received = 4  # type: ignore[attr-defined]
        self.stats.crashes_detected = 1  # type: ignore[attr-defined]

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


def test_fuzz_command_discovery_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover_and_select_target(index: int | None) -> Device:
        raise RuntimeError("Bluetooth hardware not available")

    monkeypatch.setattr("sdpfuzz2.cli._discover_and_select_target", fake_discover_and_select_target)
    result = runner.invoke(app, ["fuzz", "--mode", "random-bytes"])
    assert result.exit_code == 1
    assert "Discovery failed: Bluetooth hardware not available" in result.stdout


def test_fuzz_command_interactive_mode_abort(
    monkeypatch: pytest.MonkeyPatch, mock_probe: None
) -> None:
    import typer

    runner = CliRunner()

    def fake_prompt(text: str, type: type) -> int:
        raise typer.Abort()

    monkeypatch.setattr("typer.prompt", fake_prompt)
    result = runner.invoke(app, ["fuzz", "--target", "00:11:22:33:44:55"])
    assert result.exit_code == 1


def test_fuzz_command_interactive_mode_continuation_length(
    mock_probe: None, mock_runner: None, tmp_path: Path
) -> None:
    runner = CliRunner()
    log_file = tmp_path / "test_run.json"
    result = runner.invoke(
        app, ["fuzz", "--target", "00:11:22:33:44:55", "--output", str(log_file)], input="2\n"
    )
    assert result.exit_code == 0
    assert "Fuzz Mode:          continuation-length" in result.stdout


def test_fuzz_command_interactive_mode_continuation_bytes(
    mock_probe: None, mock_runner: None, tmp_path: Path
) -> None:
    runner = CliRunner()
    log_file = tmp_path / "test_run.json"
    result = runner.invoke(
        app, ["fuzz", "--target", "00:11:22:33:44:55", "--output", str(log_file)], input="3\n"
    )
    assert result.exit_code == 0
    assert "Fuzz Mode:          continuation-bytes" in result.stdout


def test_fuzz_command_interactive_mode_random_mutation(
    mock_probe: None, mock_runner: None, tmp_path: Path
) -> None:
    runner = CliRunner()
    log_file = tmp_path / "test_run.json"
    result = runner.invoke(
        app, ["fuzz", "--target", "00:11:22:33:44:55", "--output", str(log_file)], input="4\n"
    )
    assert result.exit_code == 0
    assert "Fuzz Mode:          random-mutation" in result.stdout


def test_fuzz_command_interactive_mode_invalid_choice(mock_probe: None, mock_runner: None) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["fuzz", "--target", "00:11:22:33:44:55"], input="5\n")
    assert result.exit_code == 1
    assert "Error: Invalid choice" in result.stdout


def test_fuzz_command_probe_transport_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    from sdpfuzz2.domain.errors import TransportError

    runner = CliRunner()

    def fake_probe(target: Device, response_timeout_ms: int) -> ProbeResult:
        raise TransportError("RFCOMM connection down")

    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe)
    result = runner.invoke(app, ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55"])
    assert result.exit_code == 1
    assert "Probe transport failed: RFCOMM connection down" in result.stdout


def test_fuzz_command_runner_fails(monkeypatch: pytest.MonkeyPatch, mock_probe: None) -> None:
    runner = CliRunner()

    async def fake_run_fuzzing_main(
        runner: object, mode: str, target_mac: str, verbose: bool
    ) -> None:
        raise RuntimeError("Orchestration runner crashed")

    monkeypatch.setattr("sdpfuzz2.cli.run_fuzzing_main", fake_run_fuzzing_main)
    result = runner.invoke(app, ["fuzz", "--mode", "random-bytes", "--target", "00:11:22:33:44:55"])
    assert result.exit_code == 1
    assert "Fuzzing session encountered an error: Orchestration runner crashed" in result.stdout


def test_run_fuzzing_main_display_loop_coverage() -> None:
    import asyncio

    from sdpfuzz2.cli import run_fuzzing_main
    from sdpfuzz2.orchestration.session import RunStatistics, SessionState

    class FakeRunner:
        def __init__(self) -> None:
            self.stats = RunStatistics()
            self.state = SessionState.RUNNING

        async def run(self) -> None:
            await asyncio.sleep(0.3)
            self.state = SessionState.STOPPED

    async def run_test() -> None:
        from typing import Any

        runner: Any = FakeRunner()
        await run_fuzzing_main(runner, "random-bytes", "00:11:22:33:44:55", verbose=False)

    asyncio.run(run_test())
