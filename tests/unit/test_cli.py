import pytest
import typer
from typer.testing import CliRunner

from sdpfuzz2.bluetooth.probe import ProbeResult
from sdpfuzz2.cli import app, select_target_device
from sdpfuzz2.domain.errors import TransportError
from sdpfuzz2.domain.models import Device


def test_version_command_returns_package_version() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_select_target_device_with_explicit_index() -> None:
    devices = [
        Device(name="Alpha", mac_address="00:11:22:33:44:55"),
        Device(name="Beta", mac_address="AA:BB:CC:DD:EE:FF"),
    ]

    selected = select_target_device(devices, selected_index=2)

    assert selected == devices[1]


def test_select_target_device_rejects_out_of_range_index() -> None:
    devices = [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    with pytest.raises(typer.BadParameter, match="Target index must be between 1 and 1"):
        select_target_device(devices, selected_index=2)


def test_discover_command_uses_option_index(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        assert include_unnamed is False
        return [
            Device(name="Alpha", mac_address="00:11:22:33:44:55"),
            Device(name="Beta", mac_address="AA:BB:CC:DD:EE:FF"),
        ]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)

    result = runner.invoke(app, ["discover", "--index", "2"])

    assert result.exit_code == 0
    assert "Alpha" in result.stdout
    assert "00:11:22:33:44:55" in result.stdout
    assert "Beta" in result.stdout
    assert "AA:BB:CC:DD:EE:FF" in result.stdout
    assert "Selected target: Beta (AA:BB:CC:DD:EE:FF)" in result.stdout


def test_discover_command_interactive_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        assert include_unnamed is False
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)

    result = runner.invoke(app, ["discover"], input="1\n")

    assert result.exit_code == 0
    assert "Selected target: Alpha (00:11:22:33:44:55)" in result.stdout


def test_discover_command_no_devices_returns_non_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        assert include_unnamed is False
        return []

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)

    result = runner.invoke(app, ["discover"])

    assert result.exit_code == 1
    assert "No discoverable named devices found" in result.stdout


def test_probe_command_uses_selected_target_and_prints_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        assert include_unnamed is False
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe_selected_target(target: Device, response_timeout_ms: int) -> ProbeResult:
        assert target.mac_address == "00:11:22:33:44:55"
        assert response_timeout_ms == 900
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x02", b"\x09\x00\x01"],
            continuation_states=[b"\x01\x02"],
        )

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe_selected_target)

    result = runner.invoke(app, ["probe", "--index", "1", "--response-timeout-ms", "900"])

    assert result.exit_code == 0
    assert "Selected target: Alpha (00:11:22:33:44:55)" in result.stdout
    assert "Starting SDP probe for 00:11:22:33:44:55..." in result.stdout
    assert "SDP probe completed" in result.stdout
    assert "Attribute pages collected: 2" in result.stdout
    assert "Continuation states collected: 1" in result.stdout
    assert "Combined attribute payload bytes: 5" in result.stdout
    assert "Debug probe details:" not in result.stdout


def test_probe_command_debug_flag_prints_probe_result_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        assert include_unnamed is False
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe_selected_target(target: Device, response_timeout_ms: int) -> ProbeResult:
        assert target.mac_address == "00:11:22:33:44:55"
        assert response_timeout_ms == 1500
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x03\x09", b"\x00\x01"],
            continuation_states=[b"\xaa\xbb"],
        )

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe_selected_target)

    result = runner.invoke(app, ["probe", "--index", "1", "--debug"])

    assert result.exit_code == 0
    assert "Debug probe details:" in result.stdout
    assert "attribute_page[1]_hex=350309" in result.stdout
    assert "attribute_page[2]_hex=0001" in result.stdout
    assert "continuation_state[1]_hex=aabb" in result.stdout
    assert "combined_attribute_payload_hex=3503090001" in result.stdout


def test_probe_command_returns_non_zero_when_transport_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        assert include_unnamed is False
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe_selected_target(target: Device, response_timeout_ms: int) -> ProbeResult:
        del target
        del response_timeout_ms
        raise TransportError("connect failed")

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe_selected_target)

    result = runner.invoke(app, ["probe", "--index", "1"])

    assert result.exit_code == 1
    assert "Probe transport failed: connect failed" in result.stdout


def test_make_progress_table_zero_packets_sent() -> None:
    from sdpfuzz2.cli import make_progress_table
    from sdpfuzz2.orchestration.session import RunStatistics

    stats = RunStatistics()
    stats.packets_sent = 0
    stats.packets_received = 0
    table = make_progress_table(stats, "random-bytes", "00:11:22:33:44:55", "RUNNING")
    assert table is not None


def test_main_menu_early_exit_if_subcommand_invoked() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "=== SDPFuzz2 Main Menu ===" not in result.stdout


def test_main_menu_exit_option() -> None:
    runner = CliRunner()
    result = runner.invoke(app, [], input="6\n")
    assert result.exit_code == 0
    assert "=== SDPFuzz2 Main Menu ===" in result.stdout
    assert "Exiting." in result.stdout


def test_main_menu_abort() -> None:
    runner = CliRunner()
    result = runner.invoke(app, [], input="")
    assert result.exit_code == 0
    assert "=== SDPFuzz2 Main Menu ===" in result.stdout


def test_main_menu_invalid_choice() -> None:
    runner = CliRunner()
    result = runner.invoke(app, [], input="7\n6\n")
    assert result.exit_code == 0
    assert "Error: Invalid choice. Please choose a number between 1 and 6." in result.stdout


def test_main_menu_standalone_discovery_found(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    result = runner.invoke(app, [], input="3\n6\n")
    assert result.exit_code == 0
    assert "Alpha" in result.stdout
    assert "00:11:22:33:44:55" in result.stdout


def test_main_menu_standalone_discovery_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return []

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    result = runner.invoke(app, [], input="3\n6\n")
    assert result.exit_code == 0
    assert "No discoverable named devices found" in result.stdout


def test_main_menu_standalone_probing(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe(target: Device, response_timeout_ms: int) -> ProbeResult:
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x02"],
            continuation_states=[b"\x01\x02"],
        )

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe)
    result = runner.invoke(app, [], input="4\n1\n6\n")
    assert result.exit_code == 0
    assert "Starting SDP probe for 00:11:22:33:44:55..." in result.stdout
    assert "SDP probe completed" in result.stdout
    assert "Attribute pages collected: 1" in result.stdout


def test_main_menu_standalone_probing_exit_on_discovery_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return []

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    result = runner.invoke(app, [], input="4\n6\n")
    assert result.exit_code == 0
    assert "No discoverable named devices found" in result.stdout


def test_main_menu_standalone_probing_transport_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe(target: Device, response_timeout_ms: int) -> ProbeResult:
        raise TransportError("probe failed")

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe)
    result = runner.invoke(app, [], input="4\n1\n6\n")
    assert result.exit_code == 0
    assert "Probe transport failed: probe failed" in result.stdout


def test_main_menu_cleanup_corpus(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_clean(self: object) -> tuple[int, int]:
        return 2, 3

    monkeypatch.setattr("sdpfuzz2.cli.CorpusManager.clean_corpus", fake_clean)
    result = runner.invoke(app, [], input="5\n6\n")
    assert result.exit_code == 0
    assert (
        "Cleanup complete: 2 orphaned database records and 3 orphaned binary files removed."
        in result.stdout
    )


def test_main_menu_corpus_management(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    result = runner.invoke(app, [], input="2\n4\n6\n")
    assert result.exit_code == 0
    assert "=== SDPFuzz2 Corpus Management ===" in result.stdout
    assert "Exiting." in result.stdout


def test_main_menu_discover_and_fuzz(monkeypatch: pytest.MonkeyPatch) -> None:
    from sdpfuzz2.orchestration.session import SessionState

    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe(target: Device, response_timeout_ms: int) -> ProbeResult:
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x02"],
            continuation_states=[b"\x01\x02"],
        )

    async def fake_run(self: object) -> None:
        self.state = SessionState.STOPPED  # type: ignore[attr-defined]
        self.stats.packets_sent = 5  # type: ignore[attr-defined]
        self.stats.packets_received = 5  # type: ignore[attr-defined]
        self.stats.crashes_detected = 0  # type: ignore[attr-defined]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe)
    monkeypatch.setattr("sdpfuzz2.orchestration.runner.FuzzRunner.run", fake_run)

    result = runner.invoke(app, [], input="1\n1\n1\n6\n")
    assert result.exit_code == 0
    assert "Performing initial SDP probe on target 00:11:22:33:44:55..." in result.stdout
    assert "SDP probe completed successfully." in result.stdout
    assert "Fuzz Mode:          random-bytes" in result.stdout
    assert "Session completed successfully." in result.stdout


def test_main_menu_discover_and_fuzz_exit_on_discovery_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return []

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    result = runner.invoke(app, [], input="1\n6\n")
    assert result.exit_code == 0
    assert "No discoverable named devices found" in result.stdout


def test_main_menu_discover_and_fuzz_abort_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    result = runner.invoke(app, [], input="1\n1\n")
    assert result.exit_code == 0


def test_main_menu_discover_and_fuzz_invalid_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    result = runner.invoke(app, [], input="1\n1\n5\n6\n")
    assert result.exit_code == 0
    assert "Error: Invalid choice. Please choose a number between 1 and 4." in result.stdout


def test_main_menu_discover_and_fuzz_mode_length(monkeypatch: pytest.MonkeyPatch) -> None:
    from sdpfuzz2.orchestration.session import SessionState

    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe(target: Device, response_timeout_ms: int) -> ProbeResult:
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x02"],
            continuation_states=[b"\x01\x02"],
        )

    async def fake_run(self: object) -> None:
        self.state = SessionState.STOPPED  # type: ignore[attr-defined]
        self.stats.crashes_detected = 0  # type: ignore[attr-defined]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe)
    monkeypatch.setattr("sdpfuzz2.orchestration.runner.FuzzRunner.run", fake_run)

    result = runner.invoke(app, [], input="1\n1\n2\n6\n")
    assert result.exit_code == 0
    assert "Fuzz Mode:          continuation-length" in result.stdout


def test_main_menu_discover_and_fuzz_mode_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    from sdpfuzz2.orchestration.session import SessionState

    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe(target: Device, response_timeout_ms: int) -> ProbeResult:
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x02"],
            continuation_states=[b"\x01\x02"],
        )

    async def fake_run(self: object) -> None:
        self.state = SessionState.STOPPED  # type: ignore[attr-defined]
        self.stats.crashes_detected = 0  # type: ignore[attr-defined]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe)
    monkeypatch.setattr("sdpfuzz2.orchestration.runner.FuzzRunner.run", fake_run)

    result = runner.invoke(app, [], input="1\n1\n3\n6\n")
    assert result.exit_code == 0
    assert "Fuzz Mode:          continuation-bytes" in result.stdout


def test_main_menu_discover_and_fuzz_mode_bytes_no_states(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe(target: Device, response_timeout_ms: int) -> ProbeResult:
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x02"],
            continuation_states=[],
        )

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe)

    result = runner.invoke(app, [], input="1\n1\n3\n6\n")
    assert result.exit_code == 0
    assert "Error: No continuation states collected from target device." in result.stdout


def test_main_menu_discover_and_fuzz_mode_mutation(monkeypatch: pytest.MonkeyPatch) -> None:
    from sdpfuzz2.orchestration.session import SessionState

    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe(target: Device, response_timeout_ms: int) -> ProbeResult:
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x02"],
            continuation_states=[b"\x01\x02"],
        )

    async def fake_run(self: object) -> None:
        self.state = SessionState.STOPPED  # type: ignore[attr-defined]
        self.stats.crashes_detected = 0  # type: ignore[attr-defined]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe)
    monkeypatch.setattr("sdpfuzz2.orchestration.runner.FuzzRunner.run", fake_run)

    result = runner.invoke(app, [], input="1\n1\n4\n6\n")
    assert result.exit_code == 0
    assert "Fuzz Mode:          random-mutation" in result.stdout


def test_main_menu_discover_and_fuzz_crash_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    from sdpfuzz2.orchestration.session import SessionState

    runner = CliRunner()

    def fake_discover(self: object, *, include_unnamed: bool = False) -> list[Device]:
        return [Device(name="Alpha", mac_address="00:11:22:33:44:55")]

    def fake_probe(target: Device, response_timeout_ms: int) -> ProbeResult:
        return ProbeResult(
            attribute_list_fragments=[b"\x35\x02"],
            continuation_states=[b"\x01\x02"],
        )

    async def fake_run(self: object) -> None:
        self.state = SessionState.STOPPED  # type: ignore[attr-defined]
        self.stats.crashes_detected = 1  # type: ignore[attr-defined]

    monkeypatch.setattr("sdpfuzz2.cli.DiscoveryService.discover", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._probe_selected_target", fake_probe)
    monkeypatch.setattr("sdpfuzz2.orchestration.runner.FuzzRunner.run", fake_run)

    result = runner.invoke(app, [], input="1\n1\n1\n6\n")
    assert result.exit_code == 0
    assert "Session stopped due to crash detection." in result.stdout


def test_main_menu_corpus_management_invalid_choice() -> None:
    runner = CliRunner()
    result = runner.invoke(app, [], input="2\n5\n4\n6\n")
    assert result.exit_code == 0
    assert "Error: Invalid choice. Please choose a number between 1 and 4." in result.stdout


def test_main_menu_corpus_management_replay_invalid_seq() -> None:
    runner = CliRunner()
    result = runner.invoke(app, [], input="2\n2\nnonexistent\n\n1\nn\n4\n6\n")
    assert result.exit_code == 0
    assert "Sequence with ID 'nonexistent' not found." in result.stdout


def test_main_menu_corpus_management_fuzz_empty_corpus() -> None:
    runner = CliRunner()
    result = runner.invoke(app, [], input="2\n3\n\n4\n6\n")
    assert result.exit_code == 0
    assert "Error: Corpus is empty. Cannot run corpus-mutation fuzzing." in result.stdout


def test_main_menu_corpus_management_fuzz_abort() -> None:
    runner = CliRunner()
    result = runner.invoke(app, [], input="2\n3\n")
    assert result.exit_code == 0


def test_main_menu_corpus_management_replay_abort() -> None:
    runner = CliRunner()
    result = runner.invoke(app, [], input="2\n2\n")
    assert result.exit_code == 0
