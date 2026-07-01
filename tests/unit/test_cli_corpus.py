"""Unit tests for corpus management CLI commands."""

from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from sdpfuzz2.cli import app
from sdpfuzz2.domain.models import Device
from sdpfuzz2.logging.corpus_manager import CorpusManager


@pytest.fixture
def temp_corpus(tmp_path: Path) -> Path:
    """Fixture to set up a temporary corpus dir."""
    corpus_dir = tmp_path / "test_corpus"
    corpus_dir.mkdir()
    return corpus_dir


def test_clean_command(temp_corpus: Path) -> None:
    """Test sdpfuzz2 clean CLI command."""
    runner = CliRunner()
    manager = CorpusManager(base_dir=temp_corpus)

    # Save a sequence to create a valid record and file
    manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"data"])

    # Create an orphan file
    orphan_file = temp_corpus / "orphan.bin"
    orphan_file.write_bytes(b"\x00")

    result = runner.invoke(app, ["clean", "--base-dir", str(temp_corpus)])
    assert result.exit_code == 0
    assert "Cleanup complete" in result.stdout
    assert "1 orphaned binary files removed" in result.stdout
    assert not orphan_file.exists()


def test_corpus_list_empty(temp_corpus: Path) -> None:
    """Test corpus list command on empty corpus."""
    runner = CliRunner()
    result = runner.invoke(app, ["corpus", "list", "--base-dir", str(temp_corpus)])
    assert result.exit_code == 0
    assert "Corpus is empty." in result.stdout


def test_corpus_list_populated(temp_corpus: Path) -> None:
    """Test corpus list command on populated corpus."""
    runner = CliRunner()
    manager = CorpusManager(base_dir=temp_corpus)
    manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    result = runner.invoke(app, ["corpus", "list", "--base-dir", str(temp_corpus)])
    assert result.exit_code == 0
    assert "00:11:22" in result.stdout


def test_corpus_replay_not_found(temp_corpus: Path) -> None:
    """Test replaying a non-existent sequence ID."""
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "corpus",
            "replay",
            "nonexistent",
            "--target",
            "00:11:22:33:44:55",
            "--base-dir",
            str(temp_corpus),
        ],
    )
    assert result.exit_code != 0
    assert "not found" in result.stdout


def test_corpus_replay_success(temp_corpus: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test successful replay of a sequence."""
    runner = CliRunner()
    manager = CorpusManager(base_dir=temp_corpus)
    seq_id = manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    async def mock_replay(*args: object, **kwargs: object) -> bool:
        # returns False -> no crash/timeout
        return False

    monkeypatch.setattr("sdpfuzz2.orchestration.replay.ReplayController.replay", mock_replay)

    result = runner.invoke(
        app,
        [
            "corpus",
            "replay",
            seq_id,
            "--target",
            "00:11:22:33:44:55",
            "--base-dir",
            str(temp_corpus),
        ],
    )
    assert result.exit_code == 0
    assert "Replay complete: target did not crash" in result.stdout


def test_corpus_replay_crashed(temp_corpus: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test replay of a sequence that triggers a crash."""
    runner = CliRunner()
    manager = CorpusManager(base_dir=temp_corpus)
    seq_id = manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    async def mock_replay(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr("sdpfuzz2.orchestration.replay.ReplayController.replay", mock_replay)

    result = runner.invoke(
        app,
        [
            "corpus",
            "replay",
            seq_id,
            "--target",
            "00:11:22:33:44:55",
            "--base-dir",
            str(temp_corpus),
        ],
    )
    assert result.exit_code == 0
    assert "Replay complete: crash/timeout detected!" in result.stdout


def test_corpus_replay_interactive_target(
    temp_corpus: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test replay with dynamic/interactive target resolution fallback."""
    runner = CliRunner()
    manager = CorpusManager(base_dir=temp_corpus)
    seq_id = manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    def fake_discover(*args: object, **kwargs: object) -> Device:
        return Device(name="Interactive target", mac_address="AA:BB:CC:DD:EE:FF")

    async def mock_replay(*args: object, **kwargs: object) -> bool:
        return False

    monkeypatch.setattr("sdpfuzz2.cli._discover_and_select_target", fake_discover)
    monkeypatch.setattr("sdpfuzz2.orchestration.replay.ReplayController.replay", mock_replay)

    result = runner.invoke(app, ["corpus", "replay", seq_id, "--base-dir", str(temp_corpus)])
    assert result.exit_code == 0
    assert "No replay target specified" in result.stdout
    assert "Replay complete" in result.stdout


def test_corpus_replay_interactive_target_failure(
    temp_corpus: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test replay dynamic resolution failure."""
    runner = CliRunner()
    manager = CorpusManager(base_dir=temp_corpus)
    seq_id = manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    def fake_discover(*args: object, **kwargs: object) -> Device:
        raise RuntimeError("No bluetooth controllers")

    monkeypatch.setattr("sdpfuzz2.cli._discover_and_select_target", fake_discover)

    result = runner.invoke(app, ["corpus", "replay", seq_id, "--base-dir", str(temp_corpus)])
    assert result.exit_code == 1
    assert "Discovery failed" in result.stdout


def test_corpus_replay_fallback_to_fuzz(temp_corpus: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test replay fallback to mutation fuzzing when replay does not crash."""
    runner = CliRunner()
    manager = CorpusManager(base_dir=temp_corpus)
    seq_id = manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    async def mock_replay(*args: object, **kwargs: object) -> bool:
        return False

    fuzz_called = False

    def mock_fuzzing(*args: object, **kwargs: object) -> None:
        nonlocal fuzz_called
        fuzz_called = True

    monkeypatch.setattr("sdpfuzz2.orchestration.replay.ReplayController.replay", mock_replay)
    monkeypatch.setattr("sdpfuzz2.cli._run_corpus_mutation_fuzzing", mock_fuzzing)

    result = runner.invoke(
        app,
        [
            "corpus",
            "replay",
            seq_id,
            "--target",
            "00:11:22:33:44:55",
            "--mutate-on-fail",
            "--base-dir",
            str(temp_corpus),
        ],
    )
    assert result.exit_code == 0
    assert "Fallback trigger enabled" in result.stdout
    assert fuzz_called is True


def test_corpus_fuzz_empty_corpus(temp_corpus: Path) -> None:
    """Test corpus fuzzing CLI fails if corpus is empty."""
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["corpus", "fuzz", "--target", "00:11:22:33:44:55", "--base-dir", str(temp_corpus)],
    )
    assert result.exit_code != 0
    assert "Corpus is empty" in result.stdout


def test_corpus_fuzz_success(temp_corpus: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test corpus fuzzing CLI success path."""
    runner = CliRunner()
    manager = CorpusManager(base_dir=temp_corpus)
    manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    fuzz_called = False

    def mock_fuzzing(*args: object, **kwargs: object) -> None:
        nonlocal fuzz_called
        fuzz_called = True

    monkeypatch.setattr("sdpfuzz2.cli._run_corpus_mutation_fuzzing", mock_fuzzing)

    result = runner.invoke(
        app,
        ["corpus", "fuzz", "--target", "00:11:22:33:44:55", "--base-dir", str(temp_corpus)],
    )
    assert result.exit_code == 0
    assert fuzz_called is True


def test_corpus_fuzz_interactive_target(temp_corpus: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test corpus fuzzing dynamic discovery fallback."""
    runner = CliRunner()
    manager = CorpusManager(base_dir=temp_corpus)
    manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    def fake_discover(*args: object, **kwargs: object) -> Device:
        return Device(name="Interactive target", mac_address="AA:BB:CC:DD:EE:FF")

    fuzz_called = False

    def mock_fuzzing(*args: object, **kwargs: object) -> None:
        nonlocal fuzz_called
        fuzz_called = True

    monkeypatch.setattr("sdpfuzz2.cli._discover_and_select_target", fake_discover)
    monkeypatch.setattr("sdpfuzz2.cli._run_corpus_mutation_fuzzing", mock_fuzzing)

    result = runner.invoke(app, ["corpus", "fuzz", "--base-dir", str(temp_corpus)])
    assert result.exit_code == 0
    assert fuzz_called is True


def test_corpus_fuzz_interactive_target_failure(
    temp_corpus: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test corpus fuzzing dynamic resolution failure path."""
    runner = CliRunner()
    manager = CorpusManager(base_dir=temp_corpus)
    manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    def fake_discover(*args: object, **kwargs: object) -> Device:
        raise RuntimeError("No bluetooth controllers")

    monkeypatch.setattr("sdpfuzz2.cli._discover_and_select_target", fake_discover)

    result = runner.invoke(app, ["corpus", "fuzz", "--base-dir", str(temp_corpus)])
    assert result.exit_code == 1


def test_run_corpus_mutation_fuzzing_execution(
    temp_corpus: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test actual execution of corpus-mutation fuzzing."""
    from sdpfuzz2.cli import _run_corpus_mutation_fuzzing

    manager = CorpusManager(base_dir=temp_corpus)
    manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    run_called = False

    async def mock_run_fuzzing_main(*args: Any, **kwargs: Any) -> None:
        nonlocal run_called
        run_called = True
        # Set stats/runner state to simulate clean completion
        runner_obj = args[0]
        runner_obj.stats.packets_sent = 5
        runner_obj.stats.packets_received = 5
        runner_obj.stats.crashes_detected = 0

    monkeypatch.setattr("sdpfuzz2.cli.run_fuzzing_main", mock_run_fuzzing_main)

    _run_corpus_mutation_fuzzing(
        target_mac="00:11:22:33:44:55",
        manager=manager,
        base_dir=str(temp_corpus),
    )
    assert run_called is True


def test_run_corpus_mutation_fuzzing_execution_crash_exit(
    temp_corpus: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test actual execution of corpus-mutation fuzzing when crash is detected."""
    from sdpfuzz2.cli import _run_corpus_mutation_fuzzing

    manager = CorpusManager(base_dir=temp_corpus)
    manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    async def mock_run_fuzzing_main(*args: Any, **kwargs: Any) -> None:
        runner_obj = args[0]
        runner_obj.stats.packets_sent = 5
        runner_obj.stats.packets_received = 5
        runner_obj.stats.crashes_detected = 1

    monkeypatch.setattr("sdpfuzz2.cli.run_fuzzing_main", mock_run_fuzzing_main)

    with pytest.raises(typer.Exit) as exc_info:
        _run_corpus_mutation_fuzzing(
            target_mac="00:11:22:33:44:55",
            manager=manager,
            base_dir=str(temp_corpus),
        )
    assert exc_info.value.exit_code == 2


def test_run_corpus_mutation_fuzzing_execution_runner_error(
    temp_corpus: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test actual execution of corpus-mutation fuzzing when runner raises exception."""
    from sdpfuzz2.cli import _run_corpus_mutation_fuzzing

    manager = CorpusManager(base_dir=temp_corpus)
    manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    async def mock_run_fuzzing_main(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Runner crashed")

    monkeypatch.setattr("sdpfuzz2.cli.run_fuzzing_main", mock_run_fuzzing_main)

    with pytest.raises(typer.Exit) as exc_info:
        _run_corpus_mutation_fuzzing(
            target_mac="00:11:22:33:44:55",
            manager=manager,
            base_dir=str(temp_corpus),
        )
    assert exc_info.value.exit_code == 1


def test_corpus_interactive_menu_options(
    temp_corpus: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test interactive callback menu prompts and branching."""
    runner = CliRunner()
    manager = CorpusManager(base_dir=temp_corpus)
    manager.save_sequence("crash_candidate", "00:11:22:33:44:55", [b"pkt"])

    # 1. Option 1: List sequences
    result = runner.invoke(app, ["corpus", "--base-dir", str(temp_corpus)], input="1\n")
    assert result.exit_code == 0
    assert "00:11:22" in result.stdout

    # 2. Option 2: Replay a sequence
    # Provide choice 2, then sequence id, then blank for target, then loop 1, then mutate n
    async def mock_replay(*args: object, **kwargs: object) -> bool:
        return False

    def fake_discover(*args: object, **kwargs: object) -> Device:
        return Device(name="Interactive target", mac_address="AA:BB:CC:DD:EE:FF")

    monkeypatch.setattr("sdpfuzz2.cli._discover_and_select_target", fake_discover)
    monkeypatch.setattr("sdpfuzz2.orchestration.replay.ReplayController.replay", mock_replay)

    seqs = manager.list_sequences()
    seq_id = seqs[0]["id"]

    result = runner.invoke(
        app, ["corpus", "--base-dir", str(temp_corpus)], input=f"2\n{seq_id}\n\n1\nn\n"
    )
    assert result.exit_code == 0
    assert "Replay complete" in result.stdout

    # 3. Option 3: Fuzz target
    # Provide choice 3, target blank
    fuzz_called = False

    def mock_fuzzing(*args: object, **kwargs: object) -> None:
        nonlocal fuzz_called
        fuzz_called = True

    monkeypatch.setattr("sdpfuzz2.cli._run_corpus_mutation_fuzzing", mock_fuzzing)
    result = runner.invoke(app, ["corpus", "--base-dir", str(temp_corpus)], input="3\n\n")
    assert result.exit_code == 0
    assert fuzz_called is True

    # 4. Option 4: Exit
    result = runner.invoke(app, ["corpus", "--base-dir", str(temp_corpus)], input="4\n")
    assert result.exit_code == 0
    assert "Exiting." in result.stdout

    # 5. Abort choice
    result = runner.invoke(app, ["corpus", "--base-dir", str(temp_corpus)], input="\n")
    # should exit gracefully


def test_cli_commands_direct_calls(temp_corpus: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test calling CLI functions programmatically to hit default fallback paths."""
    from sdpfuzz2.cli import clean_corpus_cmd, corpus_fuzz, corpus_list, corpus_main, corpus_replay

    corpus_list()
    clean_corpus_cmd()

    with pytest.raises(typer.Exit):
        corpus_replay(seq_id="dummy")

    with pytest.raises(typer.Exit):
        corpus_fuzz()

    class FakeContext:
        invoked_subcommand = "dummy_sub"

    corpus_main(ctx=FakeContext())  # type: ignore[arg-type]

    class FakeContextInteractive:
        invoked_subcommand = None

    def fake_prompt(*args: object, **kwargs: object) -> None:
        raise typer.Abort()

    monkeypatch.setattr("typer.prompt", fake_prompt)
    corpus_main(ctx=FakeContextInteractive())  # type: ignore[arg-type]
