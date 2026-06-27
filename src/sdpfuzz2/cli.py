"""CLI entrypoint for SDPFuzz2."""

import asyncio
import datetime
import logging
import os
from collections.abc import Sequence
from pathlib import Path

import structlog
import typer
from rich.console import Console
from rich.table import Table

from sdpfuzz2.bluetooth.discovery import DiscoveryService
from sdpfuzz2.bluetooth.l2cap_transport import L2CAPTransport
from sdpfuzz2.bluetooth.probe import ProbeResult, SDPProbe
from sdpfuzz2.config import RuntimeConfig
from sdpfuzz2.domain.errors import TransportError
from sdpfuzz2.domain.models import Device
from sdpfuzz2.fuzzing.cont_state_byte_mutation import ContinuationStateByteMutationStrategy
from sdpfuzz2.fuzzing.cont_state_len_mutation import ContinuationStateLengthMutationStrategy
from sdpfuzz2.fuzzing.random_bytes import TotallyRandomBytesStrategy
from sdpfuzz2.fuzzing.random_mutation import RandomMutationStrategy
from sdpfuzz2.logging.run_logger import RunLogger
from sdpfuzz2.orchestration.runner import FuzzRunner, FuzzRunnerConfig
from sdpfuzz2.orchestration.session import RunStatistics, SessionState

app = typer.Typer(help="Bluetooth SDP fuzzing toolkit")


def setup_logging(verbose: bool) -> None:
    """Configure structlog based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def make_progress_table(stats: RunStatistics, mode: str, target_mac: str, state: str) -> Table:
    table = Table(
        title="SDPFuzz2 Fuzzing Session Status", show_header=True, header_style="bold magenta"
    )
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Target MAC", target_mac)
    table.add_row("Fuzz Mode", mode)
    table.add_row("Session State", state)
    table.add_row("Elapsed Time", f"{stats.elapsed_seconds:.1f}s")
    table.add_row("Packets Sent", str(stats.packets_sent))
    table.add_row("Responses Received", str(stats.packets_received))

    if stats.packets_sent > 0:
        recv_rate = (stats.packets_received / stats.packets_sent) * 100
        table.add_row("Response Rate", f"{recv_rate:.1f}%")
    else:
        table.add_row("Response Rate", "0.0%")

    table.add_row("Timeouts", str(stats.timeouts))
    table.add_row("Errors", str(stats.errors))

    crash_status = "No Crash Detected"
    if stats.crashes_detected > 0:
        crash_status = f"[bold red]CRASH DETECTED ({stats.crashes_detected})[/bold red]"
    table.add_row("Crash Status", crash_status)

    return table


async def update_display_loop(runner: FuzzRunner, mode: str, target_mac: str) -> None:
    from rich.live import Live

    with Live(
        make_progress_table(runner.stats, mode, target_mac, runner.state.value),
        refresh_per_second=4,
    ) as live:
        while runner.state != SessionState.STOPPED:
            live.update(make_progress_table(runner.stats, mode, target_mac, runner.state.value))
            await asyncio.sleep(0.25)
        # Final update
        live.update(make_progress_table(runner.stats, mode, target_mac, runner.state.value))


async def run_fuzzing_main(runner: FuzzRunner, mode: str, target_mac: str, verbose: bool) -> None:
    if verbose:
        typer.echo(f"Starting fuzzing session against {target_mac} (mode: {mode})...")
        await runner.run()
    else:
        runner_task = asyncio.create_task(runner.run())
        display_task = asyncio.create_task(update_display_loop(runner, mode, target_mac))
        try:
            await runner_task
        finally:
            display_task.cancel()
            try:
                await display_task
            except asyncio.CancelledError:
                pass


def select_target_device(devices: Sequence[Device], selected_index: int | None = None) -> Device:
    """Select a single target device from discovered devices."""
    if not devices:
        raise typer.BadParameter("No devices available for selection")

    selected = selected_index
    if selected is None:
        selected = typer.prompt("Select target index", type=int)

    if selected < 1 or selected > len(devices):
        raise typer.BadParameter(f"Target index must be between 1 and {len(devices)}")

    return devices[selected - 1]


def _render_discovered_devices(devices: Sequence[Device]) -> None:
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Name")
    table.add_column("MAC Address")
    for index, device in enumerate(devices, start=1):
        table.add_row(str(index), device.name, device.mac_address)
    Console().print(table)


def _discover_and_select_target(index: int | None) -> Device:
    devices = DiscoveryService().discover(include_unnamed=False)
    if not devices:
        typer.echo("No discoverable named devices found")
        raise typer.Exit(code=1)

    _render_discovered_devices(devices)
    target = select_target_device(devices, selected_index=index)
    typer.echo(f"Selected target: {target.name} ({target.mac_address})")
    return target


def _probe_selected_target(target: Device, response_timeout_ms: int) -> ProbeResult:
    probe = SDPProbe(
        transport=L2CAPTransport(target_mac=target.mac_address),
        response_timeout_ms=response_timeout_ms,
    )
    return probe.collect_initial_state()


def _render_probe_debug(result: ProbeResult) -> None:
    typer.echo("Debug probe details:")
    for index, fragment in enumerate(result.attribute_list_fragments, start=1):
        typer.echo(f"attribute_page[{index}]_hex={fragment.hex()}")

    if result.continuation_states:
        for index, state in enumerate(result.continuation_states, start=1):
            typer.echo(f"continuation_state[{index}]_hex={state.hex()}")
    else:
        typer.echo("continuation_state: none")

    typer.echo(f"combined_attribute_payload_hex={result.full_attribute_list.hex()}")


@app.command()
def version() -> None:
    """Print package version."""
    from sdpfuzz2 import __version__

    typer.echo(__version__)


@app.command()
def scaffold_status() -> None:
    """Show current implementation phase status."""
    typer.echo("Phase 0 scaffolding complete")
    typer.echo("Phase 1 discovery complete")
    typer.echo("Phase 2 SDP probing complete")


@app.command("discover")
def discover_target(index: int | None = typer.Option(None, "--index", "-i")) -> None:
    """Discover nearby devices and select one target device."""
    _discover_and_select_target(index=index)


@app.command("probe")
def probe_target(
    index: int | None = typer.Option(None, "--index", "-i"),
    response_timeout_ms: int = typer.Option(1500, "--response-timeout-ms"),
    debug: bool = typer.Option(False, "--debug"),
) -> None:
    """Discover a target device and run initial valid SDP probe collection."""
    target = _discover_and_select_target(index=index)
    typer.echo(f"Starting SDP probe for {target.mac_address}...")

    try:
        result = _probe_selected_target(target, response_timeout_ms=response_timeout_ms)
    except TransportError as exc:
        typer.echo(f"Probe transport failed: {exc}")
        raise typer.Exit(code=1) from exc

    typer.echo("SDP probe completed")
    typer.echo(f"Attribute pages collected: {len(result.attribute_list_fragments)}")
    typer.echo(f"Continuation states collected: {len(result.continuation_states)}")
    typer.echo(f"Combined attribute payload bytes: {len(result.full_attribute_list)}")

    if debug:
        _render_probe_debug(result)


@app.command("fuzz")
def fuzz_target(
    mode: str | None = typer.Option(
        None,
        "--mode",
        "-m",
        help="Fuzzing mode: random-bytes, continuation-length, continuation-bytes, random-mutation",
    ),
    target: str | None = typer.Option(
        None, "--target", "-t", help="Bluetooth MAC address of the target"
    ),
    concurrency: int = typer.Option(1, "--concurrency", "-c", help="Number of concurrent workers"),
    queue_size: int = typer.Option(64, "--queue-size", help="Maximum queue size for scheduler"),
    max_length: int = typer.Option(
        64, "--max-length", help="Maximum packet length for random bytes strategy"
    ),
    delay: float = typer.Option(0.0, "--delay", help="Inter-packet delay in milliseconds"),
    rate_limit: int = typer.Option(0, "--rate-limit", help="Packets per second limit"),
    seed: int | None = typer.Option(None, "--seed", help="Random seed for reproducible fuzzing"),
    output: str | None = typer.Option(None, "--output", "-o", help="Path to output JSON log file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output for diagnostics"),
) -> None:
    """Start an SDP fuzzing session against a target."""
    # 1. Parameter Validation
    valid_modes = ["random-bytes", "continuation-length", "continuation-bytes", "random-mutation"]
    if mode is not None:
        mode_lower = mode.lower()
        if mode_lower not in valid_modes:
            raise typer.BadParameter(
                f"Invalid fuzzing mode '{mode}'. Available modes are: {', '.join(valid_modes)}"
            )
        mode = mode_lower

    if concurrency < 1:
        raise typer.BadParameter("concurrency must be >= 1")

    if queue_size < 1:
        raise typer.BadParameter("queue-size must be >= 1")

    if max_length < 16:
        raise typer.BadParameter("max-length must be >= 16")

    if delay < 0.0:
        raise typer.BadParameter("delay must be >= 0.0")

    if rate_limit < 0:
        raise typer.BadParameter("rate-limit must be >= 0")

    # 2. Target Device Selection
    if target is None:
        try:
            device = _discover_and_select_target(index=None)
        except Exception as exc:
            typer.echo(f"Discovery failed: {exc}")
            raise typer.Exit(code=1) from exc
    else:
        try:
            device = Device(name="Target Device", mac_address=target)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc

    # 3. Interactive Mode Selection
    if mode is None:
        typer.echo("Available fuzzing modes:")
        typer.echo("1. random-bytes")
        typer.echo("2. continuation-length")
        typer.echo("3. continuation-bytes")
        typer.echo("4. random-mutation")
        try:
            choice = typer.prompt("Select fuzzing mode", type=int)
        except typer.Abort as exc:
            raise typer.Exit(code=1) from exc
        if choice == 1:
            mode = "random-bytes"
        elif choice == 2:
            mode = "continuation-length"
        elif choice == 3:
            mode = "continuation-bytes"
        elif choice == 4:
            mode = "random-mutation"
        else:
            typer.echo("Error: Invalid choice. Please choose a number between 1 and 4.")
            raise typer.Exit(code=1)

    # 4. Perform SDP Probe
    typer.echo(f"Performing initial SDP probe on target {device.mac_address}...")
    try:
        probe_result = _probe_selected_target(device, response_timeout_ms=1500)
    except TransportError as exc:
        typer.echo(f"Probe transport failed: {exc}")
        raise typer.Exit(code=1) from exc

    typer.echo("SDP probe completed successfully.")

    # 5. Initialize Strategy
    if mode == "random-bytes":
        strategy = TotallyRandomBytesStrategy(max_length=max_length, seed=seed)
    elif mode == "continuation-length":
        strategy = ContinuationStateLengthMutationStrategy(seed=seed)
    elif mode == "continuation-bytes":
        if not probe_result.continuation_states:
            typer.echo(
                "Error: No continuation states collected from target device. "
                "continuation-bytes mode requires at least one continuation state."
            )
            raise typer.Exit(code=1)
        strategy = ContinuationStateByteMutationStrategy(
            valid_continuation_states=probe_result.continuation_states,
            seed=seed,
        )
    elif mode == "random-mutation":
        strategy = RandomMutationStrategy(seed=seed)
    else:
        raise typer.BadParameter(f"Unknown fuzzing mode: {mode}")

    # 6. Initialize RunLogger & Output Configuration
    if output is not None:
        output_path = Path(output)
    else:
        log_dir = Path(os.environ.get("SDPFUZZ2_LOG_DIR", "fuzz_logs"))
        mac_clean = device.mac_address.replace(":", "-")
        timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"fuzz_{timestamp}_{mac_clean}.json"
        output_path = log_dir / filename

    run_logger = RunLogger(
        output_path=output_path,
        device_name=device.name,
        device_mac_address=device.mac_address,
        fuzz_mode=mode,
    )

    # 7. Setup Logging Verbosity
    setup_logging(verbose=verbose)

    # 8. Setup Runner Config
    runtime_config = RuntimeConfig(
        concurrency=concurrency,
        queue_size=queue_size,
        response_timeout_ms=1500,
    )
    runner_config = FuzzRunnerConfig(
        runtime_config=runtime_config,
        stop_on_crash=True,
    )

    runner = FuzzRunner(
        strategy=strategy,
        transport_factory=lambda: L2CAPTransport(target_mac=device.mac_address),
        run_logger=run_logger,
        config=runner_config,
        delay_ms=delay,
        rate_limit=rate_limit,
    )

    # 9. Run Fuzz Session
    try:
        asyncio.run(run_fuzzing_main(runner, mode, device.mac_address, verbose))
    except Exception as exc:
        typer.echo(f"Fuzzing session encountered an error: {exc}")
        raise typer.Exit(code=1) from exc

    # 10. Display Session Summary
    typer.echo("\n--- Fuzzing Session Summary ---")
    typer.echo(f"Target MAC:         {device.mac_address}")
    typer.echo(f"Fuzz Mode:          {mode}")
    typer.echo(f"Elapsed Time:       {runner.stats.elapsed_seconds:.1f}s")
    typer.echo(f"Packets Sent:       {runner.stats.packets_sent}")
    typer.echo(f"Responses Received: {runner.stats.packets_received}")
    typer.echo(f"Timeouts:           {runner.stats.timeouts}")
    typer.echo(f"Errors:             {runner.stats.errors}")
    typer.echo(f"Crashes Detected:   {runner.stats.crashes_detected}")
    typer.echo(f"Log Path:           {output_path.resolve()}")

    if runner.stats.crashes_detected > 0:
        typer.echo("Session stopped due to crash detection.")
        raise typer.Exit(code=2)
    else:
        typer.echo("Session completed successfully.")
