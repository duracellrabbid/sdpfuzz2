"""CLI entrypoint for SDPFuzz2."""

from collections.abc import Sequence

import typer

from sdpfuzz2.bluetooth.discovery import DiscoveryService
from sdpfuzz2.bluetooth.l2cap_transport import L2CAPTransport
from sdpfuzz2.bluetooth.probe import ProbeResult, SDPProbe
from sdpfuzz2.domain.errors import TransportError
from sdpfuzz2.domain.models import Device

app = typer.Typer(help="Bluetooth SDP fuzzing toolkit")


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
    for index, device in enumerate(devices, start=1):
        typer.echo(f"[{index}] {device.name} - {device.mac_address}")


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
