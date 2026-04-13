"""CLI entrypoint for SDPFuzz2."""

from collections.abc import Sequence

import typer

from sdpfuzz2.bluetooth.discovery import DiscoveryService
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
    typer.echo("Phase 2 fuzzing in progress")


@app.command("discover")
def discover_target(index: int | None = typer.Option(None, "--index", "-i")) -> None:
    """Discover nearby devices and select one target device."""
    devices = DiscoveryService().discover(include_unnamed=False)
    if not devices:
        typer.echo("No discoverable named devices found")
        raise typer.Exit(code=1)

    _render_discovered_devices(devices)
    target = select_target_device(devices, selected_index=index)
    typer.echo(f"Selected target: {target.name} ({target.mac_address})")
