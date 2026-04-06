"""CLI entrypoint for SDPFuzz2."""

import typer

app = typer.Typer(help="Bluetooth SDP fuzzing toolkit")


@app.command()
def version() -> None:
    """Print package version."""
    from sdpfuzz2 import __version__

    typer.echo(__version__)


@app.command()
def scaffold_status() -> None:
    """Show current implementation phase status."""
    typer.echo("Phase 0 scaffolding complete")
