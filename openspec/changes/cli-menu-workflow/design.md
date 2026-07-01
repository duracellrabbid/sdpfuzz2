## Context

SDPFuzz2 currently registers several subcommands via Typer (e.g., `discover`, `probe`, `fuzz`, `clean`, and the `corpus` app). To run a fuzzing session, users must run `discover` to find the target, `probe` to inspect its state, and then `fuzz` with multiple flags. This workflow requires running the tool multiple times and copying values (like MAC addresses).

We will introduce an interactive main menu when running the `sdpfuzz2` command without any subcommand, combining discovery, probing, and fuzzing into a unified prompt flow.

## Goals / Non-Goals

**Goals:**
- Present a rich CLI main menu when running `sdpfuzz2` with no arguments.
- Maintain full backward compatibility so all existing subcommands (`fuzz`, `discover`, `probe`, etc.) function normally.
- Provide a unified "Discover & Fuzz" workflow that performs scanning, selection, probing, mode choosing, and immediately starts fuzzing in a single session.
- Integrate the interactive corpus submenu directly.

**Non-Goals:**
- Modifying core fuzzing, networking, or database mechanics.
- Introducing heavy interactive terminal libraries (e.g., Textual, prompt_toolkit).

## Decisions

### 1. Main Typer Callback
- **Decision**: Implement a main callback `@app.callback(invoke_without_command=True)` on the root `app`.
- **Rationale**: Allows the root command to intercept execution when no subcommand is specified, without altering the behavior of existing subcommands.
- **Alternatives Considered**:
  - Creating a separate `menu` subcommand: Rejected because running `sdpfuzz2` with no arguments is the standard UX pattern for interactive tools.

### 2. Interactive Flow Re-use
- **Decision**: Extract and modularize device selection, probe execution, and fuzz runner initialization so they can be invoked cleanly from both the standalone subcommands and the interactive menu.
- **Rationale**: Prevents code duplication and ensures that fuzzing settings (concurrency, queue sizes, delays) use safe defaults during interactive execution.

### 3. CLI Prompts with Standard Typer & Rich
- **Decision**: Use `typer.prompt` and `rich` tables/formatting.
- **Rationale**: Keeps the codebase free of complex text-based user interface (TUI) dependencies, keeping the package size and installation footprint minimal.

## Risks / Trade-offs

- **[Risk]** Main callback running on every subcommand execution.
  - *Mitigation*: The callback must inspect `ctx.invoked_subcommand` and exit early if it is not `None`.
- **[Risk]** Complex test mocking for interactive menus.
  - *Mitigation*: Structuring menu paths cleanly so `CliRunner` can pass sequential string inputs (e.g., `"1\n1\n1\n"`) to simulate standard operations.
