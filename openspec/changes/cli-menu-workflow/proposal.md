## Why

Running the tool currently requires executing multiple separate command-line invocations (`discover`, `probe`, `fuzz`, `corpus`, `clean`), causing cognitive load and friction for users. A single interactive entrypoint improves the CLI user experience significantly.

## What Changes

- Introduce an interactive main menu when running the `sdpfuzz2` command without any subcommand.
- Implement a streamlined "Discover & Fuzz Target" workflow that performs scanning, selection, probing, mode selection, and runs fuzzing in one continuous interactive session.
- Integrate a sub-menu for corpus management activities (listing, replaying, corpus fuzzing).
- Add interactive menu entries for standalone discovery, probing, and cleanup.

## Capabilities

### New Capabilities
- `cli-interactive-menu`: Orchestrates the interactive CLI dashboard, prompts, and unified flow for device scanning, selection, probing, and fuzzing execution.

### Modified Capabilities
<!-- None -->

## Impact

- `src/sdpfuzz2/cli.py`: Introduce main app callback (`@app.callback(invoke_without_command=True)`) and menu navigation loop.
- No impact on core fuzzing logic, L2CAP socket code, or data structures.
