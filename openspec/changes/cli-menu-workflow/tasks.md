## 1. Setup and Framework

- [ ] 1.1 Add `@app.callback(invoke_without_command=True)` to `src/sdpfuzz2/cli.py` to capture direct root command execution
- [ ] 1.2 Implement checks inside the callback to inspect `ctx.invoked_subcommand` and exit early if a subcommand is specified

## 2. Interactive Menu Layout and Standalone Options

- [ ] 2.1 Implement the main interactive menu display using `rich` styling and `typer.prompt` selection
- [ ] 2.2 Wire up the Standalone Discovery option (Option 3) to execute target device scanning
- [ ] 2.3 Wire up the Standalone Probing option (Option 4) to scan, select, and run initial SDP probe
- [ ] 2.4 Wire up the Cleanup Corpus option (Option 5) to clean database records and orphaned files

## 3. Unified Discover & Fuzz Target Option

- [ ] 3.1 Implement the interactive "Discover & Fuzz Target" option (Option 1) combining discovery, target selection, and initial SDP probing
- [ ] 3.2 Add the fuzzing mode interactive selection prompt (modes 1-4)
- [ ] 3.3 Construct and run the `FuzzRunner` using the selected target, mode, and default config parameters

## 4. Corpus Management Submenu

- [ ] 4.1 Restructure the existing `corpus_main` interactive menu to be fully navigable from the main menu (Option 2)
- [ ] 4.2 Add navigation links to transition back to the main menu from the corpus submenu

## 5. Verification and Testing

- [ ] 5.1 Add CLI unit tests covering root app callback execution and menu prompt mocks
- [ ] 5.2 Add unit tests for Option 1 (Discover & Fuzz Target) ensuring discovery leads immediately to probing and fuzzing
- [ ] 5.3 Add unit tests for Standalone Discovery, Probing, and Corpus Management options in the main menu
- [ ] 5.4 Run black, ruff, mypy, and pytest to ensure complete test coverage and no regressions
