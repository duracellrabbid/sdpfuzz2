## Why

Currently, when SDPFuzz2 discovers a timeout or crash, the details are written to JSON logs, but there is no mechanism to save the raw packet sequences in a format that can be easily replayed for reproduction or mutated to explore deeper vulnerability states. Introducing corpus management solves this by letting developers automatically capture, replay, and mutate high-value fuzzing sequences.

## What Changes

- Add a new hybrid storage corpus database containing a SQLite index (`corpus.db`) and raw binary packet sequences (`.bin` files using length-prefixed format).
- Modify the fuzzing loop to maintain a sliding history of the last `N` packets sent across all workers.
- Automatically save the sliding window history when a crash or timeout candidate is detected.
- Implement Workflow A (Deterministic Replay) to rerun saved sequences against a target.
- Implement Workflow B (Corpus-Mutation Fuzzing) to select saved packets, mutate them, and fuzz with feedback.
- Introduce `sdpfuzz2 clean` to scan and remove orphaned database records or binary files.
- Introduce interactive CLI menus under `sdpfuzz2 corpus` for sequence listing and actions.

## Capabilities

### New Capabilities
- `corpus-management`: Storing, querying, replaying, and mutating interesting packet sequences.

### Modified Capabilities
<!-- None -->

## Impact

- `src/sdpfuzz2/cli.py`: New Typer commands for `sdpfuzz2 corpus` and `sdpfuzz2 clean`.
- `src/sdpfuzz2/orchestration/runner.py`: Integration of packet history tracking and automatic corpus recording.
- `src/sdpfuzz2/logging/corpus_manager.py`: Implementation of SQLite index queries, file I/O for sequence `.bin` files, and cleanup sweeps.
- `src/sdpfuzz2/fuzzing/corpus_mutation.py`: New `CorpusMutationStrategy` to flip bytes and fuzz using corpus seeds.
