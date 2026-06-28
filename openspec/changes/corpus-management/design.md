## Context

The fuzzer currently runs in an ephemeral mode where any discovered crash or timeout triggers are logged in JSON, but cannot be easily re-executed. There is no automated workflow to feed interesting payloads back into the fuzzing strategy. A local corpus management database solves this by recording execution sequences of size `N` leading up to crashes or timeouts.

## Goals / Non-Goals

**Goals:**
- Implement a local hybrid storage database using SQLite for indexing (`corpus.db`) and length-prefixed binary files for raw packet sequences (`.bin`).
- Maintain a sliding window history of the last `N` sent request packets across all concurrent workers.
- Automatically write history to the corpus upon crash detection or timeout candidate detection.
- Provide a CLI interface (`sdpfuzz2 corpus`) to list, replay (Workflow A), and fuzz using mutated corpus seeds (Workflow B).
- Provide a CLI synchronization command (`sdpfuzz2 clean`) to prune missing records or files.

**Non-Goals:**
- Network-based corpus sharing or remote database syncing.
- Crash sequence minimization (reducing `N` packets to the minimal reproducer).
- Advanced response anomaly detection (such as opcode classification, which is deferred to response parsing capability).

## Decisions

### SQLite Index with Length-Prefixed Binary Files
We considered storing everything in a single massive JSON file or SQLite BLOBs.
- **Massive JSON**: Requires parsing and rewriting the entire database on every write/delete. Inefficient as the corpus grows.
- **SQLite BLOBs**: Keeps database size extremely large and makes extraction of individual `.bin` files for standalone analysis difficult.
- **Chosen Alternative**: A hybrid approach. SQLite stores metadata and metadata paths, and raw packet sequences are stored in `.bin` files. The `.bin` files use a custom `[PacketCount][Packet1Length][Packet1Payload]...` binary layout to preserve exact raw bytes and prevent unicode/hex conversion overhead.

### Circular Deque in FuzzRunner
We considered having each worker record its own packet history.
- **Worker History**: Doesn't capture interleaving packet execution from concurrent workers that might collectively trigger a crash.
- **Chosen Alternative**: A global thread-safe sliding history (`collections.deque`) in the `FuzzRunner`. This captures the exact interleaving order of sent packets across all concurrency lanes.

### Target Selection for Replay
To ensure the fuzzer does not assume the original target MAC address stored in sequence metadata, replay targets are resolved dynamically:
- **Explicit Override**: If the `--target` CLI parameter is provided, the fuzzer uses that MAC address for transport initialization.
- **Interactive Selector**: If no target is passed, the fuzzer triggers the target device discovery and selection workflow, letting the user select a device from the list.

### Replay Fallback and Looping
We considered simple one-shot execution for replay triggers.
- **One-Shot Only**: Risks missing flaky, timing-sensitive, or state-sensitive crashes.
- **Chosen Alternative**: Support two CLI options:
  - `--loop <count>`: Repeat the sequence execution up to `<count>` times to stress-test target.
  - `--mutate-on-fail`: If replay doesn't trigger a crash, automatically pivot to corpus-mutation fuzzing using this sequence as the seed.

## Risks / Trade-offs

- **[Risk]** Target MAC addresses change between different lab setups.
  - **Mitigation**: Allow overriding the target MAC address at CLI replay time.
- **[Risk]** Database index records and `.bin` files become unsynced if the user manually deletes files.
  - **Mitigation**: Implement `sdpfuzz2 clean` to scan both disk and database, removing any records with missing `.bin` files and deleting orphan `.bin` files.
- **[Risk]** Interleaved concurrency noise in sequence length `N`.
  - **Mitigation**: Allow configuring `N` via the `--sequence-length` CLI flag to tune the window size depending on active worker concurrency.
