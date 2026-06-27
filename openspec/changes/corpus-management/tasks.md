## 1. Corpus Storage and Index Database

- [ ] 1.1 Create `src/sdpfuzz2/logging/corpus_manager.py` with SQLite database setup
- [ ] 1.2 Implement database CRUD operations for listing and inserting sequences
- [ ] 1.3 Implement binary sequence reader and writer using length-prefixed packet serialization
- [ ] 1.4 Write unit tests for SQLite index storage and binary sequence serialization

## 2. Sliding History and Automatic Saving

- [ ] 2.1 Add sliding history circular queue using `collections.deque` in `FuzzRunner`
- [ ] 2.2 Add CLI argument `--sequence-length / -n` to configure circular queue size
- [ ] 2.3 Integrate auto-save hooks in `FuzzRunner._loop` for crash and timeout candidates
- [ ] 2.4 Write unit and integration tests for packet history and failure auto-save hooks

## 3. Replay and Corpus Mutation

- [ ] 3.1 Implement replay execution path sending sequence packets sequentially through L2CAPTransport
- [ ] 3.2 Add dynamic target MAC resolution (explicit override via CLI or interactive discovery fallback) to replay
- [ ] 3.3 Add loop iteration `--loop` parameter support to the replay loop execution
- [ ] 3.4 Add fallback trigger to transition to corpus-mutation fuzzing if replay fails to crash target
- [ ] 3.5 Implement `CorpusMutationStrategy` that loads seeds from SQLite index and applies `flip_bytes` mutators
- [ ] 3.6 Write unit tests for replay controller and corpus mutation strategy

## 4. CLI Menu and Cleanup Sweep

- [ ] 4.1 Implement interactive CLI menu under `sdpfuzz2 corpus` (list, replay, fuzz) with device selection prompts
- [ ] 4.2 Implement `sdpfuzz2 clean` command to sync SQLite records and remove orphan `.bin` files
- [ ] 4.3 Write integration tests for CLI commands and clean operations
