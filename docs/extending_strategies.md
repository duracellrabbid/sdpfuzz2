# Extending Fuzzing Strategies

This document provides a guide and code examples on how to implement and integrate a new fuzzing strategy in SDPFuzz2.

## 1. Implementing the `FuzzingStrategy` Interface

All fuzzing strategies must inherit from `FuzzingStrategy` defined in [src/sdpfuzz2/fuzzing/base.py](file:///D:/Shared/sdpfuzz2/src/sdpfuzz2/fuzzing/base.py) and implement the abstract method `next_packet() -> bytes`.

### Example: Implementing a Custom UUID Mutation Strategy
Below is an example of a custom strategy that mutates the Service Search UUID list in a template request:

```python
# src/sdpfuzz2/fuzzing/uuid_mutation.py

import random
from sdpfuzz2.fuzzing.base import FuzzingStrategy
from sdpfuzz2.sdp.packet_builder import build_service_search_attribute_request

class UUIDMutationStrategy(FuzzingStrategy):
    """Mutate service search request UUIDs to find parsing errors in vendor stacks."""

    def __init__(self, target_uuid_base: int = 0x1100, seed: int | None = None) -> None:
        self._target_uuid_base = target_uuid_base
        self._rng = random.Random(seed)
        self._tx_id = 1

    def next_packet(self) -> bytes:
        # Generate a random 16-bit UUID around our target base
        mutated_uuid = self._target_uuid_base + self._rng.randint(0, 0xFF)

        # Build request with custom transaction ID
        packet = build_service_search_attribute_request(
            transaction_id=self._tx_id,
            service_search_pattern=[mutated_uuid],
            continuation_state=b""
        )

        # Increment transaction ID
        self._tx_id = 1 if self._tx_id >= 0xFFFF else self._tx_id + 1
        return packet
```

---

## 2. Registering the New Strategy in the CLI

To expose your new strategy to the `sdpfuzz2 fuzz` command, follow these steps:

1. **Add option to the `--mode` parameter choices** in [src/sdpfuzz2/cli.py](file:///D:/Shared/sdpfuzz2/src/sdpfuzz2/cli.py):
   ```python
   # Inside fuzz_target() parameter validation:
   valid_modes = [
       "random-bytes",
       "continuation-length",
       "continuation-bytes",
       "random-mutation",
       "uuid-mutation"  # Add your mode here
   ]
   ```
2. **Display in the interactive mode prompt** if the mode is not specified:
   ```python
   # Inside interactive mode selection:
   typer.echo("5. uuid-mutation")
   # ...
   elif choice == 5:
       mode = "uuid-mutation"
   ```
3. **Instantiate the strategy** inside the strategy selection block:
   ```python
   # Inside fuzz_target() strategy initialization:
   elif mode == "uuid-mutation":
       # You can define custom CLI options or read CLI defaults
       strategy = UUIDMutationStrategy(target_uuid_base=0x1100, seed=seed)
   ```

---

## 3. Writing Contract Tests

Ensure you write tests to assert that your strategy produces valid outputs, behaves deterministically when a seed is provided, and is task-safe:

```python
# tests/unit/test_uuid_mutation_strategy.py

from sdpfuzz2.fuzzing.uuid_mutation import UUIDMutationStrategy

def test_uuid_mutation_strategy_seeded_determinism() -> None:
    strategy1 = UUIDMutationStrategy(seed=42)
    strategy2 = UUIDMutationStrategy(seed=42)

    # Assert sequences match exactly
    assert [strategy1.next_packet() for _ in range(10)] == [strategy2.next_packet() for _ in range(10)]
```
