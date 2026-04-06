"""Enums used across fuzzing orchestration."""

from enum import Enum


class FuzzMode(str, Enum):
    """Available fuzzing strategy names."""

    TOTALLY_RANDOM_BYTES = "totally_random_bytes"
    CONT_STATE_LEN_MUTATION = "cont_state_len_mutation"
    CONT_STATE_RANDOM_BYTES = "cont_state_random_bytes"
    RANDOM_MUTATION = "random_mutation"
