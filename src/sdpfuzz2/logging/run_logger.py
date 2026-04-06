"""Run log writer."""

import json
from pathlib import Path

from sdpfuzz2.domain.models import RunLog


class RunLogger:
    """Persists run logs in JSON format."""

    def __init__(self, output_path: Path) -> None:
        self.output_path = output_path

    def write(self, run_log: RunLog) -> None:
        self.output_path.write_text(json.dumps(run_log.to_dict(), indent=2), encoding="utf-8")
