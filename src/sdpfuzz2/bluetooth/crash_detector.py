"""Crash detection heuristics placeholder."""


class CrashDetector:
    """Classifies likely target crash events during fuzzing."""

    def should_stop(self) -> bool:
        """Return whether current heuristics indicate fuzzing should stop.

        This remains a placeholder until the crash-detection phase is implemented.
        """
        return False
