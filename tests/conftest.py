from typing import Any

import pytest


def pytest_collection_modifyitems(config: Any, items: list[Any]) -> None:
    for item in items:
        # Check if the test is under tests/integration
        path = str(item.fspath).replace("\\", "/")
        if "tests/integration" in path:
            item.add_marker(pytest.mark.integration)
