"""
Target adapters for the validate-findings harness.

Each adapter knows how to:
  - preflight()  — verify reachability and capture a fingerprint
  - classify()   — safe | mutating | destructive for a given verb/payload
  - execute()    — run a single plan step and return a StepResult
  - rollback()   — undo a mutating step where possible

Thread safety: get_adapter() returns shared singletons whose mutable state
(e.g. K8sAdapter rate-limiting) is protected by threading.Lock. Multiple
executor threads may safely call get_adapter() and execute() concurrently.
Use new_adapter() if you need an independent instance with its own state.
"""

import sys
from pathlib import Path

# Allow `from adapters import ...` when validate-findings/ is on sys.path
# AND `from .adapters import ...` when used as a subpackage.
if not __package__:
    sys.path.insert(0, str(Path(__file__).parent))

from .base import AdapterBase, Fingerprint, StepResult
from .container import ContainerAdapter
from .k8s import K8sAdapter
from .wasm import WasmAdapter

TARGET_ADAPTERS: dict[str, AdapterBase] = {
    "k8s": K8sAdapter(),
    "container": ContainerAdapter(),
    "wasm": WasmAdapter(),
}

_ADAPTER_CLASSES: dict[str, type[AdapterBase]] = {
    "k8s": K8sAdapter,
    "container": ContainerAdapter,
    "wasm": WasmAdapter,
}


def get_adapter(name: str) -> AdapterBase:
    """Return the shared singleton adapter for *name*."""
    try:
        return TARGET_ADAPTERS[name]
    except KeyError as e:
        raise ValueError(f"unknown adapter: {name!r}") from e


def new_adapter(name: str) -> AdapterBase:
    """Return a fresh adapter instance with independent state."""
    try:
        return _ADAPTER_CLASSES[name]()
    except KeyError as e:
        raise ValueError(f"unknown adapter: {name!r}") from e


__all__ = [
    "TARGET_ADAPTERS",
    "AdapterBase",
    "ContainerAdapter",
    "Fingerprint",
    "K8sAdapter",
    "StepResult",
    "WasmAdapter",
    "get_adapter",
    "new_adapter",
]
