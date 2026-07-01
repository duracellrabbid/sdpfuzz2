"""Replay execution controller."""

import asyncio
from collections.abc import Callable

from sdpfuzz2.bluetooth.l2cap_transport import L2CAPTransport
from sdpfuzz2.bluetooth.transport import Transport
from sdpfuzz2.logging.corpus_manager import CorpusManager


class ReplayController:
    """Controls sequential replay of saved corpus sequences."""

    def __init__(
        self,
        corpus_manager: CorpusManager,
        transport_factory_builder: Callable[[str], Callable[[], Transport]] | None = None,
    ) -> None:
        """Initialize ReplayController."""
        self.corpus_manager = corpus_manager
        self.transport_factory_builder = transport_factory_builder or (
            lambda mac: lambda: L2CAPTransport(target_mac=mac)
        )

    async def replay(
        self,
        seq_id: str,
        target_mac: str,
        loop_count: int = 1,
        delay_ms: float = 0.0,
    ) -> bool:
        """Replay sequence, returning True if crash/timeout occurs, False otherwise."""
        packets = self.corpus_manager.load_packets(seq_id)
        if not packets:
            raise ValueError(f"Sequence {seq_id} has no packets to replay.")

        transport_factory = self.transport_factory_builder(target_mac)

        for _ in range(loop_count):
            transport = transport_factory()
            try:
                for packet in packets:
                    transport.send(packet)
                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000.0)
                    # Receive response (1500ms timeout default)
                    _ = transport.receive(1500)
            except Exception:
                # Any exception represents a failure (timeout or crash)
                return True
            finally:
                try:
                    close_fn = getattr(transport, "close", None)
                    if close_fn is not None:
                        close_fn()
                except Exception:
                    pass

        return False
