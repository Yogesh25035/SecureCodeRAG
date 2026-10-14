import secrets
import time
import uuid as _stdlib_uuid


def uuid7(timestamp=None, nanos=None):
    """Minimal UUID v7 implementation used as a compatibility shim for LangChain/LangSmith.

    This avoids the blocked native `uuid_utils` DLL on Windows while preserving the
    API consumed by the app: `uuid_utils.compat.uuid7(timestamp=..., nanos=...)`.
    """
    if timestamp is None and nanos is None:
        unix_ms = time.time_ns() // 1_000_000
    elif timestamp is not None:
        unix_ms = ((int(timestamp) * 1_000_000_000) + (int(nanos or 0))) // 1_000_000
    else:
        unix_ms = int(time.time_ns() // 1_000_000)

    random_bits = secrets.randbits(74)
    b = bytearray(16)
    b[0:6] = (unix_ms & 0xFFFFFFFFFFFF).to_bytes(6, byteorder="big")
    b[6] = 0x70 | ((random_bits >> 70) & 0x0F)
    b[7] = (random_bits >> 62) & 0xFF
    b[8] = 0x80 | ((random_bits >> 56) & 0x3F)
    b[9:16] = ((random_bits & ((1 << 56) - 1)).to_bytes(7, byteorder="big"))
    return _stdlib_uuid.UUID(bytes=bytes(b))


__all__ = ["uuid7"]
