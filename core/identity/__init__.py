"""
CoworkGuard Core — Identity Layer
Phase 1: Actor identity, session tracking, event stamping.
"""
from .actor_stamper import stamp_event, update_registry, get_registry, confidence_copy
from .session_tracker import update_session, get_session_id, build_actor_registry_payload

__all__ = [
    "stamp_event",
    "update_registry",
    "get_registry",
    "confidence_copy",
    "update_session",
    "get_session_id",
    "build_actor_registry_payload",
]
