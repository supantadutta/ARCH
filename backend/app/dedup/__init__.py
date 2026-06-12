"""Finding deduplication package."""

from app.dedup.deduplicator import (  # noqa: F401
    DuplicateMatch,
    compute_signature,
    deduplicate_finding,
    deduplicate_program,
    find_duplicate_candidates,
)
