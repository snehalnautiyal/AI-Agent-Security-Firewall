"""
Session store — keeps an in-memory log of every request/response pair
scanned during a GuardLayer session. Persisted to JSON on demand.
"""

from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from guardlayer.models import ScanResult, SessionRecord


class SessionStore:
    """Thread-safe in-memory store for scan records."""

    def __init__(self) -> None:
        # All records for the current session, keyed by record_id
        self._records: dict[str, SessionRecord] = {}

    def new_record(self, target_url: str, request_scan: ScanResult) -> SessionRecord:
        """Create and store a new record when a request arrives."""
        record = SessionRecord(
            record_id=str(uuid.uuid4()),
            timestamp=datetime.now(tz=timezone.utc),
            target_url=target_url,
            request_scan=request_scan,
            was_blocked=request_scan.blocked,
        )
        self._records[record.record_id] = record
        return record

    def update_response(self, record_id: str, response_scan: ScanResult) -> None:
        """Attach the response scan result to an existing record."""
        record = self._records.get(record_id)
        if record:
            record.response_scan = response_scan
            if response_scan.blocked:
                record.was_blocked = True

    def all_records(self) -> list[SessionRecord]:
        """Return all records sorted oldest-first."""
        return sorted(self._records.values(), key=lambda r: r.timestamp)

    def blocked_count(self) -> int:
        """Count how many requests were blocked this session."""
        return sum(1 for r in self._records.values() if r.was_blocked)

    def save_json(self, output_path: Path) -> None:
        """Dump all records to a JSON file for offline inspection."""
        data = [record.model_dump(mode="json") for record in self.all_records()]
        output_path.write_text(json.dumps(data, indent=2, default=str))


# Module-level singleton shared across the proxy and CLI
store = SessionStore()
