import time
from datetime import datetime
from watchdog.events import FileSystemEventHandler
from rich.console import Console
from core.hasher import IntegrityHasher

console = Console()

class FIMEventHandler(FileSystemEventHandler):
    """
    Listens for live filesystem events (modify, create, delete, move)
    and validates them against cryptographic hashes in real time.
    """

    def __init__(self, monitored_paths=None):
        super().__init__()
        self.monitored_paths = set(monitored_paths or [])

    def _log_alert(self, event_type: str, src_path: str, severity: str, details: str):
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
        color = "red" if severity == "CRITICAL" else "yellow"
        console.print(
            f"[{color}][!] LIVE EVENT DETECTED [{severity}][/{color}] "
            f"[dim]{timestamp}[/dim] -> [bold white]{src_path}[/bold white] "
            f"([cyan]{event_type}[/cyan]): {details}"
        )

    def on_modified(self, event):
        if event.is_directory:
            return
        meta = IntegrityHasher.get_file_metadata(event.src_path)
        sha_preview = meta["sha256"][:16] + "..." if meta and meta.get("sha256") else "N/A"
        self._log_alert(
            event_type="FILE_MODIFIED",
            src_path=event.src_path,
            severity="CRITICAL",
            details=f"Live write detected. Updated SHA-256: {sha_preview}"
        )

    def on_created(self, event):
        if event.is_directory:
            return
        self._log_alert(
            event_type="FILE_CREATED",
            src_path=event.src_path,
            severity="HIGH",
            details="New file created inside monitored security boundary."
        )

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._log_alert(
            event_type="FILE_DELETED",
            src_path=event.src_path,
            severity="CRITICAL",
            details="Target asset unlinked/deleted from disk."
        )

    def on_moved(self, event):
        self._log_alert(
            event_type="FILE_MOVED",
            src_path=event.src_path,
            severity="HIGH",
            details=f"Asset moved or renamed to {event.dest_path}"
        )
