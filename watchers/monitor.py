import os
import time
from watchdog.observers import Observer
from rich.console import Console
from watchers.event_handler import FIMEventHandler

console = Console()

class RealtimeMonitor:
    """
    Spawns inotify/watchdog observation threads to monitor filesystem paths.
    """

    def __init__(self, targets_config):
        self.config = targets_config
        self.observer = Observer()
        self.event_handler = FIMEventHandler()

    def start(self):
        watch_count = 0
        directories_to_watch = set()

        # Extract parent directories of monitored files
        for fpath in self.config.get("monitored_files", []):
            parent = os.path.dirname(fpath)
            if os.path.exists(parent):
                directories_to_watch.add(parent)

        # Include explicit monitored directories
        for dpath in self.config.get("monitored_directories", []):
            if os.path.exists(dpath):
                directories_to_watch.add(dpath)

        for directory in directories_to_watch:
            try:
                self.observer.schedule(self.event_handler, path=directory, recursive=False)
                watch_count += 1
            except Exception as e:
                console.print(f"[dim yellow][!] Warning: Could not monitor {directory}: {e}[/dim yellow]")

        console.print(f"[bold green]✔ Active Real-Time Guard:[/bold green] Monitoring {watch_count} directory paths.")
        console.print("[dim]Press Ctrl + C to stop the watcher...[/dim]\n")

        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow][*] Stopping real-time integrity monitor observer...[/yellow]")
            self.observer.stop()
        self.observer.join()
