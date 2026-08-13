"""Watch mode (extra F15): re-scan on file changes.

Uses ``watchdog`` to observe a project directory and re-trigger a ``--diff``
scan after a short quiet period, giving near-real-time feedback while the
developer edits code.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

DEFAULT_IGNORE_SEGMENTS = (
    ".git",
    ".mado",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".coverage",
)


def should_ignore_event(path: str, ignore_segments: tuple[str, ...] = DEFAULT_IGNORE_SEGMENTS) -> bool:
    """Return True when a filesystem event should not trigger a re-scan."""
    parts = Path(path).parts
    for part in parts:
        if part in ignore_segments:
            return True
    return False


class DebouncedHandler(FileSystemEventHandler):
    """Coalesce rapid filesystem events into a single scan trigger."""

    def __init__(
        self,
        trigger: Callable[[], None],
        debounce: float = 0.5,
        ignore_segments: tuple[str, ...] = DEFAULT_IGNORE_SEGMENTS,
    ) -> None:
        self.trigger = trigger
        self.debounce = debounce
        self.ignore_segments = ignore_segments
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if isinstance(event.src_path, bytes):
            return
        if should_ignore_event(event.src_path, self.ignore_segments):
            return
        self._schedule()

    def _schedule(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self.debounce, self._fire)
            self._timer.daemon = True
            self._timer.start()

    def _fire(self) -> None:
        try:
            self.trigger()
        finally:
            with self._lock:
                self._timer = None

    def stop(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None


class WatchMode:
    """Observe a directory and run a callback when the code changes."""

    def __init__(
        self,
        root: str | Path,
        scan_callback: Callable[[], None],
        debounce: float = 0.5,
        ignore_segments: tuple[str, ...] = DEFAULT_IGNORE_SEGMENTS,
    ) -> None:
        self.root = str(Path(root).resolve())
        self.scan_callback = scan_callback
        self.debounce = debounce
        self.ignore_segments = ignore_segments

    def run(self) -> None:
        """Block, watching the directory until interrupted (Ctrl-C)."""
        handler = DebouncedHandler(
            trigger=self.scan_callback,
            debounce=self.debounce,
            ignore_segments=self.ignore_segments,
        )
        observer = Observer()
        observer.schedule(handler, self.root, recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            observer.stop()
            observer.join()
            handler.stop()
