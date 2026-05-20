from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Optional

from security_scanner.models import ScanResult


class Priority(IntEnum):
    HIGH = 0
    NORMAL = 1
    LOW = 2


class TaskStatus(str):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanTask:
    task_id: str = ""
    path: Path = Path()
    priority: Priority = Priority.NORMAL
    options: dict[str, Any] = field(default_factory=dict)
    status: str = TaskStatus.PENDING
    progress_current: int = 0
    progress_total: int = 0
    progress_label: str = ""
    result: Optional[ScanResult] = None
    error: Optional[str] = None
    created_at: float = 0.0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    def __post_init__(self):
        if not self.task_id:
            self.task_id = uuid.uuid4().hex[:12]
        if not self.created_at:
            self.created_at = time.time()

    @property
    def duration_ms(self) -> int:
        start = self.started_at or self.created_at
        end = self.completed_at or time.time()
        return int((end - start) * 1000)

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "path": str(self.path),
            "priority": self.priority.name,
            "status": self.status,
            "progress_current": self.progress_current,
            "progress_total": self.progress_total,
            "progress_label": self.progress_label,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "created_at": self.created_at,
        }


ProgressCallback = Callable[[str, int, int], None]


class ScanQueue:
    def __init__(self):
        self._lock = threading.Lock()
        self._tasks: dict[str, ScanTask] = {}
        self._pending: list[str] = []
        self._running: Optional[str] = None
        self._stop_events: dict[str, threading.Event] = {}
        self._on_task_complete: Optional[Callable[[ScanTask], None]] = None
        self._on_task_progress: Optional[Callable[[ScanTask, str, int, int], None]] = None

    def set_on_complete(self, callback: Optional[Callable[[ScanTask], None]]) -> None:
        self._on_task_complete = callback

    def set_on_progress(self, callback: Optional[Callable[[ScanTask, str, int, int], None]]) -> None:
        self._on_task_progress = callback

    def enqueue(self, path: Path, priority: Priority = Priority.NORMAL,
                options: Optional[dict[str, Any]] = None) -> str:
        task = ScanTask(
            path=path,
            priority=priority,
            options=options or {},
        )
        with self._lock:
            self._tasks[task.task_id] = task
            self._pending.insert(0 if priority == Priority.HIGH else len(self._pending),
                                 task.task_id)
            self._sort_pending()
            self._stop_events[task.task_id] = threading.Event()
        return task.task_id

    def _sort_pending(self) -> None:
        self._pending.sort(key=lambda tid: self._tasks[tid].priority)

    def dequeue(self) -> Optional[ScanTask]:
        with self._lock:
            if not self._pending:
                return None
            if self._running is not None:
                return None
            task_id = self._pending.pop(0)
            task = self._tasks[task_id]
            task.status = TaskStatus.RUNNING
            task.started_at = time.time()
            self._running = task_id
            return task

    def get_task(self, task_id: str) -> Optional[ScanTask]:
        with self._lock:
            return self._tasks.get(task_id)

    def get_status(self, task_id: str) -> Optional[str]:
        task = self.get_task(task_id)
        return task.status if task else None

    def list_tasks(self, status: Optional[str] = None) -> list[ScanTask]:
        with self._lock:
            tasks = list(self._tasks.values())
        if status:
            tasks = [t for t in tasks if t.status == status]
        return sorted(tasks, key=lambda t: t.created_at, reverse=True)

    def cancel(self, task_id: str) -> bool:
        with self._lock:
            event = self._stop_events.get(task_id)
            if event:
                event.set()
            task = self._tasks.get(task_id)
            if task is None:
                return False
            if task.status == TaskStatus.PENDING:
                if task_id in self._pending:
                    self._pending.remove(task_id)
                task.status = TaskStatus.CANCELLED
                return True
            if task.status == TaskStatus.RUNNING:
                task.status = TaskStatus.CANCELLED
                return True
            return False

    def cancel_all(self) -> int:
        with self._lock:
            ids = list(self._tasks.keys())
        count = 0
        for tid in ids:
            if self.cancel(tid):
                count += 1
        return count

    def is_stop_requested(self, task_id: str) -> bool:
        event = self._stop_events.get(task_id)
        return event is not None and event.is_set()

    def create_progress_callback(self, task_id: str) -> ProgressCallback:
        def _cb(label: str, current: int, total: int) -> None:
            task = self.get_task(task_id)
            if task is None:
                return
            task.progress_label = label
            task.progress_current = current
            task.progress_total = total
            if self._on_task_progress:
                self._on_task_progress(task, label, current, total)
        return _cb

    def complete_task(self, task_id: str, result: Optional[ScanResult] = None,
                      error: Optional[str] = None) -> Optional[ScanTask]:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            if error:
                task.status = TaskStatus.FAILED
                task.error = error
            else:
                task.status = TaskStatus.COMPLETED
                task.result = result
            task.completed_at = time.time()
            if self._running == task_id:
                self._running = None
            self._stop_events.pop(task_id, None)
        if self._on_task_complete:
            self._on_task_complete(task)
        return task

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    @property
    def running_count(self) -> int:
        with self._lock:
            return 1 if self._running is not None else 0

    @property
    def completed_count(self) -> int:
        with self._lock:
            return sum(1 for t in self._tasks.values()
                       if t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED))

    @property
    def total_count(self) -> int:
        with self._lock:
            return len(self._tasks)

    def clear_completed(self) -> int:
        with self._lock:
            keys = [tid for tid, t in self._tasks.items()
                    if t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED)]
            for k in keys:
                self._tasks.pop(k, None)
                self._stop_events.pop(k, None)
            self._pending = [p for p in self._pending if p in self._tasks]
        return len(keys)


scan_queue = ScanQueue()
