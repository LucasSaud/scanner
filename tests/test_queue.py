import time
from pathlib import Path

from security_scanner.queue import ScanQueue, ScanTask, Priority, TaskStatus


class TestPriority:
    def test_order(self):
        assert Priority.HIGH < Priority.NORMAL < Priority.LOW
        assert Priority.HIGH.value == 0
        assert Priority.NORMAL.value == 1
        assert Priority.LOW.value == 2


class TestScanTask:
    def test_defaults(self):
        t = ScanTask(path=Path("/test"))
        assert t.task_id
        assert t.status == TaskStatus.PENDING
        assert t.priority == Priority.NORMAL
        assert t.created_at > 0

    def test_duration(self):
        t = ScanTask(path=Path("/test"), started_at=100.0, completed_at=105.0)
        assert t.duration_ms == 5000

    def test_age(self):
        t = ScanTask(path=Path("/test"), created_at=time.time() - 10)
        assert 9.0 < t.age_seconds < 11.0

    def test_to_dict(self):
        t = ScanTask(path=Path("/test.py"), priority=Priority.HIGH)
        d = t.to_dict()
        assert d["task_id"] == t.task_id
        assert d["path"] == "/test.py"
        assert d["priority"] == "HIGH"
        assert d["status"] == "pending"

    def test_custom_task_id(self):
        t = ScanTask(task_id="myid", path=Path("/x"))
        assert t.task_id == "myid"


class TestScanQueue:
    def setup_method(self):
        self.q = ScanQueue()

    def test_enqueue_returns_id(self):
        tid = self.q.enqueue(Path("/test"))
        assert tid
        assert len(tid) == 12

    def test_enqueue_none(self):
        tid = self.q.enqueue(Path("/test"))
        assert self.q.get_task(tid) is not None

    def test_dequeue_returns_task(self):
        tid = self.q.enqueue(Path("/test"))
        task = self.q.dequeue()
        assert task is not None
        assert task.task_id == tid
        assert task.status == TaskStatus.RUNNING

    def test_dequeue_empty(self):
        task = self.q.dequeue()
        assert task is None

    def test_dequeue_only_one_at_a_time(self):
        self.q.enqueue(Path("/a"))
        self.q.enqueue(Path("/b"))
        t1 = self.q.dequeue()
        t2 = self.q.dequeue()
        assert t1 is not None
        assert t2 is None

    def test_get_status(self):
        tid = self.q.enqueue(Path("/test"))
        assert self.q.get_status(tid) == TaskStatus.PENDING
        self.q.dequeue()
        assert self.q.get_status(tid) == TaskStatus.RUNNING

    def test_get_status_unknown(self):
        assert self.q.get_status("nonexistent") is None

    def test_complete_task(self):
        tid = self.q.enqueue(Path("/test"))
        self.q.dequeue()
        task = self.q.complete_task(tid)
        assert task is not None
        assert task.status == TaskStatus.COMPLETED

    def test_complete_task_with_error(self):
        tid = self.q.enqueue(Path("/test"))
        self.q.dequeue()
        task = self.q.complete_task(tid, error="something broke")
        assert task.status == TaskStatus.FAILED
        assert task.error == "something broke"

    def test_cancel_pending(self):
        tid = self.q.enqueue(Path("/test"))
        assert self.q.cancel(tid)
        assert self.q.get_status(tid) == TaskStatus.CANCELLED

    def test_cancel_unknown(self):
        assert not self.q.cancel("nonexistent")

    def test_cancel_all(self):
        self.q.enqueue(Path("/a"))
        self.q.enqueue(Path("/b"))
        count = self.q.cancel_all()
        assert count == 2

    def test_is_stop_requested(self):
        tid = self.q.enqueue(Path("/test"))
        assert not self.q.is_stop_requested(tid)
        self.q.cancel(tid)
        assert self.q.is_stop_requested(tid)

    def test_list_tasks(self):
        self.q.enqueue(Path("/a"))
        self.q.enqueue(Path("/b"))
        tasks = self.q.list_tasks()
        assert len(tasks) == 2

    def test_list_tasks_filtered(self):
        t1 = self.q.enqueue(Path("/a"))
        self.q.enqueue(Path("/b"))
        tasks = self.q.list_tasks(status=TaskStatus.PENDING)
        assert len(tasks) == 2
        self.q.dequeue()
        tasks = self.q.list_tasks(status=TaskStatus.RUNNING)
        assert len(tasks) == 1

    def test_counters(self):
        assert self.q.pending_count == 0
        self.q.enqueue(Path("/a"))
        assert self.q.pending_count == 1
        self.q.dequeue()
        assert self.q.pending_count == 0
        assert self.q.running_count == 1
        self.q.complete_task(self.q.list_tasks(status=TaskStatus.RUNNING)[0].task_id)
        assert self.q.running_count == 0
        assert self.q.completed_count == 1
        assert self.q.total_count == 1

    def test_clear_completed(self):
        t1 = self.q.enqueue(Path("/a"))
        self.q.enqueue(Path("/b"))
        self.q.dequeue()
        self.q.complete_task(t1)
        assert self.q.completed_count == 1
        assert self.q.clear_completed() >= 1
        assert self.q.completed_count == 0

    def test_priority_order(self):
        t_low = self.q.enqueue(Path("/low"), priority=Priority.LOW)
        t_high = self.q.enqueue(Path("/high"), priority=Priority.HIGH)
        task = self.q.dequeue()
        assert task is not None
        assert task.task_id == t_high

    def test_create_progress_callback(self):
        tid = self.q.enqueue(Path("/test"))
        cb = self.q.create_progress_callback(tid)
        cb("scanning", 5, 10)
        task = self.q.get_task(tid)
        assert task is not None
        assert task.progress_current == 5
        assert task.progress_total == 10
        assert task.progress_label == "scanning"

    def test_on_complete_callback(self):
        results = []
        self.q.set_on_complete(lambda t: results.append(t.task_id))
        tid = self.q.enqueue(Path("/test"))
        self.q.dequeue()
        self.q.complete_task(tid)
        assert results == [tid]

    def test_on_progress_callback(self):
        results = []
        self.q.set_on_progress(lambda t, l, c, n: results.append((t.task_id, l, c, n)))
        tid = self.q.enqueue(Path("/test"))
        cb = self.q.create_progress_callback(tid)
        cb("files", 10, 100)
        assert len(results) == 1
        assert results[0] == (tid, "files", 10, 100)
