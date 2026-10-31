"""Thread-safe bounded processing queue."""
import queue

class ProcessingQueue:
    def __init__(self, maxsize: int = 100):
        self.q = queue.Queue(maxsize=maxsize)

    def put_chunk(self, chunk, timeout=5.0):
        self.q.put(chunk, timeout=timeout)

    def get_chunk(self, timeout=5.0):
        return self.q.get(timeout=timeout)
