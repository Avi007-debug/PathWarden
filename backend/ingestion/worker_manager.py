"""Worker pool supervisor for parallel chunk processing."""
from concurrent.futures import ThreadPoolExecutor

class WorkerManager:
    def __init__(self, max_workers: int = 4):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    def submit_chunk(self, fn, *args, **kwargs):
        return self.executor.submit(fn, *args, **kwargs)

    def shutdown(self):
        self.executor.shutdown(wait=True)
