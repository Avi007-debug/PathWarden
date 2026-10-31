"""Stream-oriented Parquet writer storing partitioned batches."""
import pyarrow as pa
import pyarrow.parquet as pq
import os

class ParquetWriter:
    def __init__(self, output_dir: str = "data/normalized"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def write_batch(self, records: list, batch_id: int):
        if not records:
            return
        table = pa.Table.from_pylist(records)
        target = os.path.join(self.output_dir, f"events_batch_{batch_id:05d}.parquet")
        pq.write_table(table, target)
        return target
