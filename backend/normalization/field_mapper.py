"""Map source-specific keys into ECS target fields."""
class FieldMapper:
    def __init__(self, mapping_dict=None):
        self.mapping = mapping_dict or {}

    def map_fields(self, record: dict) -> dict:
        out = {}
        for src_k, target_k in self.mapping.items():
            if src_k in record:
                out[target_k] = record[src_k]
        return out
