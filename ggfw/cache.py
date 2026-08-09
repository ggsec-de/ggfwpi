"""Extracted GGFW component: cache."""
from ggfw._compat import Any, Optional, time

class CacheManager:
    def __init__(self):
        self.cache = {}
        self.ttl = 300

    def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return value
            del self.cache[key]
        return None

    def set(self, key: str, value: Any):
        self.cache[key] = (value, time.time())

    def invalidate(self, key: str):
        if key in self.cache:
            del self.cache[key]

    def clear(self):
        self.cache.clear()
