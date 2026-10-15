"""
Phoenix DFIR - Cache abstraction layer
Backend Redis si REDIS_URL est defini, fallback in-memory thread-safe sinon.
"""

import os
import time
import threading
import json
from typing import Optional, Any


class _InMemoryBackend:
    """Backend in-memory thread-safe avec expiration paresseuse."""

    def __init__(self):
        self._data = {}
        self._counters = {}
        self._lock = threading.Lock()

    def _evict(self, key):
        item = self._data.get(key)
        if item and item[1] is not None and item[1] < time.time():
            self._data.pop(key, None)
            return None
        return item

    def get(self, key):
        with self._lock:
            item = self._evict(key)
            return item[0] if item else None

    def set(self, key, value, ttl=None):
        with self._lock:
            expiry = (time.time() + ttl) if ttl else None
            self._data[key] = (value, expiry)
        return True

    def delete(self, key):
        with self._lock:
            self._data.pop(key, None)
            self._counters.pop(key, None)
        return True

    def exists(self, key):
        with self._lock:
            return self._evict(key) is not None

    def incr(self, key, ttl=None):
        with self._lock:
            entry = self._counters.get(key)
            if entry and entry[1] is not None and entry[1] < time.time():
                entry = None
            if entry is None:
                expiry = (time.time() + ttl) if ttl else None
                self._counters[key] = (1, expiry)
                return 1
            new_val = entry[0] + 1
            self._counters[key] = (new_val, entry[1])
            return new_val

    def sliding_window_hit(self, key, window):
        """Enregistre un hit et retourne le nombre de hits dans la fenetre."""
        with self._lock:
            now = time.time()
            bucket = self._data.get(key)
            history = bucket[0] if bucket else []
            history = [t for t in history if now - t < window]
            history.append(now)
            self._data[key] = (history, now + window)
            return len(history)

    def ping(self):
        return True

    def backend_name(self):
        return 'memory'


class _RedisBackend:
    """Backend Redis. Toutes les operations sont serialisees JSON."""

    def __init__(self, url):
        import redis  # noqa: import-time
        self._client = redis.from_url(url, decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
        # Verifier la connexion immediatement, leve si KO
        self._client.ping()

    def get(self, key):
        raw = self._client.get(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return raw

    def set(self, key, value, ttl=None):
        payload = json.dumps(value) if not isinstance(value, str) else value
        if ttl:
            return bool(self._client.set(key, payload, ex=int(ttl)))
        return bool(self._client.set(key, payload))

    def delete(self, key):
        return bool(self._client.delete(key))

    def exists(self, key):
        return bool(self._client.exists(key))

    def incr(self, key, ttl=None):
        pipe = self._client.pipeline()
        pipe.incr(key)
        if ttl:
            pipe.expire(key, int(ttl), nx=True)
        result = pipe.execute()
        return int(result[0])

    def sliding_window_hit(self, key, window):
        """Utilise un ZSET pour une fenetre glissante precise."""
        now = time.time() * 1000  # ms pour eviter les collisions
        cutoff = now - (window * 1000)
        pipe = self._client.pipeline()
        pipe.zremrangebyscore(key, 0, cutoff)
        pipe.zadd(key, {f'{now}:{os.getpid()}': now})
        pipe.zcard(key)
        pipe.expire(key, int(window) + 1)
        result = pipe.execute()
        return int(result[2])

    def ping(self):
        try:
            return bool(self._client.ping())
        except Exception:
            return False

    def backend_name(self):
        return 'redis'


class Cache:
    """Facade cache. Tente Redis si REDIS_URL est defini, sinon in-memory."""

    def __init__(self, redis_url=None):
        self._backend = None
        url = redis_url or os.environ.get('REDIS_URL', '').strip()
        if url:
            try:
                self._backend = _RedisBackend(url)
            except Exception as e:
                print(f"[cache] Redis indisponible ({e}), fallback in-memory", flush=True)
                self._backend = _InMemoryBackend()
        else:
            self._backend = _InMemoryBackend()

    def get(self, key: str) -> Optional[Any]:
        return self._backend.get(key)

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        return self._backend.set(key, value, ttl)

    def delete(self, key: str) -> bool:
        return self._backend.delete(key)

    def exists(self, key: str) -> bool:
        return self._backend.exists(key)

    def incr(self, key: str, ttl: Optional[int] = None) -> int:
        return self._backend.incr(key, ttl)

    def sliding_window_hit(self, key: str, window: int) -> int:
        return self._backend.sliding_window_hit(key, window)

    def ping(self) -> bool:
        return self._backend.ping()

    @property
    def backend_name(self) -> str:
        return self._backend.backend_name()


# Singleton applicatif
cache = Cache()
