"""Channels layer configuration for Redis-backed pub/sub.

Loaded by settings to configure the ``channels`` channel layer backend.
"""

import os

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [
                (
                    os.environ.get("REDIS_HOST", "redis"),
                    int(os.environ.get("REDIS_PORT", 6379)),
                )
            ],
            "capacity": 1500,
            "expiry": 10,
        },
    },
}