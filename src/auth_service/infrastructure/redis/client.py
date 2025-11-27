"""Redis Client for Auth Service

Provides async Redis client management for token blacklisting,
user storage, and caching operations.
"""

import logging
from typing import Optional
import redis.asyncio as redis
from auth_service.config.settings import get_settings

logger = logging.getLogger(__name__)


class RedisClient:
    """Async Redis client wrapper"""

    def __init__(self, url: str = None):
        """Initialize Redis client

        Args:
            url: Redis connection URL (optional, uses settings if not provided)
        """
        settings = get_settings()
        self.url = url or settings.redis_url
        self._client: Optional[redis.Redis] = None

    async def connect(self):
        """Establish Redis connection"""
        if not self._client:
            self._client = await redis.from_url(self.url, encoding="utf-8", decode_responses=True)
            logger.info(f"Connected to Redis at {self.url}")

    async def disconnect(self):
        """Close Redis connection"""
        if self._client:
            await self._client.close()
            self._client = None
            logger.info("Disconnected from Redis")

    def get_client(self) -> redis.Redis:
        """Get the underlying Redis client

        Returns:
            Redis client instance

        Raises:
            RuntimeError: If client not connected
        """
        if not self._client:
            raise RuntimeError("Redis client not connected. Call connect() first.")
        return self._client

    async def health_check(self) -> bool:
        """Check Redis connection health

        Returns:
            True if Redis is responsive, False otherwise
        """
        try:
            if not self._client:
                return False
            await self._client.ping()
            return True
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False


# Global Redis client instance
_redis_client: Optional[RedisClient] = None


async def get_redis_client() -> RedisClient:
    """Get or create global Redis client

    Returns:
        RedisClient instance

    Note:
        Call connect() before using the client
    """
    global _redis_client
    if not _redis_client:
        _redis_client = RedisClient()
        await _redis_client.connect()
    return _redis_client


async def close_redis_client():
    """Close global Redis client"""
    global _redis_client
    if _redis_client:
        await _redis_client.disconnect()
        _redis_client = None
