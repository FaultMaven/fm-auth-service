"""Redis Client for Auth Service

Provides async Redis client management for token blacklisting,
user storage, and caching operations with Sentinel support for HA.
"""

import logging
from typing import Optional

import redis.asyncio as redis
from fm_core_lib.infrastructure import get_redis_client as get_redis_from_factory

from auth_service.config.settings import get_settings

logger = logging.getLogger(__name__)


class RedisClient:
    """Async Redis client wrapper with Sentinel support"""

    def __init__(self):
        """Initialize Redis client

        Uses fm-core-lib factory for deployment-neutral configuration.
        """
        self._client: Optional[redis.Redis] = None

    async def connect(self):
        """Establish Redis connection with Sentinel support.

        Uses fm-core-lib factory for deployment-neutral Redis configuration:
        - Standalone mode (development, self-hosted)
        - Sentinel mode (enterprise K8s with HA)

        Environment Variables:
            REDIS_MODE: "standalone" (default) or "sentinel"

            For standalone:
                REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD

            For sentinel:
                REDIS_SENTINEL_HOSTS: Comma-separated "host:port,host:port"
                REDIS_MASTER_SET: Master set name (default: "mymaster")
                REDIS_DB, REDIS_PASSWORD
        """
        if not self._client:
            settings = get_settings()

            self._client = await get_redis_from_factory(
                mode=settings.redis_mode,
                host=settings.redis_host,
                port=settings.redis_port,
                db=settings.redis_db,
                password=settings.redis_password,
                sentinel_hosts=settings.redis_sentinel_hosts,
                master_set=settings.redis_master_set,
            )

            if settings.redis_mode == "sentinel":
                logger.info(
                    f"Connected to Redis (SENTINEL): "
                    f"master_set={settings.redis_master_set}, "
                    f"sentinels={settings.redis_sentinel_hosts}, "
                    f"db={settings.redis_db}"
                )
            else:
                logger.info(
                    f"Connected to Redis (STANDALONE): "
                    f"{settings.redis_host}:{settings.redis_port}/{settings.redis_db}"
                )


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
