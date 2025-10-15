"""OAuth metrics for monitoring and observability."""

from typing import Dict, Optional

from secure_mcp_gateway.utils import logger


class OAuthMetrics:
    """
    Tracks OAuth-related metrics for monitoring.

    Metrics tracked:
    - Token acquisition attempts (success/failure)
    - Token cache hit/miss ratio
    - Token refresh count
    - OAuth endpoint latency
    - Active tokens count
    """

    def __init__(self):
        """Initialize metrics."""
        self._metrics: Dict[str, int] = {
            "token_acquisitions_total": 0,
            "token_acquisitions_success": 0,
            "token_acquisitions_failure": 0,
            "token_cache_hits": 0,
            "token_cache_misses": 0,
            "token_refreshes": 0,
            "token_invalidations": 0,
            "token_expirations": 0,
        }
        self._latencies: Dict[str, list] = {
            "token_acquisition": [],
        }

    def record_token_acquisition(
        self, success: bool, latency_ms: Optional[float] = None
    ):
        """
        Record token acquisition attempt.

        Args:
            success: Whether acquisition was successful
            latency_ms: Optional latency in milliseconds
        """
        self._metrics["token_acquisitions_total"] += 1
        if success:
            self._metrics["token_acquisitions_success"] += 1
        else:
            self._metrics["token_acquisitions_failure"] += 1

        if latency_ms is not None:
            self._latencies["token_acquisition"].append(latency_ms)
            # Keep only last 100 samples
            if len(self._latencies["token_acquisition"]) > 100:
                self._latencies["token_acquisition"].pop(0)

    def record_cache_hit(self):
        """Record token cache hit."""
        self._metrics["token_cache_hits"] += 1

    def record_cache_miss(self):
        """Record token cache miss."""
        self._metrics["token_cache_misses"] += 1

    def record_token_refresh(self):
        """Record token refresh."""
        self._metrics["token_refreshes"] += 1

    def record_token_invalidation(self):
        """Record token invalidation."""
        self._metrics["token_invalidations"] += 1

    def record_token_expiration(self):
        """Record token expiration."""
        self._metrics["token_expirations"] += 1

    def get_metrics(self) -> Dict[str, any]:
        """
        Get all metrics.

        Returns:
            Dictionary of metrics
        """
        metrics = self._metrics.copy()

        # Calculate cache hit ratio
        total_cache_requests = (
            self._metrics["token_cache_hits"] + self._metrics["token_cache_misses"]
        )
        if total_cache_requests > 0:
            metrics["cache_hit_ratio"] = (
                self._metrics["token_cache_hits"] / total_cache_requests
            )
        else:
            metrics["cache_hit_ratio"] = 0.0

        # Calculate success rate
        if self._metrics["token_acquisitions_total"] > 0:
            metrics["success_rate"] = (
                self._metrics["token_acquisitions_success"]
                / self._metrics["token_acquisitions_total"]
            )
        else:
            metrics["success_rate"] = 0.0

        # Calculate average latency
        if self._latencies["token_acquisition"]:
            metrics["avg_latency_ms"] = sum(self._latencies["token_acquisition"]) / len(
                self._latencies["token_acquisition"]
            )
            metrics["max_latency_ms"] = max(self._latencies["token_acquisition"])
            metrics["min_latency_ms"] = min(self._latencies["token_acquisition"])
        else:
            metrics["avg_latency_ms"] = 0.0
            metrics["max_latency_ms"] = 0.0
            metrics["min_latency_ms"] = 0.0

        return metrics

    def reset(self):
        """Reset all metrics."""
        self._metrics = {k: 0 for k in self._metrics}
        self._latencies = {"token_acquisition": []}
        logger.info("[OAuthMetrics] Metrics reset")


# Global metrics instance
_oauth_metrics: Optional[OAuthMetrics] = None


def get_oauth_metrics() -> OAuthMetrics:
    """
    Get global OAuth metrics instance.

    Returns:
        OAuthMetrics instance
    """
    global _oauth_metrics
    if _oauth_metrics is None:
        _oauth_metrics = OAuthMetrics()
    return _oauth_metrics


def reset_oauth_metrics() -> None:
    """Reset global OAuth metrics (for testing)."""
    global _oauth_metrics
    if _oauth_metrics is not None:
        _oauth_metrics.reset()
