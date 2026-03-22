"""
Performance Monitoring Module
=============================
Tracks encryption time, hashing time, signature time,
total transfer time, CPU, and memory usage.
"""

import time
import psutil
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PerformanceMetrics:
    """Container for performance measurements."""
    encryption_time_ms: float = 0.0
    decryption_time_ms: float = 0.0
    hashing_time_ms: float = 0.0
    signing_time_ms: float = 0.0
    verification_time_ms: float = 0.0
    key_encryption_time_ms: float = 0.0
    key_decryption_time_ms: float = 0.0
    total_time_ms: float = 0.0
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    file_size_bytes: int = 0

    def to_dict(self) -> dict:
        return {
            'encryption_time_ms': round(self.encryption_time_ms, 3),
            'decryption_time_ms': round(self.decryption_time_ms, 3),
            'hashing_time_ms': round(self.hashing_time_ms, 3),
            'signing_time_ms': round(self.signing_time_ms, 3),
            'verification_time_ms': round(self.verification_time_ms, 3),
            'key_encryption_time_ms': round(self.key_encryption_time_ms, 3),
            'key_decryption_time_ms': round(self.key_decryption_time_ms, 3),
            'total_time_ms': round(self.total_time_ms, 3),
            'cpu_usage_percent': round(self.cpu_usage_percent, 2),
            'memory_usage_mb': round(self.memory_usage_mb, 2),
            'file_size_bytes': self.file_size_bytes,
        }


class PerformanceMonitor:
    """Monitors and records performance metrics for cryptographic operations."""

    def __init__(self):
        self.metrics = PerformanceMetrics()
        self._start_time = None
        self._process = psutil.Process(os.getpid())

    def start_total_timer(self):
        """Start the total operation timer."""
        self._start_time = time.perf_counter()
        # Sample initial CPU
        self._process.cpu_percent()

    def stop_total_timer(self):
        """Stop the total timer and record CPU/memory."""
        if self._start_time:
            self.metrics.total_time_ms = (time.perf_counter() - self._start_time) * 1000
        self.metrics.cpu_usage_percent = self._process.cpu_percent()
        mem_info = self._process.memory_info()
        self.metrics.memory_usage_mb = mem_info.rss / (1024 * 1024)

    def measure(self, operation_name: str):
        """
        Context manager to time an operation.

        Usage:
            with monitor.measure('encryption'):
                # do encryption
        """
        return _TimerContext(self, operation_name)

    def get_metrics(self) -> PerformanceMetrics:
        """Return collected metrics."""
        return self.metrics

    @staticmethod
    def get_system_stats() -> dict:
        """Get current system resource stats."""
        return {
            'cpu_percent': psutil.cpu_percent(interval=0.1),
            'memory_percent': psutil.virtual_memory().percent,
            'memory_available_mb': psutil.virtual_memory().available / (1024 * 1024),
        }


class _TimerContext:
    """Context manager for timing individual operations."""

    def __init__(self, monitor: PerformanceMonitor, operation: str):
        self.monitor = monitor
        self.operation = operation
        self.start = None

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed_ms = (time.perf_counter() - self.start) * 1000
        attr_name = f"{self.operation}_time_ms"
        if hasattr(self.monitor.metrics, attr_name):
            setattr(self.monitor.metrics, attr_name, elapsed_ms)
        return False
