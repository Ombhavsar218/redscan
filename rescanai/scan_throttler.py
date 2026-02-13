"""
Scan Throttler - Controls scan speed to avoid overwhelming targets
"""

import time
import threading
from typing import Optional


class ScanThrottler:
    """
    Rate limiter for security scanning to avoid overwhelming targets
    and prevent being blocked by rate limiting
    """
    
    def __init__(self, requests_per_second: float = 10.0):
        """
        Initialize throttler
        
        Args:
            requests_per_second: Maximum requests per second (default: 10)
        """
        self.rps = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0
        self.lock = threading.Lock()
        self.error_count = 0
        self.adaptive_delay = 0
    
    def throttle(self):
        """
        Enforce rate limiting - call before each request
        Blocks if necessary to maintain rate limit
        """
        with self.lock:
            now = time.time()
            time_since_last = now - self.last_request_time
            
            # Calculate required wait time
            required_wait = self.min_interval + self.adaptive_delay
            
            if time_since_last < required_wait:
                sleep_time = required_wait - time_since_last
                time.sleep(sleep_time)
            
            self.last_request_time = time.time()
    
    def report_error(self, error_type: str = 'generic'):
        """
        Report an error (timeout, rate limit, etc.)
        Automatically increases delay for adaptive throttling
        
        Args:
            error_type: Type of error ('rate_limit', 'timeout', 'connection', etc.)
        """
        with self.lock:
            self.error_count += 1
            
            # Increase delay based on error type
            if error_type == 'rate_limit':
                # Significant slowdown for rate limiting
                self.adaptive_delay += 0.5
            elif error_type in ['timeout', 'connection']:
                # Moderate slowdown for network issues
                self.adaptive_delay += 0.1
            else:
                # Small slowdown for other errors
                self.adaptive_delay += 0.05
            
            # Cap maximum delay at 5 seconds
            self.adaptive_delay = min(self.adaptive_delay, 5.0)
    
    def report_success(self):
        """
        Report a successful request
        Gradually reduces adaptive delay
        """
        with self.lock:
            # Gradually reduce delay on success
            if self.adaptive_delay > 0:
                self.adaptive_delay = max(0, self.adaptive_delay - 0.01)
    
    def reset(self):
        """Reset throttler state"""
        with self.lock:
            self.error_count = 0
            self.adaptive_delay = 0
            self.last_request_time = 0
    
    def get_current_rate(self) -> float:
        """Get current effective rate (requests per second)"""
        with self.lock:
            effective_interval = self.min_interval + self.adaptive_delay
            return 1.0 / effective_interval if effective_interval > 0 else 0
    
    def get_stats(self) -> dict:
        """Get throttler statistics"""
        with self.lock:
            return {
                'configured_rps': self.rps,
                'current_rps': self.get_current_rate(),
                'error_count': self.error_count,
                'adaptive_delay': self.adaptive_delay
            }
