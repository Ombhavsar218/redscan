"""
Progressive Scanner Base - Foundation for all progressive scanning operations
"""

from typing import Dict, Any, Callable, Optional
from .scan_throttler import ScanThrottler


class ProgressiveScannerBase:
    """
    Base class for progressive scanning operations
    Provides common functionality for state management and progress reporting
    """
    
    def __init__(self, target: str, progress_callback: Optional[Callable] = None):
        """
        Initialize progressive scanner
        
        Args:
            target: Target to scan (IP, domain, URL)
            progress_callback: Function to call with progress updates
        """
        self.target = target
        self.progress_callback = progress_callback or self._default_progress_callback
        
        # Scan state
        self.state = {
            'initialized': False,
            'current_step': 0,
            'total_steps': 0,
            'items_processed': 0,
            'items_total': 0,
            'results': [],
            'errors': [],
            'start_time': None,
            'end_time': None
        }
        
        # Throttler for rate limiting
        self.throttler = ScanThrottler(requests_per_second=10)
    
    def _default_progress_callback(self, progress: int, message: str, data: Optional[Dict] = None):
        """Default progress callback"""
        print(f"[{progress}%] {message}")
        if data:
            print(f"  Data: {data}")
    
    def initialize_scan(self, total_steps: int, total_items: int = 0):
        """
        Initialize scan state
        
        Args:
            total_steps: Total number of progress steps
            total_items: Total number of items to process (optional)
        """
        import time
        
        self.state['initialized'] = True
        self.state['total_steps'] = total_steps
        self.state['items_total'] = total_items
        self.state['start_time'] = time.time()
        self.state['current_step'] = 0
        self.state['items_processed'] = 0
        self.state['results'] = []
        self.state['errors'] = []
        self.throttler.reset()
    
    def report_progress(self, step: int, message: str, data: Optional[Dict] = None):
        """
        Report progress to callback
        
        Args:
            step: Current step number
            message: Progress message
            data: Additional data to include
        """
        self.state['current_step'] = step
        
        # Calculate percentage
        if self.state['total_steps'] > 0:
            percentage = int((step / self.state['total_steps']) * 100)
        else:
            percentage = 0
        
        # Prepare progress data
        progress_data = {
            'step': step,
            'total_steps': self.state['total_steps'],
            'items_processed': self.state['items_processed'],
            'items_total': self.state['items_total'],
            'results_count': len(self.state['results']),
            'errors_count': len(self.state['errors']),
            'throttler_stats': self.throttler.get_stats()
        }
        
        if data:
            progress_data.update(data)
        
        # Call progress callback
        self.progress_callback(percentage, message, progress_data)
    
    def accumulate_result(self, result: Any):
        """
        Add a result to the accumulated results
        
        Args:
            result: Result to add
        """
        self.state['results'].append(result)
        self.state['items_processed'] += 1
    
    def accumulate_results(self, results: list):
        """
        Add multiple results to the accumulated results
        
        Args:
            results: List of results to add
        """
        self.state['results'].extend(results)
        self.state['items_processed'] += len(results)
    
    def record_error(self, error: Exception, context: str = ''):
        """
        Record an error that occurred during scanning
        
        Args:
            error: Exception that occurred
            context: Context information about where error occurred
        """
        error_info = {
            'error': str(error),
            'type': type(error).__name__,
            'context': context,
            'timestamp': self._get_timestamp()
        }
        self.state['errors'].append(error_info)
    
    def finalize_scan(self) -> Dict[str, Any]:
        """
        Finalize scan and return results
        
        Returns:
            Dictionary containing scan results and metadata
        """
        import time
        
        self.state['end_time'] = time.time()
        
        # Calculate scan duration
        if self.state['start_time']:
            duration = self.state['end_time'] - self.state['start_time']
        else:
            duration = 0
        
        return {
            'target': self.target,
            'results': self.state['results'],
            'errors': self.state['errors'],
            'statistics': {
                'items_processed': self.state['items_processed'],
                'items_total': self.state['items_total'],
                'results_count': len(self.state['results']),
                'errors_count': len(self.state['errors']),
                'duration_seconds': duration,
                'items_per_second': self.state['items_processed'] / duration if duration > 0 else 0
            },
            'throttler_stats': self.throttler.get_stats()
        }
    
    def get_state(self) -> Dict[str, Any]:
        """Get current scan state"""
        return self.state.copy()
    
    def _get_timestamp(self) -> float:
        """Get current timestamp"""
        import time
        return time.time()
    
    def _calculate_progress_percentage(self) -> int:
        """Calculate current progress percentage"""
        if self.state['total_steps'] > 0:
            return int((self.state['current_step'] / self.state['total_steps']) * 100)
        elif self.state['items_total'] > 0:
            return int((self.state['items_processed'] / self.state['items_total']) * 100)
        else:
            return 0
