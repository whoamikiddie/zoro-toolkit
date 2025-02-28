import time
from functools import wraps

class RateLimiter:
    def __init__(self, max_requests=10, time_window=1):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            self.wait()
            return func(*args, **kwargs)
        return wrapper

    def __enter__(self):
        self.wait()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def wait(self):
        """Wait if necessary to comply with rate limits"""
        current_time = time.time()

        # Remove old requests outside the time window
        self.requests = [req_time for req_time in self.requests 
                        if current_time - req_time <= self.time_window]

        if len(self.requests) >= self.max_requests:
            sleep_time = self.requests[0] + self.time_window - current_time
            if sleep_time > 0:
                time.sleep(sleep_time)

        self.requests.append(current_time)

# Usage example:
# @RateLimiter(max_requests=10, time_window=1)
# def some_function():
#     pass
#
# or
#
# with RateLimiter(max_requests=10, time_window=1):
#     do_something()