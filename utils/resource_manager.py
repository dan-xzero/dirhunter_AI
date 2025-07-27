#!/usr/bin/env python3
"""
Resource Manager - Monitor and control system resources for optimized scanning
"""

import os
import threading
import time
import logging
import tempfile
import shutil
from typing import Dict, List, Optional, Tuple, Callable

# Configure logging
logger = logging.getLogger(__name__)

# Try to import psutil for better resource monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available - using basic resource monitoring")

class ResourceManager:
    """Monitors and controls resource usage during scans"""
    
    def __init__(self, 
                max_memory_percent: float = 80.0, 
                max_cpu_percent: float = 90.0,
                check_interval: float = 5.0):
        """
        Initialize resource manager with thresholds
        
        Args:
            max_memory_percent: Maximum memory usage percentage (0-100)
            max_cpu_percent: Maximum CPU usage percentage (0-100)
            check_interval: How often to check resource usage (seconds)
        """
        self.max_memory_percent = max_memory_percent
        self.max_cpu_percent = max_cpu_percent
        self.check_interval = check_interval
        self.paused = threading.Event()
        self._running = False
        self._monitor_thread = None
        self._callbacks = []
        
    def start_monitoring(self):
        """Start the resource monitoring thread"""
        if self._running:
            return
            
        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Resource monitoring started")
        
    def stop_monitoring(self):
        """Stop the resource monitoring thread"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2.0)
            self._monitor_thread = None
        logger.info("Resource monitoring stopped")
            
    def _monitor_loop(self):
        """Main monitoring loop to check resource usage"""
        while self._running:
            try:
                should_pause = self._check_resources()
                
                if should_pause and not self.paused.is_set():
                    logger.warning("Resource threshold exceeded - pausing intensive operations")
                    self.paused.set()
                    # Notify all registered callbacks
                    for callback in self._callbacks:
                        try:
                            callback(paused=True)
                        except Exception as e:
                            logger.error(f"Error in resource callback: {e}")
                elif not should_pause and self.paused.is_set():
                    logger.info("Resources back to normal - resuming operations")
                    self.paused.clear()
                    # Notify all registered callbacks
                    for callback in self._callbacks:
                        try:
                            callback(paused=False)
                        except Exception as e:
                            logger.error(f"Error in resource callback: {e}")
            except Exception as e:
                logger.error(f"Error monitoring resources: {e}")
                
            time.sleep(self.check_interval)
    
    def _check_resources(self) -> bool:
        """Check if system resources are above thresholds
        
        Returns:
            bool: True if any resource is over threshold
        """
        if PSUTIL_AVAILABLE:
            # Get memory usage
            mem = psutil.virtual_memory()
            memory_percent = mem.percent
            
            # Get CPU usage averaged across all cores
            cpu_percent = psutil.cpu_percent(interval=0.5)
            
            # Log current usage
            logger.debug(f"Resource usage - Memory: {memory_percent:.1f}%, CPU: {cpu_percent:.1f}%")
            
            # Check against thresholds
            return (memory_percent > self.max_memory_percent or 
                    cpu_percent > self.max_cpu_percent)
        else:
            # Without psutil we can't reliably check resources
            return False
            
    def register_callback(self, callback: Callable[[bool], None]):
        """Register a callback to be notified of resource state changes
        
        Args:
            callback: Function taking a paused parameter (True/False)
        """
        self._callbacks.append(callback)
        
    def should_pause(self) -> bool:
        """Check if operations should be paused due to resource constraints
        
        Returns:
            bool: True if operations should pause
        """
        return self.paused.is_set()
        
    def wait_if_needed(self, timeout: Optional[float] = None) -> bool:
        """Wait if resources are constrained
        
        Args:
            timeout: Maximum time to wait in seconds (None = wait forever)
            
        Returns:
            bool: True if wait completed successfully, False if timed out
        """
        if not self.paused.is_set():
            return True
            
        logger.info(f"Waiting for resources to free up (timeout: {timeout or 'none'}s)")
        return not self.paused.wait(timeout=timeout)

    @staticmethod
    def get_recommended_concurrency() -> int:
        """Get recommended domain concurrency based on system resources
        
        Returns:
            int: recommended_domains
        """
        if not PSUTIL_AVAILABLE:
            # Conservative defaults if psutil not available
            return 2
            
        # Get system information
        cpu_count = psutil.cpu_count(logical=False) or psutil.cpu_count() or 2
        
        # Calculate recommended values
        # Use physical cores if available, otherwise logical cores
        recommended_domains = max(1, min(cpu_count // 2, 3))
        
        logger.info(f"Recommended domain concurrency: {recommended_domains}")
        return recommended_domains

    @staticmethod
    def kill_browser_processes(timeout_seconds: float = 5.0) -> int:
        """Kill stuck browser processes
        
        Args:
            timeout_seconds: Grace period before force killing
            
        Returns:
            int: Number of processes killed
        """
        if not PSUTIL_AVAILABLE:
            return 0
            
        count = 0
        # Expanded list of browser-related process names to cover all browsers
        browser_names = [
            # Chrome and variants
            'chrome', 'chromium', 'chromedriver', 
            # Firefox and variants
            'firefox', 'firefox-bin', 'geckodriver', 'firefox-esr',
            # Safari
            'safari', 'safaridriver', 'webkit', 
            # Edge
            'edge', 'msedge', 'msedgedriver', 
            # Opera
            'opera', 'operadriver',
            # PhantomJS
            'phantomjs',
            # Selenium
            'selenium', 'selenium-server',
            # Webdriver related
            'webdriver', 'webdriveragent'
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                # Check if this is a browser process
                is_browser = False
                proc_name = proc.info['name'].lower() if proc.info.get('name') else ''
                
                # Check name
                if any(browser in proc_name for browser in browser_names):
                    is_browser = True
                
                # Check command line args for browser processes
                if not is_browser and proc.info.get('cmdline'):
                    cmdline = ' '.join(proc.info['cmdline']).lower()
                    if any(browser in cmdline for browser in browser_names):
                        is_browser = True
                    
                    # Also check for web driver specific arguments
                    browser_args = ['--headless', '--remote-debugging-port', 
                                  'webdriver', 'marionette', '--disable-extensions']
                    if any(arg in cmdline for arg in browser_args):
                        is_browser = True
                
                if is_browser:
                    logger.info(f"Terminating browser process: {proc.info['name']} (PID: {proc.info['pid']})")
                    proc.terminate()
                    gone, still_alive = psutil.wait_procs([proc], timeout=timeout_seconds)
                    
                    if still_alive:
                        logger.warning(f"Force killing browser process: {proc.info['name']} (PID: {proc.info['pid']})")
                        proc.kill()
                    
                    count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        return count

    @staticmethod
    def clean_temporary_dirs() -> int:
        """Clean up temporary directories created by the browser
        
        Returns:
            int: Number of directories removed
        """
        temp_dir = tempfile.gettempdir()
        count = 0
        
        # Look for directories matching browser temp patterns
        browser_patterns = [
            'chrome_', 'firefox_', 'gecko_', 'edge_', 'opera_', 'safari_',
            'selenium', 'webdriver', '.org.chromium.Chromium',
            'scoped_dir', 'tmp_browser_', '_MEI', '.com.google.Chrome',
            'mozilla_', '.cache', 'MozillaMailbox'
        ]
        
        for item in os.listdir(temp_dir):
            if any(pattern in item for pattern in browser_patterns):
                full_path = os.path.join(temp_dir, item)
                try:
                    if os.path.isdir(full_path):
                        shutil.rmtree(full_path, ignore_errors=True)
                        count += 1
                except Exception as e:
                    logger.warning(f"Failed to remove temporary directory {full_path}: {e}")
                    
        return count

# Create a global instance
resource_manager = ResourceManager() 