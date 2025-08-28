#!/usr/bin/env python3
"""
User Agent Manager for DirHunter AI

This module provides realistic, rotating user agents to avoid WAF detection.
It includes multiple browser profiles and realistic headers that modern browsers send.
"""

import random
import time
from typing import Dict, List, Tuple

# Realistic browser user agents (updated regularly)
BROWSER_PROFILES = {
    "chrome_windows": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
    ],
    "chrome_macos": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
    ],
    "firefox_windows": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0"
    ],
    "firefox_macos": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:118.0) Gecko/20100101 Firefox/118.0"
    ],
    "safari_macos": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15"
    ],
    "edge_windows": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.0.0"
    ]
}

# Common browser headers that WAFs expect
BROWSER_HEADERS = {
    "chrome": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0"
    },
    "firefox": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "no-cache"
    },
    "safari": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    },
    "edge": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1"
    }
}

class UserAgentManager:
    """Manages realistic user agents and headers for web requests"""
    
    def __init__(self):
        self.current_profile = None
        self.current_headers = None
        self.last_rotation = 0
        self.rotation_interval = 300  # Rotate every 5 minutes
        
    def get_random_profile(self) -> Tuple[str, Dict[str, str]]:
        """Get a random browser profile with realistic headers"""
        
        # Check if we need to rotate
        current_time = time.time()
        if (self.current_profile is None or 
            current_time - self.last_rotation > self.rotation_interval):
            
            # Select random browser type
            browser_types = list(BROWSER_PROFILES.keys())
            selected_profile = random.choice(browser_types)
            
            # Get random user agent for this profile
            user_agent = random.choice(BROWSER_PROFILES[selected_profile])
            
            # Determine browser type for headers
            if "chrome" in selected_profile:
                browser_type = "chrome"
            elif "firefox" in selected_profile:
                browser_type = "firefox"
            elif "safari" in selected_profile:
                browser_type = "safari"
            elif "edge" in selected_profile:
                browser_type = "edge"
            else:
                browser_type = "chrome"  # Default fallback
            
            # Get headers for this browser type
            headers = BROWSER_HEADERS[browser_type].copy()
            headers["User-Agent"] = user_agent
            
            # Add some randomization to headers
            if random.random() > 0.5:
                headers["Accept-Language"] = "en-GB,en;q=0.9,en-US;q=0.8"
            
            # Store current profile
            self.current_profile = selected_profile
            self.current_headers = headers
            self.last_rotation = current_time
            
        return self.current_headers["User-Agent"], self.current_headers
    
    def get_headers(self, include_scanner_header: bool = False) -> Dict[str, str]:
        """Get complete headers for requests"""
        _, headers = self.get_random_profile()
        
        # Add scanner identification header if requested
        if include_scanner_header:
            headers["X-Scanner"] = "DirHunter-AI"
        
        return headers
    
    def get_user_agent(self) -> str:
        """Get just the user agent string"""
        user_agent, _ = self.get_random_profile()
        return user_agent
    
    def get_ffuf_user_agent(self) -> str:
        """Get user agent specifically for ffuf (without -FUZZ suffix)"""
        user_agent = self.get_user_agent()
        # Remove any suspicious suffixes that might be added
        if user_agent.endswith("-FUZZ"):
            user_agent = user_agent[:-5]
        return user_agent

# Global instance
user_agent_manager = UserAgentManager()

def get_realistic_headers(include_scanner_header: bool = False) -> Dict[str, str]:
    """Get realistic browser headers"""
    return user_agent_manager.get_headers(include_scanner_header)

def get_realistic_user_agent() -> str:
    """Get a realistic user agent string"""
    return user_agent_manager.get_user_agent()

def get_ffuf_user_agent() -> str:
    """Get user agent for ffuf commands"""
    return user_agent_manager.get_ffuf_user_agent()

