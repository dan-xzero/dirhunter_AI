# User Agent Improvements for WAF Avoidance

## Overview

This document outlines the comprehensive improvements made to DirHunter AI's user agent handling to avoid Web Application Firewall (WAF) detection and blocking.

## Issues Identified

### 1. **Inconsistent User Agents**
- Different parts of the codebase used different user agents
- Some user agents were outdated or suspicious
- No centralized management of user agent strings

### 2. **Suspicious Patterns**
- FFUF user agent had obvious "-FUZZ" suffix that WAFs could detect
- Some user agents used older browser versions
- Missing realistic browser headers that WAFs expect

### 3. **Default/Generic User Agents**
- Some requests used default `python-requests` user agent
- Missing common browser headers like `Accept`, `Accept-Language`, etc.
- No rotation or randomization of user agents

## Solutions Implemented

### 1. **New User Agent Manager (`utils/user_agent_manager.py`)**

#### Features:
- **Realistic Browser Profiles**: Multiple browser types (Chrome, Firefox, Safari, Edge)
- **Platform Variety**: Windows and macOS variants
- **Version Diversity**: Multiple browser versions for each profile
- **Automatic Rotation**: User agents rotate every 5 minutes
- **Complete Headers**: Full set of realistic browser headers

#### Browser Profiles Included:
```python
BROWSER_PROFILES = {
    "chrome_windows": [Chrome 120, 119, 118, 117],
    "chrome_macos": [Chrome 120, 119, 118, 117],
    "firefox_windows": [Firefox 121, 120, 119, 118],
    "firefox_macos": [Firefox 121, 120, 119, 118],
    "safari_macos": [Safari 17.1, 17.0, 16.6, 16.5],
    "edge_windows": [Edge 120, 119, 118, 117]
}
```

#### Realistic Headers:
- `Accept`: Proper MIME type preferences
- `Accept-Language`: Realistic language preferences
- `Accept-Encoding`: Compression support
- `DNT`: Do Not Track header
- `Connection`: Keep-alive connections
- `Upgrade-Insecure-Requests`: HTTPS upgrade support
- `Sec-Fetch-*`: Modern browser security headers
- `Cache-Control`: Realistic caching behavior

### 2. **Updated Files**

#### Core Files Updated:
1. **`main_optimized.py`**
   - `capture_headers()` function now uses realistic headers
   - Removed hardcoded user agent

2. **`utils/filters.py`**
   - `curl_fetch_hash()` function uses dynamic headers
   - Removed static HEADERS dictionary
   - Added scanner identification header

3. **`utils/scanner.py`**
   - `run_ffuf()` function uses realistic user agent
   - `smart_resolve_scheme()` function uses realistic headers
   - Removed "-FUZZ" suffix from user agent

4. **`utils/simple_tech_detector.py`**
   - `detect_technologies()` function uses realistic headers
   - Removed hardcoded user agent and headers

5. **`utils/active_scan.py`**
   - `perform_active_scan()` function uses realistic headers
   - `probe_paths()` function uses realistic headers
   - All HTTP requests now use proper browser headers

6. **`utils/dns_check.py`**
   - `check_with_http_https()` function uses realistic headers
   - DNS validation requests now look like real browsers

7. **`utils/screenshot.py`**
   - `create_fallback_screenshot()` function uses realistic headers
   - Screenshot fallback requests now use proper headers

## Key Benefits

### 1. **WAF Avoidance**
- Realistic user agents that match actual browser behavior
- Complete set of headers that modern browsers send
- No suspicious patterns or scanner indicators
- Automatic rotation prevents pattern detection

### 2. **Improved Success Rate**
- Reduced likelihood of being blocked by WAFs
- Better compatibility with various web applications
- More accurate technology detection due to realistic requests

### 3. **Maintainability**
- Centralized user agent management
- Easy to update browser versions and add new profiles
- Consistent behavior across all scanning components

## Usage Examples

### Basic Usage:
```python
from utils.user_agent_manager import get_realistic_headers, get_realistic_user_agent

# Get complete headers for requests
headers = get_realistic_headers(include_scanner_header=True)

# Get just the user agent string
user_agent = get_realistic_user_agent()

# Get user agent for ffuf (without suspicious suffixes)
ffuf_ua = get_ffuf_user_agent()
```

### In HTTP Requests:
```python
import requests
from utils.user_agent_manager import get_realistic_headers

headers = get_realistic_headers(include_scanner_header=True)
response = requests.get(url, headers=headers, timeout=10)
```

### For FFUF Commands:
```python
from utils.user_agent_manager import get_ffuf_user_agent

user_agent = get_ffuf_user_agent()
cmd = ["ffuf", "-H", f"User-agent: {user_agent}", ...]
```

## Configuration

### Rotation Interval
The user agent rotation interval can be adjusted in the `UserAgentManager` class:
```python
self.rotation_interval = 300  # Rotate every 5 minutes
```

### Adding New Browser Profiles
New browser profiles can be added to the `BROWSER_PROFILES` dictionary:
```python
"new_browser": [
    "Mozilla/5.0 (New Browser User Agent String)",
    # Add more versions...
]
```

### Custom Headers
Additional headers can be added to the `BROWSER_HEADERS` dictionaries for each browser type.

## Testing

The user agent manager includes comprehensive testing to ensure:
- All required headers are present
- User agents rotate correctly
- Multiple browser profiles are available
- No suspicious patterns are present

## Security Considerations

1. **Scanner Identification**: The `X-Scanner: DirHunter-AI` header is optional and can be disabled
2. **Header Consistency**: All headers are consistent with the selected browser profile
3. **No Fingerprinting**: Headers are randomized to prevent fingerprinting
4. **Rate Limiting**: User agents rotate to avoid rate limiting based on user agent patterns

## Future Improvements

1. **Geographic Variation**: Add user agents from different geographic regions
2. **Mobile Browsers**: Include mobile browser user agents
3. **Dynamic Updates**: Automatically update browser versions from online sources
4. **Behavioral Patterns**: Add realistic request timing and patterns
5. **Proxy Support**: Integrate with proxy rotation for additional anonymity

## Conclusion

These improvements significantly enhance DirHunter AI's ability to avoid WAF detection while maintaining accurate scanning capabilities. The centralized user agent management system makes it easy to maintain and update browser profiles as needed.

