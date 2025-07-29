#!/usr/bin/env python3
"""
Active Scanning Module for Enhanced Technology Detection

This module provides active scanning techniques to improve technology detection accuracy:
1. Path probing - checking common paths to identify technologies
2. JavaScript analysis - finding JS libraries and frameworks
3. Headers and cookies analysis - detecting patterns in HTTP headers and cookies
4. Response behavior analysis - testing how the application responds to various inputs
"""

import os
import logging
import json
import re
import time
import urllib.parse
from typing import Dict, List, Any, Set, Tuple, Optional
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Common paths to probe for technology detection
TECHNOLOGY_PATHS = {
    "WordPress": [
        ("/wp-login.php", "WordPress"),
        ("/wp-admin/", "WordPress"),
        ("/wp-content/", "WordPress"),
        ("/wp-includes/", "WordPress")
    ],
    "Drupal": [
        ("/user/login", "Drupal"),
        ("/admin/", "Drupal"),
        ("/sites/default/", "Drupal"),
        ("/core/", "Drupal")
    ],
    "Joomla": [
        ("/administrator/", "Joomla"),
        ("/components/", "Joomla"),
        ("/modules/", "Joomla"),
        ("/templates/", "Joomla")
    ],
    "Magento": [
        ("/admin/", "Magento"),
        ("/skin/", "Magento"),
        ("/checkout/", "Magento"),
        ("/mage/", "Magento")
    ],
    "Laravel": [
        ("/artisan", "Laravel"),
        ("/storage/logs/", "Laravel"),
        ("/vendor/laravel/", "Laravel")
    ],
    "Django": [
        ("/admin/login/", "Django"),
        ("/static/admin/", "Django"),
        ("/media/", "Django")
    ],
    "ASP.NET": [
        ("/aspx", "ASP.NET"),
        ("/webresources/", "ASP.NET"),
        ("/scriptresource.axd", "ASP.NET")
    ],
    "Spring Boot": [
        ("/actuator", "Spring Boot"),
        ("/actuator/health", "Spring Boot"),
        ("/swagger-ui.html", "Spring Boot + Swagger")
    ],
    "Express.js": [
        ("/api/", "Express.js"),
        ("/api/v1/", "Express.js")
    ],
    "Angular": [
        ("/assets/i18n/", "Angular"),
        ("/main.js", "Angular"),
        ("/polyfills.js", "Angular"),
        ("/runtime.js", "Angular")
    ],
    "React": [
        ("/static/js/main.", "React"),
        ("/static/js/bundle.", "React"),
        ("/static/css/main.", "React")
    ]
}

# JavaScript library paths to check
JS_LIBRARY_PATHS = {
    "jQuery": [
        ("/jquery.min.js", "jQuery"),
        ("/jquery-*.min.js", "jQuery"),
        ("/assets/js/jquery", "jQuery")
    ],
    "Vue.js": [
        ("/vue.min.js", "Vue.js"),
        ("/vue.js", "Vue.js")
    ],
    "Bootstrap": [
        ("/bootstrap.min.js", "Bootstrap"),
        ("/bootstrap.min.css", "Bootstrap")
    ],
    "Lodash": [
        ("/lodash.min.js", "Lodash"),
        ("/lodash.js", "Lodash")
    ],
    "Moment.js": [
        ("/moment.min.js", "Moment.js"),
        ("/moment.js", "Moment.js")
    ]
}

# API endpoints to probe
API_ENDPOINTS = {
    "REST API": [
        ("/api", "REST API"),
        ("/api/v1", "REST API"),
        ("/v1", "REST API"),
        ("/rest", "REST API")
    ],
    "GraphQL": [
        ("/graphql", "GraphQL"),
        ("/api/graphql", "GraphQL"),
        ("/gql", "GraphQL")
    ],
    "Swagger": [
        ("/swagger", "Swagger"),
        ("/swagger-ui", "Swagger"),
        ("/api-docs", "Swagger")
    ]
}

# Response header patterns
HEADER_PATTERNS = {
    "Server": {
        r"nginx": "nginx",
        r"Apache": "Apache",
        r"IIS": "IIS",
        r"LiteSpeed": "LiteSpeed",
        r"cloudflare": "Cloudflare",
        r"Express": "Express.js",
        r"gunicorn": "Gunicorn",
        r"openresty": "OpenResty"
    },
    "X-Powered-By": {
        r"PHP": "PHP",
        r"ASP.NET": "ASP.NET",
        r"Express": "Express.js",
        r"JSF": "JavaServer Faces",
        r"Servlet": "Java Servlet",
        r"Django": "Django",
        r"Ruby": "Ruby"
    },
    "Set-Cookie": {
        r"PHPSESSID": "PHP",
        r"laravel_session": "Laravel",
        r"JSESSIONID": "Java",
        r"ASP.NET_SessionId": "ASP.NET",
        r"django": "Django",
        r"wp_": "WordPress",
        r"magento": "Magento",
        r"Drupal": "Drupal"
    },
    "X-Generator": {
        r"WordPress": "WordPress",
        r"Drupal": "Drupal",
        r"Joomla": "Joomla"
    }
}

def probe_paths(base_url: str, max_paths: int = 20, timeout: int = 10) -> Dict[str, Any]:
    """Probe common paths to identify technologies
    
    Args:
        base_url: Base URL to probe
        max_paths: Maximum number of paths to probe
        timeout: Request timeout in seconds
        
    Returns:
        Dict of detected technologies
    """
    detected_techs = {}
    path_count = 0
    
    # Parse base URL and ensure it has a trailing slash
    parsed_url = urllib.parse.urlparse(base_url)
    base = parsed_url.scheme + "://" + parsed_url.netloc
    if not base.endswith('/'):
        base += '/'
    
    # Combine all path lists
    all_paths = []
    for tech, paths in {**TECHNOLOGY_PATHS, **JS_LIBRARY_PATHS, **API_ENDPOINTS}.items():
        for path_info in paths:
            all_paths.append((tech, path_info))
    
    logger.info(f"Probing {min(len(all_paths), max_paths)} paths on {base_url}")
    
    # Create a session for connection pooling
    session = requests.Session()
    
    for tech, (path, tech_name) in all_paths:
        # Check if we've reached the maximum number of paths to probe
        if path_count >= max_paths:
            break
        
        # Skip paths that start with a pattern we've already found
        if any(tech in detected_techs for tech in [tech_name, tech]):
            continue
            
        # Normalize path
        if path.startswith('/'):
            path = path[1:]
        
        # Build the full URL
        full_url = base + path
        
        try:
            path_count += 1
            
            # Send a HEAD request first to avoid downloading large files
            response = session.head(full_url, timeout=timeout, verify=False, 
                                   allow_redirects=False)
            
            # If successful or redirected, check with a GET request
            if response.status_code in [200, 301, 302, 307, 308]:
                response = session.get(full_url, timeout=timeout, verify=False, 
                                      allow_redirects=False)
                
                if response.status_code == 200:
                    logger.info(f"Found technology indicator at {full_url}")
                    
                    # Record the technology
                    detected_techs[tech_name] = {
                        "version": "",
                        "confidence": "high", 
                        "source": "active_scan",
                        "path": path
                    }
                    
                    # Extract version from response if possible
                    version = extract_version_from_response(response, tech_name)
                    if version:
                        detected_techs[tech_name]["version"] = version
        
        except (requests.RequestException, TimeoutError) as e:
            logger.debug(f"Error probing {full_url}: {e}")
    
    logger.info(f"Active path probing found {len(detected_techs)} technologies")
    return detected_techs

def analyze_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Analyze HTTP headers to identify technologies
    
    Args:
        headers: HTTP response headers
        
    Returns:
        Dict of detected technologies
    """
    detected_techs = {}
    
    for header_name, patterns in HEADER_PATTERNS.items():
        header_value = None
        
        # Find header regardless of case
        for h_name, h_value in headers.items():
            if h_name.lower() == header_name.lower():
                header_value = h_value
                break
        
        if not header_value:
            continue
            
        # Check for patterns in the header value
        for pattern, tech_name in patterns.items():
            if re.search(pattern, header_value, re.IGNORECASE):
                version = ""
                
                # Try to extract version information
                version_match = re.search(r'[0-9]+\.[0-9]+(\.[0-9]+)?', header_value)
                if version_match:
                    version = version_match.group(0)
                
                detected_techs[tech_name] = {
                    "version": version,
                    "confidence": "high", 
                    "source": "header_analysis"
                }
    
    return detected_techs

def extract_version_from_response(response: requests.Response, tech_name: str) -> str:
    """Extract version information from response
    
    Args:
        response: HTTP response
        tech_name: Technology name
        
    Returns:
        Version string or empty string
    """
    version = ""
    
    # Check if content type is text
    content_type = response.headers.get('Content-Type', '')
    if 'text/html' not in content_type and 'application/json' not in content_type:
        return version
    
    try:
        # Look for common version patterns in the response
        content = response.text
        
        # Technology-specific version patterns
        if tech_name == "WordPress":
            match = re.search(r'ver=([0-9]+\.[0-9]+(\.[0-9]+)?)', content)
            if match:
                version = match.group(1)
        elif tech_name == "Drupal":
            match = re.search(r'Drupal ([0-9]+\.[0-9]+)', content)
            if match:
                version = match.group(1)
        elif tech_name in ["jQuery", "Vue.js", "React", "Angular"]:
            match = re.search(r'"version":\s*"([0-9]+\.[0-9]+(\.[0-9]+)?)"', content)
            if match:
                version = match.group(1)
        elif tech_name == "Bootstrap":
            match = re.search(r'Bootstrap v([0-9]+\.[0-9]+(\.[0-9]+)?)', content)
            if match:
                version = match.group(1)
        else:
            # Generic version pattern
            match = re.search(r'[0-9]+\.[0-9]+(\.[0-9]+)?', content)
            if match:
                version = match.group(0)
    except Exception as e:
        logger.debug(f"Error extracting version: {e}")
    
    return version

def perform_active_scan(url: str, timeout: int = 10) -> Dict[str, Any]:
    """Perform active scanning techniques to identify technologies
    
    Args:
        url: URL to scan
        timeout: Request timeout in seconds
        
    Returns:
        Dict of detected technologies
    """
    detected_techs = {}
    
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    logger.info(f"Performing active scan on {url}")
    
    try:
        # Get the base page
        response = requests.get(url, timeout=timeout, verify=False)
        response.raise_for_status()
        
        # Analyze headers from the base page
        header_techs = analyze_headers(response.headers)
        detected_techs.update(header_techs)
        
        # Probe common paths
        path_techs = probe_paths(url, max_paths=20, timeout=timeout)
        
        # Merge results, keeping version information if already detected
        for tech_name, tech_info in path_techs.items():
            if tech_name not in detected_techs:
                detected_techs[tech_name] = tech_info
            elif not detected_techs[tech_name].get("version") and tech_info.get("version"):
                detected_techs[tech_name]["version"] = tech_info["version"]
        
    except requests.RequestException as e:
        logger.error(f"Error during active scan: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during active scan: {e}")
    
    logger.info(f"Active scan found {len(detected_techs)} technologies")
    return detected_techs

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        url = sys.argv[1]
        print(f"Performing active scan on {url}")
        results = perform_active_scan(url)
        
        print("\nDetected Technologies:")
        for tech, info in results.items():
            version = f" v{info['version']}" if info.get('version') else ""
            source = f" ({info.get('source', 'unknown')})"
            print(f"- {tech}{version}{source}")
    else:
        print("Usage: python3 active_scan.py <url>")
        sys.exit(1) 