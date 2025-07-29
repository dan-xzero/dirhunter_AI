#!/usr/bin/env python3
"""
Fingerprint Manager - Manages multiple technology detection backends
with priority given to browser-free methods.
"""

import os
import logging
from typing import Dict, Any, Optional
import time # Added for timing

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def detect_technologies_for_url(url: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Detect technologies for a URL using the best available detector
    
    Args:
        url: The URL to analyze
        use_cache: Whether to use cached results
        
    Returns:
        Dictionary with technology information
    """
    # Add URL normalization to ensure consistent cache keys
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # First, try to use our browser-free detector (simple_tech_detector)
    try:
        from utils.simple_tech_detector import detect_technologies
        
        if not use_cache:
            # Clear cache for this URL by creating a temporary function
            import hashlib
            import os
            import json
            
            url_hash = hashlib.md5(url.encode()).hexdigest()
            cache_file = os.path.join("db", "tech_cache.json")
            
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, 'r') as f:
                        cache = json.load(f)
                    
                    if url_hash in cache:
                        del cache[url_hash]
                        logger.info(f"Cleared cache for {url}")
                        
                    with open(cache_file, 'w') as f:
                        json.dump(cache, f)
                except Exception as e:
                    logger.warning(f"Error clearing cache: {e}")
        
        # Call the detector
        logger.info(f"Using browser-free technology detector for {url}")
        start_time = time.time()
        results = detect_technologies(url)
        elapsed = time.time() - start_time
        
        if results:
            # Count technologies and versions (excluding metadata keys)
            tech_count = len([k for k in results if k not in ('cve_vulns', 'cve_details')])
            version_count = sum(1 for k, v in results.items() 
                              if k not in ('cve_vulns', 'cve_details') and 
                              isinstance(v, dict) and v.get('version'))
            
            logger.info(f"Detected {tech_count} technologies for {url} in {elapsed:.2f}s "
                       f"({version_count} with version info)")
            
            # Log CVE information if available
            if 'cve_vulns' in results and results['cve_vulns'] > 0:
                logger.info(f"Found {results['cve_vulns']} potential vulnerabilities in {url}")
            
            return results
        
        logger.warning(f"Browser-free detector failed for {url}, trying fallback")
    except ImportError:
        logger.warning("Browser-free detector not available, trying fallback")
    except Exception as e:
        logger.warning(f"Error in browser-free detector: {e}")
    
    # Fall back to tech_fingerprint (which now uses simple_tech_detector as well)
    try:
        from utils.tech_fingerprint import fingerprint
        
        logger.info(f"Using tech_fingerprint fallback for {url}")
        start_time = time.time()
        results = fingerprint(url)
        elapsed = time.time() - start_time
        
        if results:
            logger.info(f"Tech fingerprint detected technologies for {url} in {elapsed:.2f}s")
            return results
        
        logger.warning(f"Tech fingerprint detector failed for {url}")
        return {}
    except ImportError:
        logger.warning("Tech fingerprint detector not available")
        return {}
    except Exception as e:
        logger.error(f"Error in tech fingerprint detector: {e}")
        return {}

def check_cves_for_technologies(techs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check for CVEs in the detected technologies
    
    Args:
        techs: Dictionary of detected technologies
        
    Returns:
        Updated technologies dictionary with CVE information
    """
    if not techs or "cve_details" in techs:
        return techs  # Already processed or no technologies
    
    try:
        from utils.simple_tech_detector import _prepare_for_cve_detection
        from utils.cve import check_components
        
        # Prepare components in the format needed for CVE checking
        components = _prepare_for_cve_detection(techs)
        
        # Only proceed if we have components with versions
        if components:
            cve_results = check_components(components)
            
            if cve_results:
                # Store the overall count
                techs["cve_vulns"] = len(cve_results)
                
                # Organize by package
                cve_details = {}
                for cve in cve_results:
                    pkg_name = cve.get("package", "").lower()
                    if not pkg_name:
                        continue
                        
                    if pkg_name not in cve_details:
                        cve_details[pkg_name] = {"ids": [], "version": cve.get("version", "")}
                        
                    cve_id = cve.get("id", "")
                    if cve_id and cve_id not in cve_details[pkg_name]["ids"]:
                        cve_details[pkg_name]["ids"].append(cve_id)
                
                techs["cve_details"] = cve_details
    except Exception as e:
        logger.error(f"Error checking CVEs: {e}")
    
    return techs 