#!/usr/bin/env python3
"""
False Positive Reduction Module for Technology Detection

This module provides functions to reduce false positives in technology detection:
1. Confidence scoring based on multiple signals
2. Secondary verification of detected technologies
3. False positive filtering rules
4. Context-aware detection
"""

import logging
import re
from typing import Dict, List, Any, Set, Tuple, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Known false positive patterns
FALSE_POSITIVE_RULES = {
    # Technology: List of rules to consider it a false positive
    "WordPress": [
        # If detected from quick_pattern but specific WP paths not found
        {"condition": lambda tech_info, all_techs: 
            tech_info.get("source") == "quick_pattern" and 
            not any(p in all_techs for p in ["wp-login.php", "wp-admin", "wp-content"])
        },
        # If specifically detected with an incompatible stack
        {"condition": lambda tech_info, all_techs:
            "Drupal" in all_techs and "Magento" in all_techs
        }
    ],
    
    "Drupal": [
        # If detected from active_scan but specific Drupal paths return generic content
        {"condition": lambda tech_info, all_techs: 
            tech_info.get("source") == "active_scan" and
            tech_info.get("path") == "sites/default/" and
            "WordPress" in all_techs and not "Drupal" in tech_info.get("page_text", "").lower()
        }
    ],
    
    "Magento": [
        # If detected from active_scan path that might exist in other platforms
        {"condition": lambda tech_info, all_techs: 
            tech_info.get("source") == "active_scan" and
            tech_info.get("path") in ["admin/", "checkout/"]
        }
    ],
    
    "Django": [
        # If detected from active_scan with /media/ which is common elsewhere
        {"condition": lambda tech_info, all_techs: 
            tech_info.get("source") == "active_scan" and
            tech_info.get("path") == "media/" and
            not any(t.startswith("Python") for t in all_techs)
        }
    ]
}

# Technology compatibility matrix
# Format: {tech1: {compatible: [tech2, tech3], incompatible: [tech4, tech5]}}
COMPATIBILITY_MATRIX = {
    "WordPress": {
        "compatible": ["PHP", "jQuery", "MySQL", "React", "GraphQL", "REST API"],
        "incompatible": ["Drupal", "Joomla", "Magento", "Django", "ASP.NET"]
    },
    "Drupal": {
        "compatible": ["PHP", "jQuery", "MySQL", "Symfony"],
        "incompatible": ["WordPress", "Joomla", "Magento", "Django", "ASP.NET"]
    },
    "Magento": {
        "compatible": ["PHP", "jQuery", "MySQL", "Zend"],
        "incompatible": ["WordPress", "Drupal", "Joomla", "Django", "ASP.NET"]
    },
    "Django": {
        "compatible": ["Python", "PostgreSQL", "SQLite", "jQuery"],
        "incompatible": ["WordPress", "Drupal", "Joomla", "ASP.NET", "PHP"]
    },
    "ASP.NET": {
        "compatible": ["Microsoft SQL Server", "jQuery", "IIS"],
        "incompatible": ["WordPress", "Drupal", "Joomla", "Django", "Apache"]
    },
    "Node.js": {
        "compatible": ["Express.js", "MongoDB", "React", "Angular", "Vue.js"],
        "incompatible": []  # Node can run alongside many other platforms
    }
}

def calculate_confidence_score(tech_name: str, tech_info: Dict[str, Any], all_techs: Dict[str, Any]) -> float:
    """
    Calculate a confidence score for a detected technology
    
    Args:
        tech_name: Name of the technology
        tech_info: Information about the technology
        all_techs: All detected technologies
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    base_score = 0.5  # Default medium confidence
    
    # Source-based confidence
    source = tech_info.get("source", "unknown")
    if source == "header":
        base_score = 0.9  # Headers are very reliable
    elif source == "active_scan":
        base_score = 0.8  # Active scanning is quite reliable
    elif source == "complex_pattern":
        base_score = 0.7  # Complex patterns are somewhat reliable
    elif source == "quick_pattern":
        base_score = 0.6  # Quick patterns are less reliable
    
    # Adjust for version information
    if tech_info.get("version"):
        base_score += 0.1  # Version information increases confidence
    
    # Adjust for multiple detections
    tech_sources = set()
    for name, info in all_techs.items():
        if name == tech_name:
            continue
        if isinstance(info, dict) and "source" in info:
            tech_sources.add(info["source"])
    
    # More sources increases confidence
    if len(tech_sources) >= 2:
        base_score += 0.05 * min(len(tech_sources), 3)
    
    # Adjust for compatibility with other detected technologies
    if tech_name in COMPATIBILITY_MATRIX:
        compat_info = COMPATIBILITY_MATRIX[tech_name]
        
        # Check for compatible technologies
        compatible_count = sum(1 for t in compat_info.get("compatible", []) if t in all_techs)
        if compatible_count > 0:
            base_score += 0.05 * min(compatible_count, 3)
        
        # Check for incompatible technologies
        incompatible_count = sum(1 for t in compat_info.get("incompatible", []) if t in all_techs)
        if incompatible_count > 0:
            base_score -= 0.15 * min(incompatible_count, 3)
    
    # Cap the score between 0.0 and 1.0
    return max(0.0, min(1.0, base_score))

def check_false_positives(tech_name: str, tech_info: Dict[str, Any], all_techs: Dict[str, Any]) -> bool:
    """
    Check if a detected technology is likely a false positive
    
    Args:
        tech_name: Name of the technology
        tech_info: Information about the technology
        all_techs: All detected technologies
        
    Returns:
        True if likely a false positive, False otherwise
    """
    # Skip if no rules for this technology
    if tech_name not in FALSE_POSITIVE_RULES:
        return False
    
    # Check each rule for this technology
    for rule in FALSE_POSITIVE_RULES[tech_name]:
        condition = rule.get("condition")
        if condition and callable(condition):
            if condition(tech_info, all_techs):
                logger.debug(f"False positive detected: {tech_name}")
                return True
    
    return False

def verify_technology(tech_name: str, tech_info: Dict[str, Any]) -> float:
    """
    Perform additional verification for a technology
    
    Args:
        tech_name: Name of the technology
        tech_info: Information about the technology
        
    Returns:
        Verification score between 0.0 and 1.0
    """
    score = 0.5  # Default medium confidence
    
    # Check for specific verification markers
    source = tech_info.get("source", "unknown")
    
    if source == "header":
        # Headers are very reliable
        score = 0.9
    elif source == "active_scan":
        # Check for more specific path-based verification
        path = tech_info.get("path", "")
        
        if tech_name == "WordPress" and path in ["wp-login.php", "wp-admin/"]:
            score = 0.9
        elif tech_name == "Drupal" and path in ["user/login", "core/"]:
            score = 0.9
        elif tech_name == "Django" and path in ["admin/login/", "static/admin/"]:
            score = 0.9
    
    return score

def filter_false_positives(detected_techs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter out likely false positives from detected technologies
    
    Args:
        detected_techs: Dict of detected technologies
        
    Returns:
        Dict of filtered technologies
    """
    filtered_techs = {}
    tech_names = {k: v for k, v in detected_techs.items() if k not in ('cve_vulns', 'cve_details')}
    
    # First pass: calculate confidence scores
    for tech_name, tech_info in tech_names.items():
        # Skip non-tech entries
        if not isinstance(tech_info, dict):
            continue
            
        # Calculate confidence score
        confidence = calculate_confidence_score(tech_name, tech_info, tech_names)
        
        # Update confidence in tech info
        tech_info["confidence"] = confidence
        
        # Perform additional verification
        verification = verify_technology(tech_name, tech_info)
        
        # Adjust confidence based on verification
        confidence = (confidence + verification) / 2
        tech_info["confidence"] = confidence
        
        # Keep track of confidence scores
        filtered_techs[tech_name] = tech_info
    
    # Second pass: filter out false positives
    filtered_techs = {
        tech_name: tech_info for tech_name, tech_info in filtered_techs.items()
        if (isinstance(tech_info, dict) and 
            tech_info.get("confidence", 0) >= 0.5 and 
            not check_false_positives(tech_name, tech_info, tech_names))
    }
    
    # Add back metadata
    if 'cve_vulns' in detected_techs:
        filtered_techs['cve_vulns'] = detected_techs['cve_vulns']
    if 'cve_details' in detected_techs:
        filtered_techs['cve_details'] = detected_techs['cve_details']
    
    # Log filtering results
    original_count = len(tech_names)
    filtered_count = len({k: v for k, v in filtered_techs.items() if k not in ('cve_vulns', 'cve_details')})
    
    if original_count > filtered_count:
        logger.info(f"Removed {original_count - filtered_count} likely false positives")
    
    return filtered_techs 