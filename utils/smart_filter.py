# File: dirhunter_ai/utils/smart_filter.py
"""
Smart filtering module for reducing false positives at scale
"""

import re
import hashlib
from collections import defaultdict
from urllib.parse import urlparse

class SmartFilter:
    """Enhanced filtering with pattern learning and domain-specific rules"""
    
    def __init__(self):
        # Global false positive patterns
        self.global_fp_patterns = [
            # Common 404 patterns
            r"page\s*not\s*found",
            r"404\s*error",
            r"not\s*found",
            r"does\s*not\s*exist",
            r"coming\s*soon",
            r"under\s*construction",
            r"maintenance\s*mode",
            
            # Generic error pages
            r"access\s*denied",
            r"forbidden",
            r"unauthorized",
            r"invalid\s*request",
            
            # Common CMS patterns
            r"wordpress\s*theme",
            r"joomla\s*template",
            r"drupal\s*core",
            
            # Marketing/tracking
            r"google\s*analytics",
            r"facebook\s*pixel",
            r"hotjar",
            r"gtm\.js",
        ]
        
        # Domain-specific false positive cache
        self.domain_fp_cache = defaultdict(set)
        
        # Content hash patterns (for detecting templated responses)
        self.template_hashes = defaultdict(int)
        
        # URL pattern statistics
        self.url_pattern_stats = defaultdict(lambda: defaultdict(int))
        
        # Auto-learned false positives
        self.learned_fps = set()
        
    def is_likely_false_positive(self, url, content, domain=None):
        """
        Determine if a finding is likely a false positive
        """
        content_lower = content.lower() if content else ""
        
        # Check global patterns
        for pattern in self.global_fp_patterns:
            if re.search(pattern, content_lower):
                return True, f"Matches global FP pattern: {pattern}"
        
        # Check domain-specific cache
        if domain and url in self.domain_fp_cache[domain]:
            return True, "Previously identified as FP for this domain"
        
        # Check learned false positives
        content_hash = hashlib.md5(content.encode()).hexdigest() if content else ""
        if content_hash in self.learned_fps:
            return True, "Content matches learned FP pattern"
        
        # Check for templated responses
        if self._is_templated_response(content):
            return True, "Detected as templated response"
        
        # Check URL patterns
        if self._is_suspicious_url_pattern(url, domain):
            return True, "Suspicious URL pattern"
        
        return False, None
    
    def _is_templated_response(self, content):
        """
        Detect templated responses by looking for common patterns
        """
        if not content:
            return False
        
        # Look for template variables
        template_patterns = [
            r"\{\{.*?\}\}",  # Mustache/Handlebars
            r"\{%.*?%\}",    # Jinja2/Django
            r"<%.*?%>",      # ERB/ASP
            r"\$\{.*?\}",    # JSP/Velocity
        ]
        
        for pattern in template_patterns:
            if re.search(pattern, content):
                return True
        
        # Check for repeated content structure
        lines = content.split('\n')
        if len(lines) > 10:
            # Count similar lines
            line_hashes = [hashlib.md5(line.strip().encode()).hexdigest() for line in lines if line.strip()]
            hash_counts = defaultdict(int)
            for h in line_hashes:
                hash_counts[h] += 1
            
            # If more than 30% of lines are identical, likely templated
            max_count = max(hash_counts.values()) if hash_counts else 0
            if max_count > len(line_hashes) * 0.3:
                return True
        
        return False
    
    def _is_suspicious_url_pattern(self, url, domain=None):
        """
        Detect suspicious URL patterns that often lead to false positives
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Common false positive URL patterns
        fp_url_patterns = [
            r"^/[a-f0-9]{32}$",  # MD5 hash paths
            r"^/[a-f0-9]{40}$",  # SHA1 hash paths
            r"^/\d{10,}$",       # Timestamp paths
            r"^/[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$",  # UUIDs
            r"^/wp-content/uploads/\d{4}/\d{2}/",  # WordPress uploads
            r"^/sites/default/files/",  # Drupal files
        ]
        
        for pattern in fp_url_patterns:
            if re.search(pattern, path):
                return True
        
        # Check for excessive path depth (often dynamic routes)
        path_parts = [p for p in path.split('/') if p]
        if len(path_parts) > 6:
            return True
        
        # Check for repeated patterns in URL
        if len(path_parts) > 2:
            if len(set(path_parts)) < len(path_parts) / 2:
                return True
        
        return False
    
    def learn_false_positive(self, url, content, domain=None):
        """
        Learn from user feedback to improve false positive detection
        """
        if content:
            content_hash = hashlib.md5(content.encode()).hexdigest()
            self.learned_fps.add(content_hash)
        
        if domain:
            self.domain_fp_cache[domain].add(url)
    
    def add_domain_specific_pattern(self, domain, pattern):
        """
        Add domain-specific false positive pattern
        """
        if domain not in self.domain_fp_cache:
            self.domain_fp_cache[domain] = set()
        self.domain_fp_cache[domain].add(pattern)
    
    def get_filtering_stats(self):
        """
        Get statistics about filtering performance
        """
        stats = {
            "learned_fps": len(self.learned_fps),
            "domain_rules": {domain: len(fps) for domain, fps in self.domain_fp_cache.items()},
            "global_patterns": len(self.global_fp_patterns)
        }
        return stats
    
    def export_learned_patterns(self, filepath):
        """
        Export learned patterns for reuse
        """
        import json
        data = {
            "learned_fps": list(self.learned_fps),
            "domain_fp_cache": {k: list(v) for k, v in self.domain_fp_cache.items()},
            "global_fp_patterns": self.global_fp_patterns
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def import_learned_patterns(self, filepath):
        """
        Import previously learned patterns
        """
        import json
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.learned_fps = set(data.get("learned_fps", []))
            self.domain_fp_cache = defaultdict(set)
            for domain, fps in data.get("domain_fp_cache", {}).items():
                self.domain_fp_cache[domain] = set(fps)
            
            # Optionally update global patterns
            # self.global_fp_patterns = data.get("global_fp_patterns", self.global_fp_patterns)
            
            return True
        except Exception as e:
            print(f"Failed to import patterns: {e}")
            return False

# Global instance
smart_filter = SmartFilter() 