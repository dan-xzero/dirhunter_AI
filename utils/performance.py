# File: dirhunter_ai/utils/performance.py
import time
from collections import defaultdict
from datetime import datetime

class PerformanceTracker:
    """Track performance metrics for domain scanning"""
    
    def __init__(self):
        self.scan_times = {}
        self.filter_times = {}
        self.screenshot_times = {}
        self.classification_times = {}
        self.total_times = {}
        self.findings_count = {}
        self.rate_limits = {}
        self.errors = {}
        self.start_time = time.time()
    
    def record_scan_time(self, domain, duration):
        """Record FFUF scan time for a domain"""
        self.scan_times[domain] = duration
    
    def record_filter_time(self, domain, duration):
        """Record filtering time for a domain"""
        self.filter_times[domain] = duration
    
    def record_screenshot_time(self, domain, duration):
        """Record screenshot generation time for a domain"""
        self.screenshot_times[domain] = duration
    
    def record_classification_time(self, domain, duration):
        """Record AI classification time for a domain"""
        self.classification_times[domain] = duration
    
    def record_total_time(self, domain, duration):
        """Record total processing time for a domain"""
        self.total_times[domain] = duration
    
    def record_findings(self, domain, count):
        """Record number of findings for a domain"""
        self.findings_count[domain] = count
    
    def record_rate_limits(self, domain, count):
        """Record number of rate-limited paths for a domain"""
        self.rate_limits[domain] = count
    
    def record_error(self, domain, error):
        """Record an error for a domain"""
        self.errors[domain] = error
    
    def get_average_time(self, time_dict):
        """Calculate average time from a dictionary of times"""
        if not time_dict:
            return 0
        return sum(time_dict.values()) / len(time_dict)
    
    def generate_report(self, total_elapsed):
        """Generate a comprehensive performance report"""
        report = []
        report.append("=" * 80)
        report.append("PERFORMANCE REPORT")
        report.append("=" * 80)
        report.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total elapsed time: {total_elapsed:.2f} seconds")
        report.append("")
        
        # Summary statistics
        total_domains = len(self.total_times) + len(self.errors)
        successful_domains = len(self.total_times)
        failed_domains = len(self.errors)
        total_findings = sum(self.findings_count.values())
        total_rate_limits = sum(self.rate_limits.values())
        
        report.append("SUMMARY")
        report.append("-" * 40)
        report.append(f"Total domains processed: {total_domains}")
        report.append(f"Successful: {successful_domains}")
        report.append(f"Failed: {failed_domains}")
        report.append(f"Total findings: {total_findings}")
        report.append(f"Total rate limits: {total_rate_limits}")
        report.append("")
        
        # Average times
        report.append("AVERAGE TIMES PER DOMAIN")
        report.append("-" * 40)
        report.append(f"FFUF scan: {self.get_average_time(self.scan_times):.2f}s")
        report.append(f"Filtering: {self.get_average_time(self.filter_times):.2f}s")
        report.append(f"Screenshots: {self.get_average_time(self.screenshot_times):.2f}s")
        report.append(f"AI Classification: {self.get_average_time(self.classification_times):.2f}s")
        report.append(f"Total: {self.get_average_time(self.total_times):.2f}s")
        report.append("")
        
        # Performance breakdown by domain
        report.append("DOMAIN BREAKDOWN")
        report.append("-" * 40)
        report.append(f"{'Domain':<40} {'Total':<10} {'Findings':<10} {'Status'}")
        report.append("-" * 80)
        
        # Sort by total time
        sorted_domains = sorted(self.total_times.items(), key=lambda x: x[1], reverse=True)
        
        for domain, total_time in sorted_domains:
            findings = self.findings_count.get(domain, 0)
            status = "OK"
            if domain in self.rate_limits:
                status = f"OK ({self.rate_limits[domain]} rate limits)"
            report.append(f"{domain:<40} {total_time:<10.2f} {findings:<10} {status}")
        
        # Failed domains
        if self.errors:
            report.append("")
            report.append("FAILED DOMAINS")
            report.append("-" * 40)
            for domain, error in self.errors.items():
                report.append(f"{domain}: {error}")
        
        # Performance insights
        report.append("")
        report.append("PERFORMANCE INSIGHTS")
        report.append("-" * 40)
        
        # Identify bottlenecks
        if self.scan_times:
            slowest_scan = max(self.scan_times.items(), key=lambda x: x[1])
            report.append(f"Slowest FFUF scan: {slowest_scan[0]} ({slowest_scan[1]:.2f}s)")
        
        if self.classification_times:
            slowest_class = max(self.classification_times.items(), key=lambda x: x[1])
            report.append(f"Slowest AI classification: {slowest_class[0]} ({slowest_class[1]:.2f}s)")
        
        # Efficiency metrics
        if total_domains > 0:
            avg_time_per_domain = total_elapsed / total_domains
            domains_per_hour = 3600 / avg_time_per_domain if avg_time_per_domain > 0 else 0
            report.append(f"Average time per domain: {avg_time_per_domain:.2f}s")
            report.append(f"Estimated throughput: {domains_per_hour:.0f} domains/hour")
        
        if total_findings > 0 and successful_domains > 0:
            avg_findings_per_domain = total_findings / successful_domains
            report.append(f"Average findings per domain: {avg_findings_per_domain:.1f}")
        
        report.append("=" * 80)
        
        return "\n".join(report) 