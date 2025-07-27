import os
import logging

logger = logging.getLogger(__name__)

class PathManager:
    def __init__(self):
        self.project_root = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        
        # Define core directories
        self.dirs = {
            'screenshots': os.path.join(self.project_root, 'results', 'screenshots'),
            'raw': os.path.join(self.project_root, 'results', 'raw'),
            'html': os.path.join(self.project_root, 'results', 'html'),
            'db': os.path.join(self.project_root, 'db'),
        }
        
        # Ensure all directories exist
        for name, path in self.dirs.items():
            os.makedirs(path, exist_ok=True)
            logger.debug(f"Ensured directory exists: {path}")
            
    def get_path(self, key):
        """Get the absolute path for a specific directory"""
        return self.dirs.get(key)
        
    def get_screenshot_path(self, domain, path_fragment):
        """Get absolute path for a screenshot with proper directory creation"""
        domain_dir = os.path.join(self.dirs['screenshots'], domain)
        os.makedirs(domain_dir, exist_ok=True)
        return os.path.join(domain_dir, path_fragment)

# Initialize global instance
path_manager = PathManager() 