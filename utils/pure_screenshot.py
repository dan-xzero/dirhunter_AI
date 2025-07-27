#!/usr/bin/env python3
"""
Pure Screenshot - A Python-only screenshot solution that doesn't depend on Selenium
"""

import os
import logging
import tempfile
import uuid
from datetime import datetime
import textwrap
from typing import Optional

# Configure logging
logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests package not available - using minimal mode")

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("PIL package not available - using minimal mode")

def capture_screenshot(url: str, output_path: str) -> bool:
    """
    Capture a screenshot of a webpage without using Selenium.
    
    Args:
        url (str): The URL to capture
        output_path (str): Where to save the image
    
    Returns:
        bool: True if successful, False otherwise
    """
    logger.info(f"Taking pure screenshot of {url}")
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Try to get page content first
    page_content = None
    page_title = None
    error_msg = None
    
    if REQUESTS_AVAILABLE:
        try:
            # Use a modern user agent
            headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            page_content = response.text
            
            # Try to extract title
            if "<title>" in page_content and "</title>" in page_content:
                title_start = page_content.find("<title>") + 7
                title_end = page_content.find("</title>", title_start)
                page_title = page_content[title_start:title_end].strip()
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Failed to get page content: {e}")
    
    # Create image with page information
    if PIL_AVAILABLE:
        return _create_info_image(url, output_path, page_title, page_content, error_msg)
    else:
        return _create_minimal_file(url, output_path, page_title, page_content, error_msg)

def _create_info_image(url: str, output_path: str, page_title: Optional[str], 
                      page_content: Optional[str], error_msg: Optional[str]) -> bool:
    """Create an information image with page details"""
    try:
        # Create a blank image
        width, height = 1280, 800
        img = Image.new('RGB', (width, height), color=(245, 245, 245))
        draw = ImageDraw.Draw(img)
        
        # Add header background
        draw.rectangle([(0, 0), (width, 60)], fill=(70, 130, 180))
        
        # Basic info to display
        lines = []
        
        # Add header text
        draw.text((20, 20), url, fill=(255, 255, 255))
        draw.text((width - 200, 20), datetime.now().strftime("%Y-%m-%d %H:%M"), fill=(255, 255, 255))
        
        # Add page title if available
        y_pos = 80
        if page_title:
            # Wrap title to fit image width
            wrapped_title = textwrap.fill(page_title, width=80)
            draw.text((20, y_pos), f"Title: {wrapped_title}", fill=(0, 0, 0))
            y_pos += 40
        
        # Add error message if any
        if error_msg:
            draw.text((20, y_pos), f"Error: {error_msg}", fill=(255, 0, 0))
            y_pos += 40
        
        # Add page info section
        y_pos += 20
        draw.text((20, y_pos), "Page Information:", fill=(0, 0, 0))
        y_pos += 30
        
        if page_content:
            # Add content snippet
            content_preview = page_content[:1000].replace("\n", " ").strip()
            wrapped_content = textwrap.fill(content_preview, width=100)
            draw.text((20, y_pos), wrapped_content + "...", fill=(60, 60, 60))
            
            # Save extracted text
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write(page_content[:10000])  # Save first 10K chars
        else:
            draw.text((20, y_pos), "No content available", fill=(100, 100, 100))
            
            # Create empty text file
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write(f"Failed to get content for {url}")
        
        # Save the image
        img.save(output_path)
        logger.info(f"Created info image at {output_path}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to create info image: {e}")
        return _create_minimal_file(url, output_path, page_title, page_content, error_msg)

def _create_minimal_file(url: str, output_path: str, page_title: Optional[str],
                        page_content: Optional[str], error_msg: Optional[str]) -> bool:
    """Create minimal placeholder files when PIL is not available"""
    try:
        # Create an empty image file
        with open(output_path, 'wb') as f:
            f.write(b'')
        
        # Create text file with info
        text_path = output_path.rsplit('.', 1)[0] + '.txt'
        with open(text_path, 'w', encoding='utf-8') as f:
            f.write(f"URL: {url}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            
            if page_title:
                f.write(f"Title: {page_title}\n")
            
            if error_msg:
                f.write(f"Error: {error_msg}\n")
            
            if page_content:
                f.write("\n--- Content Preview ---\n")
                f.write(page_content[:5000])
        
        logger.info(f"Created minimal placeholder files at {output_path}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to create minimal files: {e}")
        return False

# For use as a module in the main application
def take_screenshot(url: str, output_path: str) -> bool:
    """Compatible interface with utils/screenshot.py"""
    return capture_screenshot(url, output_path)

# For testing directly
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = "https://www.example.com"
        
    output_dir = "test_screenshots"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "pure_screenshot.png")
    
    success = capture_screenshot(url, output_path)
    print(f"Screenshot {'succeeded' if success else 'failed'}: {output_path}") 