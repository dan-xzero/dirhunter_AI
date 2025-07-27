import os
import logging
from PIL import Image, ImageDraw
import base64
from io import BytesIO

logger = logging.getLogger(__name__)

def create_placeholder_screenshot(url, output_path):
    """Create a placeholder image when screenshots can't be captured"""
    try:
        # Create a simple placeholder image
        width, height = 1280, 800
        img = Image.new('RGB', (width, height), color=(240, 240, 240))
        draw = ImageDraw.Draw(img)
        
        # Add text to the image
        lines = [
            "Screenshot Not Available",
            f"URL: {url}",
            "Possible reasons:",
            "- Selenium not installed or configured",
            "- Chrome/Firefox driver not found",
            "- Site requires authentication",
            "- Network connectivity issues"
        ]
        
        # Add text centered on the image
        y_position = height // 4
        for line in lines:
            # Simple center alignment
            text_width = len(line) * 10  # Rough estimate
            x_position = (width - text_width) // 2
            draw.text((x_position, y_position), line, fill=(70, 70, 70))
            y_position += 40
            
        # Save the image
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        img.save(output_path)
        
        # Create text content file
        text_path = output_path.rsplit('.', 1)[0] + '.txt'
        with open(text_path, 'w', encoding='utf-8') as f:
            f.write(f"Placeholder for {url}\nScreenshot not available")
            
        logger.info(f"Created placeholder screenshot for {url} at {output_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to create placeholder screenshot: {e}")
        
        # Last resort - create empty files
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(b'')
            with open(output_path.rsplit('.', 1)[0] + '.txt', 'w') as f:
                f.write('')
        except Exception as inner_e:
            logger.error(f"Failed to create empty files: {inner_e}")
            
        return False 