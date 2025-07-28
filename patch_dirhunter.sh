#!/bin/bash
# Patch DirHunter AI to use the simple_screenshot.sh script

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

echo -e "${BOLD}Patching DirHunter AI to use simple_screenshot.sh${RESET}"

# Make sure simple_screenshot.sh exists and is executable
if [ ! -x "./simple_screenshot.sh" ]; then
  echo -e "${RED}Error: simple_screenshot.sh not found or not executable${RESET}"
  exit 1
fi

# Back up the original screenshot.py
SCREENSHOT_FILE="utils/screenshot.py"
if [ -f "$SCREENSHOT_FILE" ]; then
  # Create backup if it doesn't already exist
  if [ ! -f "${SCREENSHOT_FILE}.backup" ]; then
    cp "$SCREENSHOT_FILE" "${SCREENSHOT_FILE}.backup"
    echo -e "${GREEN}✓${RESET} Created backup of $SCREENSHOT_FILE at ${SCREENSHOT_FILE}.backup"
  else
    echo -e "${GREEN}✓${RESET} Backup already exists at ${SCREENSHOT_FILE}.backup"
  fi
else
  echo -e "${RED}Error: $SCREENSHOT_FILE not found${RESET}"
  exit 1
fi

# Create the patch for simple_screenshot.sh
cat > /tmp/screenshot_patch.py << 'EOF'

# Simple direct screenshot function
def take_simple_screenshot(url, output_path):
    """Take screenshot using simple_screenshot.sh script"""
    import subprocess
    import os
    import logging
    
    logger = logging.getLogger(__name__)
    logger.info(f"Using simple_screenshot.sh for {url}")
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    try:
        cmd = ['./simple_screenshot.sh', url, output_path]
        logger.info(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"Simple screenshot saved to {output_path}")
            return True
        else:
            logger.error(f"Simple screenshot failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error taking simple screenshot: {e}")
        return False

# Original take_screenshot function
EOF

# Insert our new function into the file
sed -i '/def take_screenshot/i\
# Simple direct screenshot method\
def take_simple_screenshot(url, output_path):\
    """Take screenshot using simple_screenshot.sh script"""\
    import subprocess\
    import os\
    import logging\
    \
    logger = logging.getLogger(__name__)\
    logger.info(f"Using simple_screenshot.sh for {url}")\
    \
    os.makedirs(os.path.dirname(output_path), exist_ok=True)\
    \
    try:\
        cmd = ["./simple_screenshot.sh", url, output_path]\
        logger.info(f"Running: {" ".join(cmd)}")\
        result = subprocess.run(cmd, capture_output=True, text=True)\
        \
        if result.returncode == 0:\
            logger.info(f"Simple screenshot saved to {output_path}")\
            return True\
        else:\
            logger.error(f"Simple screenshot failed: {result.stderr}")\
            return False\
    except Exception as e:\
        logger.error(f"Error taking simple screenshot: {e}")\
        return False\
' "$SCREENSHOT_FILE"

# Now modify take_screenshot function to use our method
sed -i 's/def take_screenshot(url, output_path, priority="normal"):.*/def take_screenshot(url, output_path, priority="normal"):\
    """Take a screenshot of a URL with smart strategy selection\
    \
    Args:\
        url: The URL to capture\
        output_path: Where to save the screenshot\
        priority: Priority level ("high", "normal", "low")\
    \
    Returns:\
        bool: True if successful, False otherwise\
    """\
    import os\
    \
    # Try simple screenshot method first\
    success = take_simple_screenshot(url, output_path)\
    \
    # If simple screenshot fails, try browser screenshot\
    if not success:\
        logger.info(f"Simple screenshot failed, trying browser screenshot for {url}")\
        success = take_browser_screenshot(url, output_path)\
        \
        # If browser screenshot fails, try fallback\
        if not success:\
            logger.info(f"Browser screenshot failed, using fallback for {url}")\
            return create_fallback_screenshot(url, output_path)\
    \
    return success/' "$SCREENSHOT_FILE"

echo -e "${GREEN}✓${RESET} Modified $SCREENSHOT_FILE to use simple_screenshot.sh"

# Test the script
echo -e "\n${BOLD}Testing simple_screenshot.sh:${RESET}"
./simple_screenshot.sh https://example.com test_simple.png

if [ $? -eq 0 ]; then
  echo -e "\n${GREEN}✓${RESET} Test successful!"
  echo -e "\n${BOLD}DirHunter AI is now patched to use simple_screenshot.sh!${RESET}"
  echo -e "You can now run your DirHunter AI scans with improved screenshot capabilities."
else
  echo -e "\n${RED}✗${RESET} Test failed. Please check that Google Chrome is installed correctly."
fi 