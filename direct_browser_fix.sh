#!/bin/bash
# Direct Browser Fix Script for SSH Servers
# This script installs Chrome directly without snap

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
RESET="\033[0m"

echo -e "${BOLD}=== Direct Browser Fix for SSH Servers ===${RESET}"
echo "This script will install Chromium directly via APT."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}Please run as root (sudo).${RESET}"
  exit 1
fi

# First, clean up the problematic snap directories
echo -e "\n${BOLD}Cleaning problematic snap directories...${RESET}"
rm -rf /tmp/snap* 2>/dev/null
chmod 1777 /tmp

# Fix snap directories if they exist
if [ -d "/var/lib/snapd/tmp" ]; then
  chmod -R 1777 /var/lib/snapd/tmp
  echo -e "${GREEN}✓${RESET} Fixed snap tmp directory permissions"
fi

# Install necessary packages
echo -e "\n${BOLD}Installing core packages...${RESET}"
apt-get update > /dev/null 2>&1
apt-get install -y xvfb unzip wget curl gnupg > /dev/null 2>&1

# Remove any snap packages that might cause conflicts
echo -e "\n${BOLD}Removing conflicting snap packages...${RESET}"
snap remove chromium firefox 2>/dev/null

# Add Google Chrome repository
echo -e "\n${BOLD}Adding Google Chrome repository...${RESET}"
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - > /dev/null 2>&1
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list
apt-get update > /dev/null 2>&1

# Install Google Chrome
echo -e "\n${BOLD}Installing Google Chrome...${RESET}"
apt-get install -y google-chrome-stable > /dev/null 2>&1
if command -v google-chrome-stable &> /dev/null; then
  echo -e "${GREEN}✓${RESET} Google Chrome installed successfully"
  google-chrome-stable --version
else
  echo -e "${RED}✗${RESET} Failed to install Google Chrome"
fi

# Create symlink for convenience
ln -sf /usr/bin/google-chrome-stable /usr/local/bin/chrome
chmod +x /usr/local/bin/chrome
echo -e "${GREEN}✓${RESET} Created symlink at /usr/local/bin/chrome"

# Download and install ChromeDriver
echo -e "\n${BOLD}Installing ChromeDriver...${RESET}"
CHROME_VERSION=$(google-chrome-stable --version | awk '{print $3}' | cut -d. -f1)
echo "Chrome major version: $CHROME_VERSION"

LATEST_CHROMEDRIVER=$(curl -s "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_${CHROME_VERSION}")
echo "ChromeDriver version: $LATEST_CHROMEDRIVER"

TEMP_DIR=$(mktemp -d)
wget -q "https://chromedriver.storage.googleapis.com/${LATEST_CHROMEDRIVER}/chromedriver_linux64.zip" -O "${TEMP_DIR}/chromedriver.zip"

if [ -f "${TEMP_DIR}/chromedriver.zip" ]; then
  unzip -q "${TEMP_DIR}/chromedriver.zip" -d "${TEMP_DIR}"
  chmod +x "${TEMP_DIR}/chromedriver"
  mv "${TEMP_DIR}/chromedriver" /usr/local/bin/chromedriver
  echo -e "${GREEN}✓${RESET} ChromeDriver installed to /usr/local/bin/chromedriver"
else
  echo -e "${RED}✗${RESET} Failed to download ChromeDriver"
fi

# Clean up
rm -rf "${TEMP_DIR}"

# Install Selenium in all Python environments
echo -e "\n${BOLD}Installing Selenium...${RESET}"
apt-get install -y python3-pip > /dev/null 2>&1

# Install for system Python
pip3 install --upgrade selenium > /dev/null 2>&1
echo -e "${GREEN}✓${RESET} Selenium installed for system Python"

# Install for virtual environment if it exists
if [ -d "./dirscan/lib/python3.12/site-packages" ]; then
  echo -e "${BOLD}Installing Selenium in virtual environment...${RESET}"
  ./dirscan/bin/pip install --upgrade selenium > /dev/null 2>&1
  echo -e "${GREEN}✓${RESET} Selenium installed in virtual environment"
fi

# Fix permissions
echo -e "\n${BOLD}Fixing permissions...${RESET}"
chmod 1777 /tmp
echo -e "${GREEN}✓${RESET} /tmp permissions fixed"

# Create simple test
cat > /tmp/direct_test.py << 'EOF'
#!/usr/bin/env python3
import os
import sys
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options

print("Testing Chrome with Selenium...")
try:
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.binary_location = "/usr/local/bin/chrome"
    
    service = Service(executable_path="/usr/local/bin/chromedriver")
    
    print("Creating driver...")
    driver = webdriver.Chrome(service=service, options=chrome_options)
    
    print("Opening example.com...")
    driver.get("https://www.example.com")
    print(f"Page title: {driver.title}")
    
    screenshot_path = "chrome_test.png"
    print(f"Taking screenshot to {screenshot_path}...")
    driver.save_screenshot(screenshot_path)
    print(f"Screenshot saved to {os.path.abspath(screenshot_path)}")
    
    driver.quit()
    print("Chrome test passed!")
    sys.exit(0)
except Exception as e:
    print(f"Chrome test failed: {e}")
    sys.exit(1)
EOF

chmod +x /tmp/direct_test.py

# Install Xvfb for virtual display
echo -e "\n${BOLD}Installing Xvfb...${RESET}"
apt-get install -y xvfb > /dev/null 2>&1
echo -e "${GREEN}✓${RESET} Xvfb installed"

echo -e "\n${BOLD}Testing browser setup with Xvfb...${RESET}"
export DISPLAY=:99
Xvfb :99 -screen 0 1280x1024x24 -ac &
XVFB_PID=$!

# Give Xvfb time to start
sleep 2

python3 /tmp/direct_test.py
TEST_RESULT=$?

# Kill Xvfb
kill $XVFB_PID

# Check test result
if [ $TEST_RESULT -eq 0 ]; then
  echo -e "\n${BOLD}${GREEN}Browser setup successful!${RESET}"
  echo -e "Your browser is now properly configured for DirHunter AI."
else
  echo -e "\n${BOLD}${RED}Browser setup failed.${RESET}"
  
  # Create a wrapper script for screenshots
  echo -e "\n${BOLD}Creating headless chrome wrapper script...${RESET}"
  cat > /usr/local/bin/headless-chrome << 'EOF'
#!/bin/bash
# Headless Chrome wrapper script
export DISPLAY=:99
Xvfb :99 -screen 0 1280x1024x24 -ac &
XVFB_PID=$!
sleep 1

# Run Chrome with given arguments
/usr/bin/google-chrome-stable "$@"
EXIT_CODE=$?

# Kill Xvfb
kill $XVFB_PID || true

exit $EXIT_CODE
EOF

  chmod +x /usr/local/bin/headless-chrome
  echo -e "${GREEN}✓${RESET} Created headless Chrome wrapper at /usr/local/bin/headless-chrome"
  
  echo -e "\n${BOLD}Creating simplified direct screenshot script...${RESET}"
  cat > /usr/local/bin/direct-screenshot << 'EOF'
#!/bin/bash
# Direct screenshot script without Selenium
# Usage: direct-screenshot URL OUTPUT_PATH

if [ $# -lt 2 ]; then
  echo "Usage: $0 <url> <output_path>"
  exit 1
fi

URL=$1
OUTPUT_PATH=$2

# Create directory if needed
mkdir -p $(dirname "$OUTPUT_PATH")

# Take screenshot directly with Chrome
headless-chrome --headless=new --disable-gpu --no-sandbox --screenshot="$OUTPUT_PATH" "$URL"
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "Screenshot saved to $OUTPUT_PATH"
  
  # Save page source to text file
  TEXT_PATH="${OUTPUT_PATH%.*}.txt"
  headless-chrome --headless=new --disable-gpu --no-sandbox --dump-dom "$URL" > "$TEXT_PATH"
  
  echo "Page content saved to $TEXT_PATH"
  exit 0
else
  echo "Failed to take screenshot with exit code $EXIT_CODE"
  exit 1
fi
EOF

  chmod +x /usr/local/bin/direct-screenshot
  echo -e "${GREEN}✓${RESET} Created direct screenshot script at /usr/local/bin/direct-screenshot"
  
  echo -e "\n${BOLD}Testing direct screenshot script...${RESET}"
  direct-screenshot https://example.com test_screenshot_direct.png
  
  if [ -f "test_screenshot_direct.png" ]; then
    echo -e "${GREEN}✓${RESET} Direct screenshot successful!"
    echo -e "\n${BOLD}${GREEN}Alternative screenshot method is working!${RESET}"
  else
    echo -e "${RED}✗${RESET} Direct screenshot failed."
  fi
fi

# Modify utils/screenshot.py to use direct-screenshot as fallback
echo -e "\n${BOLD}Would you like to patch DirHunter AI to use the direct screenshot method? (y/n)${RESET}"
read -p "> " PATCH_RESPONSE

if [[ $PATCH_RESPONSE == "y" || $PATCH_RESPONSE == "Y" ]]; then
  SCREENSHOT_FILE="utils/screenshot.py"
  if [ -f "$SCREENSHOT_FILE" ]; then
    # Create backup
    cp "$SCREENSHOT_FILE" "${SCREENSHOT_FILE}.backup"
    echo -e "${GREEN}✓${RESET} Created backup of $SCREENSHOT_FILE at ${SCREENSHOT_FILE}.backup"
    
    # Add direct screenshot fallback
    cat > /tmp/screenshot_patch.py << 'EOF'

# Direct screenshot method added by direct_browser_fix.sh
def take_direct_screenshot(url, output_path):
    """Take screenshot using direct Chrome command without Selenium"""
    import subprocess
    import os
    logger.info(f"Using direct Chrome method for {url}")
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    try:
        # Use the direct-screenshot script
        cmd = ['/usr/local/bin/direct-screenshot', url, output_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"Direct screenshot saved to {output_path}")
            return True
        else:
            logger.error(f"Direct screenshot failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error taking direct screenshot: {e}")
        return False

# Original create_fallback_screenshot function
EOF

    # Insert our new function into the file
    sed -i '/def create_fallback_screenshot/e cat /tmp/screenshot_patch.py' "$SCREENSHOT_FILE"
    
    # Now modify take_screenshot function to use our method
    sed -i 's/        success = take_browser_screenshot(url, output_path)/        # Try direct screenshot first\n        success = take_direct_screenshot(url, output_path)\n        \n        # If direct screenshot fails, try browser screenshot\n        if not success:\n            success = take_browser_screenshot(url, output_path)/' "$SCREENSHOT_FILE"
    
    echo -e "${GREEN}✓${RESET} Modified $SCREENSHOT_FILE to use direct screenshot method"
  else
    echo -e "${RED}✗${RESET} Could not find $SCREENSHOT_FILE"
  fi
else
  echo -e "${YELLOW}Skipping DirHunter AI patch.${RESET}"
fi

echo -e "\n${BOLD}Setup complete!${RESET}"
echo -e "If the test was successful, your browser setup should now work with DirHunter AI."
echo -e "If you continue to have issues, you can manually run: direct-screenshot URL OUTPUT_PATH" 