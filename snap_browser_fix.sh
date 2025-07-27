#!/bin/bash
# Snap Browser Fix Script for SSH Servers
# This script fixes issues with snap-based browsers in headless environments

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
RESET="\033[0m"

echo -e "${BOLD}=== Snap Browser Fix for SSH Servers ===${RESET}"
echo "This script will fix issues with snap-based browsers for Selenium."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}Please run as root (sudo).${RESET}"
  exit 1
fi

# Install necessary packages
echo -e "\n${BOLD}Installing core packages...${RESET}"
apt-get update > /dev/null 2>&1
apt-get install -y xvfb unzip wget curl > /dev/null 2>&1

# Install snap if not available
if ! command -v snap &> /dev/null; then
  echo -e "\n${BOLD}Installing snap...${RESET}"
  apt-get install -y snapd > /dev/null 2>&1
  systemctl enable snapd > /dev/null 2>&1
  systemctl start snapd > /dev/null 2>&1
fi

# Install Chrome and Firefox using snap
echo -e "\n${BOLD}Installing browsers via snap...${RESET}"
snap install chromium --classic || echo -e "${RED}Failed to install Chromium snap${RESET}"
snap install firefox --classic || echo -e "${RED}Failed to install Firefox snap${RESET}"

# Create symlinks to ensure browser binaries are accessible
echo -e "\n${BOLD}Creating symlinks for browser access...${RESET}"

# For Chromium
if [ -e "/snap/bin/chromium" ]; then
  ln -sf /snap/bin/chromium /usr/local/bin/chrome
  chmod +x /usr/local/bin/chrome
  echo -e "${GREEN}✓${RESET} Created symlink for Chromium at /usr/local/bin/chrome"
else
  echo -e "${RED}✗${RESET} Could not find Chromium snap binary"
fi

# For Firefox
if [ -e "/snap/bin/firefox" ]; then
  ln -sf /snap/bin/firefox /usr/local/bin/firefox
  chmod +x /usr/local/bin/firefox
  echo -e "${GREEN}✓${RESET} Created symlink for Firefox at /usr/local/bin/firefox"
else
  echo -e "${RED}✗${RESET} Could not find Firefox snap binary"
fi

# Download and install ChromeDriver
echo -e "\n${BOLD}Installing ChromeDriver...${RESET}"
LATEST_CHROMEDRIVER=$(curl -s "https://chromedriver.storage.googleapis.com/LATEST_RELEASE")
echo "Latest ChromeDriver version: $LATEST_CHROMEDRIVER"

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
cat > /tmp/snap_test.py << 'EOF'
#!/usr/bin/env python3
import os
import sys
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options

def test_chrome_selenium():
    print("Testing Chrome with Selenium...")
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.binary_location = "/usr/local/bin/chrome"
        
        service = Service(executable_path="/usr/local/bin/chromedriver")
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        driver.get("https://www.example.com")
        print(f"Page title: {driver.title}")
        
        screenshot_path = os.path.join(os.getcwd(), "chrome_test.png")
        driver.save_screenshot(screenshot_path)
        print(f"Screenshot saved to {screenshot_path}")
        
        driver.quit()
        print("Chrome test passed!")
        return True
    except Exception as e:
        print(f"Chrome test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_chrome_selenium()
    sys.exit(0 if success else 1)
EOF

chmod +x /tmp/snap_test.py

echo -e "\n${BOLD}Testing browser setup...${RESET}"
python3 /tmp/snap_test.py
if [ $? -eq 0 ]; then
  echo -e "\n${BOLD}${GREEN}Browser setup successful!${RESET}"
  echo -e "Your browser is now properly configured for DirHunter AI."
else
  echo -e "\n${BOLD}${RED}Browser setup failed.${RESET}"
  echo -e "Additional troubleshooting may be needed."
  
  # Additional diagnostic
  echo -e "\n${BOLD}Running diagnostic commands...${RESET}"
  echo -e "\n${YELLOW}Chromium binary:${RESET}"
  ls -la /usr/local/bin/chrome
  echo -e "\n${YELLOW}ChromeDriver binary:${RESET}"
  ls -la /usr/local/bin/chromedriver
  echo -e "\n${YELLOW}Chromium snap details:${RESET}"
  snap list | grep chromium
  
  echo -e "\n${BOLD}Recommended manual steps:${RESET}"
  echo "1. Try running: sudo snap connect chromium:browser-support"
  echo "2. Try setting snap permissions: sudo snap connect chromium:process-control"
  echo "3. For more relaxed confinement: sudo snap install chromium --classic --devmode"
fi

# Final instructions
echo -e "\n${BOLD}Next Steps:${RESET}"
echo "1. Run your DirHunter AI script with the virtual environment"
echo "2. If issues persist, try the manual steps shown above" 