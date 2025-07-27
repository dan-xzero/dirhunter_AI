#!/bin/bash
# Browser Fix Script for SSH Servers
# This script fixes common issues with Chrome/Firefox in headless environments

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
RESET="\033[0m"

echo -e "${BOLD}=== Browser Fix for SSH Servers ===${RESET}"
echo "This script will attempt to fix browser issues for Selenium."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}Please run as root (sudo).${RESET}"
  exit 1
fi

# Function to install packages
install_package() {
  echo -e "${BOLD}Installing $1...${RESET}"
  apt-get install -y "$1" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo -e "  ${GREEN}✓${RESET} $1 installed"
  else
    echo -e "  ${RED}✗${RESET} Failed to install $1"
  fi
}

# Update package lists
echo -e "\n${BOLD}Updating package lists...${RESET}"
apt-get update > /dev/null 2>&1

# Install Chromium and Firefox
echo -e "\n${BOLD}Installing browsers...${RESET}"
install_package "chromium-browser"
install_package "firefox-esr"

# Install drivers
echo -e "\n${BOLD}Installing WebDrivers...${RESET}"

# ChromeDriver
echo "Checking for Chromium version..."
CHROMIUM_VERSION=$(chromium-browser --version 2>/dev/null | awk '{print $2}' | cut -d. -f1)
if [ -z "$CHROMIUM_VERSION" ]; then
  CHROMIUM_VERSION=$(chromium-browser --product-version 2>/dev/null | cut -d. -f1)
fi

if [ -n "$CHROMIUM_VERSION" ]; then
  echo "Detected Chromium version: $CHROMIUM_VERSION"
  echo "Downloading matching ChromeDriver..."
  
  TEMP_DIR=$(mktemp -d)
  wget -q "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_${CHROMIUM_VERSION}" -O "$TEMP_DIR/version.txt"
  CHROMEDRIVER_VERSION=$(cat "$TEMP_DIR/version.txt")
  
  if [ -n "$CHROMEDRIVER_VERSION" ]; then
    echo "Found ChromeDriver version: $CHROMEDRIVER_VERSION"
    wget -q "https://chromedriver.storage.googleapis.com/${CHROMEDRIVER_VERSION}/chromedriver_linux64.zip" -O "$TEMP_DIR/chromedriver.zip"
    
    if [ -f "$TEMP_DIR/chromedriver.zip" ]; then
      apt-get install -y unzip > /dev/null 2>&1
      unzip -q "$TEMP_DIR/chromedriver.zip" -d "$TEMP_DIR"
      chmod +x "$TEMP_DIR/chromedriver"
      mv "$TEMP_DIR/chromedriver" /usr/local/bin/
      echo -e "  ${GREEN}✓${RESET} ChromeDriver installed to /usr/local/bin/chromedriver"
    else
      echo -e "  ${RED}✗${RESET} Failed to download ChromeDriver"
    fi
  else
    echo -e "  ${RED}✗${RESET} Failed to determine ChromeDriver version"
  fi
  
  # Clean up
  rm -rf "$TEMP_DIR"
else
  echo -e "  ${RED}✗${RESET} Failed to determine Chromium version"
fi

# GeckoDriver
echo "Installing GeckoDriver..."
TEMP_DIR=$(mktemp -d)
GECKODRIVER_VERSION="v0.34.0"  # Use a recent stable version
GECKODRIVER_URL="https://github.com/mozilla/geckodriver/releases/download/${GECKODRIVER_VERSION}/geckodriver-${GECKODRIVER_VERSION}-linux64.tar.gz"

wget -q "$GECKODRIVER_URL" -O "$TEMP_DIR/geckodriver.tar.gz"
if [ -f "$TEMP_DIR/geckodriver.tar.gz" ]; then
  tar -xzf "$TEMP_DIR/geckodriver.tar.gz" -C "$TEMP_DIR"
  chmod +x "$TEMP_DIR/geckodriver"
  mv "$TEMP_DIR/geckodriver" /usr/local/bin/
  echo -e "  ${GREEN}✓${RESET} GeckoDriver installed to /usr/local/bin/geckodriver"
else
  echo -e "  ${RED}✗${RESET} Failed to download GeckoDriver"
fi

# Clean up
rm -rf "$TEMP_DIR"

# Install dependencies
echo -e "\n${BOLD}Installing browser dependencies...${RESET}"

# Chrome dependencies
chrome_deps=(
  "libnss3"
  "libgbm1"
  "libasound2"
  "libatk1.0-0"
  "libatk-bridge2.0-0"
  "libcups2"
  "libdrm2"
  "libxcomposite1"
  "libxdamage1"
  "libxfixes3"
  "libxrandr2"
  "libglib2.0-0"
  "libpango-1.0-0"
  "libcairo2"
  "libnspr4"
  "libnss3"
)

for pkg in "${chrome_deps[@]}"; do
  install_package "$pkg"
done

# Firefox dependencies
firefox_deps=(
  "libgtk-3-0"
  "libdbus-glib-1-2"
  "libxt6"
  "xvfb"
)

for pkg in "${firefox_deps[@]}"; do
  install_package "$pkg"
done

# Install Selenium if not already installed
echo -e "\n${BOLD}Setting up Python environment...${RESET}"
apt-get install -y python3-pip > /dev/null 2>&1
pip3 install --upgrade selenium > /dev/null 2>&1

echo -e "  ${GREEN}✓${RESET} Selenium installed/updated"

# Fix permissions in temporary directories
echo -e "\n${BOLD}Fixing permissions...${RESET}"
chmod -R 1777 /tmp
echo -e "  ${GREEN}✓${RESET} /tmp permissions fixed"

# Create test script
echo -e "\n${BOLD}Creating test script...${RESET}"

cat > /tmp/test_browser.py << 'EOF'
#!/usr/bin/env python3
import sys
import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService

def test_chrome():
    print("Testing Chrome...")
    
    chrome_options = ChromeOptions()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    
    try:
        service = ChromeService(executable_path="/usr/local/bin/chromedriver")
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        print("Opening example.com...")
        driver.get("https://www.example.com")
        print(f"Page title: {driver.title}")
        
        # Take screenshot
        driver.save_screenshot("chrome_test.png")
        print(f"Screenshot saved to {os.path.abspath('chrome_test.png')}")
        
        driver.quit()
        print("Chrome test: SUCCESS ✅")
        return True
    except Exception as e:
        print(f"Chrome test failed: {e}")
        print("Chrome test: FAILED ❌")
        return False

def test_firefox():
    print("Testing Firefox...")
    
    firefox_options = FirefoxOptions()
    firefox_options.add_argument("--headless")
    
    try:
        service = FirefoxService(executable_path="/usr/local/bin/geckodriver")
        driver = webdriver.Firefox(service=service, options=firefox_options)
        
        print("Opening example.com...")
        driver.get("https://www.example.com")
        print(f"Page title: {driver.title}")
        
        # Take screenshot
        driver.save_screenshot("firefox_test.png")
        print(f"Screenshot saved to {os.path.abspath('firefox_test.png')}")
        
        driver.quit()
        print("Firefox test: SUCCESS ✅")
        return True
    except Exception as e:
        print(f"Firefox test failed: {e}")
        print("Firefox test: FAILED ❌")
        return False

if __name__ == "__main__":
    print("Testing browsers with Selenium...")
    
    chrome_ok = test_chrome()
    print("")
    firefox_ok = test_firefox()
    
    print("\nResults:")
    print(f"Chrome: {'✅ Working' if chrome_ok else '❌ Not working'}")
    print(f"Firefox: {'✅ Working' if firefox_ok else '❌ Not working'}")
    
    if chrome_ok or firefox_ok:
        print("\nBrowser setup successful! At least one browser is working.")
        sys.exit(0)
    else:
        print("\nBrowser setup failed! Neither browser is working.")
        sys.exit(1)
EOF

chmod +x /tmp/test_browser.py
echo -e "  ${GREEN}✓${RESET} Test script created at /tmp/test_browser.py"

echo -e "\n${BOLD}Running test script to verify setup...${RESET}"
python3 /tmp/test_browser.py

echo -e "\n${BOLD}Setup complete!${RESET}"
echo -e "If the test was successful, your browser setup should now work with DirHunter AI."
echo -e "If you continue to have issues, check the error messages above." 