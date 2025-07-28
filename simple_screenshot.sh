#!/bin/bash
# Simple Screenshot Script - Completely standalone
# Usage: ./simple_screenshot.sh URL OUTPUT_FILE

# Text formatting
GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

# Check parameters
if [ $# -lt 2 ]; then
  echo "Usage: $0 <url> <output_path>"
  echo "Example: $0 https://example.com example.png"
  exit 1
fi

URL=$1
OUTPUT_PATH=$2

# Create directory if it doesn't exist
mkdir -p "$(dirname "$OUTPUT_PATH")"

# Find a free display number
DISPLAY_NUM=99
while [ -e "/tmp/.X${DISPLAY_NUM}-lock" ]; do
  DISPLAY_NUM=$((DISPLAY_NUM + 1))
done

echo "Using display :${DISPLAY_NUM}"

# Start Xvfb with the free display
Xvfb ":${DISPLAY_NUM}" -screen 0 1280x1024x24 -ac &
XVFB_PID=$!

# Wait for Xvfb to start
sleep 1

# Set the display variable
export DISPLAY=":${DISPLAY_NUM}"

# Ignore dbus errors
export DBUS_SESSION_BUS_ADDRESS="unix:path=/dev/null"

echo "Taking screenshot of $URL"
echo "Saving to $OUTPUT_PATH"

# Run Chrome/Chromium in headless mode to take screenshot
if [ -x "/usr/bin/google-chrome-stable" ]; then
  /usr/bin/google-chrome-stable --headless=new --disable-gpu --no-sandbox \
    --disable-dev-shm-usage --disable-software-rasterizer \
    --disable-background-networking --disable-default-apps \
    --disable-extensions --disable-sync --disable-translate \
    --hide-scrollbars --metrics-recording-only --mute-audio \
    --no-first-run --safebrowsing-disable-auto-update \
    --screenshot="$OUTPUT_PATH" "$URL"
  STATUS=$?
elif [ -x "/usr/bin/chromium-browser" ]; then
  /usr/bin/chromium-browser --headless=new --disable-gpu --no-sandbox \
    --disable-dev-shm-usage --disable-software-rasterizer \
    --disable-background-networking --disable-default-apps \
    --disable-extensions --disable-sync --disable-translate \
    --hide-scrollbars --metrics-recording-only --mute-audio \
    --no-first-run --safebrowsing-disable-auto-update \
    --screenshot="$OUTPUT_PATH" "$URL"
  STATUS=$?
else
  echo "${RED}No Chrome/Chromium browser found${RESET}"
  STATUS=1
fi

# Save page content to a text file
if [ $STATUS -eq 0 ]; then
  TEXT_PATH="${OUTPUT_PATH%.*}.txt"
  echo "Saving page content to $TEXT_PATH"
  
  if [ -x "/usr/bin/google-chrome-stable" ]; then
    /usr/bin/google-chrome-stable --headless=new --disable-gpu --no-sandbox \
      --disable-extensions --disable-dev-shm-usage \
      --dump-dom "$URL" > "$TEXT_PATH" 2>/dev/null
  elif [ -x "/usr/bin/chromium-browser" ]; then
    /usr/bin/chromium-browser --headless=new --disable-gpu --no-sandbox \
      --disable-extensions --disable-dev-shm-usage \
      --dump-dom "$URL" > "$TEXT_PATH" 2>/dev/null
  fi
fi

# Kill Xvfb
kill $XVFB_PID 2>/dev/null || true

# Check if screenshot was created
if [ -f "$OUTPUT_PATH" ] && [ $STATUS -eq 0 ]; then
  echo -e "${GREEN}✓${RESET} Screenshot saved to $OUTPUT_PATH"
  echo -e "${GREEN}✓${RESET} Page content saved to ${OUTPUT_PATH%.*}.txt"
  exit 0
else
  echo -e "${RED}✗${RESET} Failed to take screenshot"
  # Create a basic error image with text
  # If ImageMagick is available
  if command -v convert >/dev/null; then
    convert -size 800x600 xc:white -fill black -pointsize 20 \
      -draw "text 50,100 'Error loading $URL'" \
      -draw "text 50,150 'Screenshot failed'" "$OUTPUT_PATH"
    echo -e "${GREEN}✓${RESET} Created error placeholder image"
    
    # Create simple text file
    echo "Error loading $URL" > "${OUTPUT_PATH%.*}.txt"
    echo "Screenshot failed at $(date)" >> "${OUTPUT_PATH%.*}.txt"
    echo -e "${GREEN}✓${RESET} Created error placeholder text file"
    exit 0
  else
    echo -e "${RED}✗${RESET} Could not create placeholder image (ImageMagick not installed)"
    exit 1
  fi
fi 