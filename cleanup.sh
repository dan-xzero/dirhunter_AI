#!/bin/bash
# Cleanup script for DirHunter AI
# Removes unnecessary files after integrating screenshot functionality directly into the code

# Text formatting
GREEN="\033[0;32m"
RED="\033[0;31m"
BOLD="\033[1m"
RESET="\033[0m"

echo -e "${BOLD}Cleaning up unnecessary files...${RESET}"

# List of files to remove
FILES_TO_REMOVE=(
    # Fix scripts
    "browser_fix.sh"
    "direct_browser_fix.sh" 
    "snap_browser_fix.sh"
    "patch_dirhunter.sh"
    "simple_screenshot.sh"
    
    # Python scripts
    "browser_diagnostic.py"
    "chromium_wrapper.py"
    
    # Generated files
    "test_screenshot_direct.png"
    "test_screenshot_direct.txt"
)

# Remove each file
for file in "${FILES_TO_REMOVE[@]}"; do
    if [ -f "$file" ]; then
        rm -f "$file"
        echo -e "${GREEN}✓${RESET} Removed $file"
    else
        echo -e "${RED}×${RESET} File not found: $file"
    fi
done

# Clean up test screenshots directory
if [ -d "test_screenshots" ]; then
    rm -rf test_screenshots
    echo -e "${GREEN}✓${RESET} Removed test_screenshots directory"
fi

echo -e "\n${GREEN}✓${RESET} Cleanup complete!"
echo -e "\nAll unnecessary files have been removed."
echo -e "The screenshot functionality is now directly integrated into utils/screenshot.py"
echo -e "You can run the test script to verify it works: ${BOLD}./test_screenshot.py${RESET}" 