#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# License header checker and fixer script
# Usage: ./scripts/check-license-headers.sh [--fix] [--check-only]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Expected license header
read -r -d '' EXPECTED_HEADER << 'EOF' || true
// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
EOF

# Parse command line arguments
FIX_MODE=false
CHECK_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --fix)
            FIX_MODE=true
            shift
            ;;
        --check-only)
            CHECK_ONLY=true
            shift
            ;;
        *)
            echo "Usage: $0 [--fix] [--check-only]"
            echo "  --fix        Automatically add missing license headers"
            echo "  --check-only Only check headers, don't modify files (exit code 1 if issues found)"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}Checking license headers in source files...${NC}"
echo ""

# Use git ls-files to find tracked files with specified extensions
if [[ -n "${TEST_FILES:-}" ]]; then
    # Use test files if provided (for testing)
    FILES="$TEST_FILES"
else
    # Find all tracked files with the specified extensions
    FILES=$(git ls-files '*.js' '*.jsx' '*.nr' '*.rs' '*.sol' '*.ts' '*.tsx' 2>/dev/null | sort)
fi

if [[ -z "$FILES" ]]; then
    echo -e "${YELLOW}No source files found.${NC}"
    exit 0
fi

MISSING_FILES=()
INVALID_FILES=()
FIXED_FILES=()



# Function to check if a file has the correct license header
check_license_header() {
    local file="$1"
    local first_lines
    
    # Read first 20 lines to catch SPDX headers that might not be at the very top
    first_lines=$(head -n 20 "$file" 2>/dev/null || echo "")
    
    # Check if the file starts with the expected header
    local expected_line1="// SPDX-License-Identifier: LGPL-3.0-only"
    local expected_line2="//"
    local expected_line3="// This file is provided WITHOUT ANY WARRANTY;"
    
    local actual_line1=$(echo "$first_lines" | sed -n '1p')
    local actual_line2=$(echo "$first_lines" | sed -n '2p')
    local actual_line3=$(echo "$first_lines" | sed -n '3p')
    
    if [[ "$actual_line1" == "$expected_line1" ]] && \
       [[ "$actual_line2" == "$expected_line2" ]] && \
       [[ "$actual_line3" == "$expected_line3" ]]; then
        return 0  # Header is correct
    elif echo "$first_lines" | grep -q "SPDX-License-Identifier:"; then
        return 2  # Has SPDX but wrong format/license
    else
        return 1  # Missing header entirely
    fi
}

# Function to add license header to a file
add_license_header() {
    local file="$1"
    local temp_file
    temp_file=$(mktemp)
    
    # Add the header followed by an empty line, then the original content
    {
        echo "$EXPECTED_HEADER"
        echo ""
        cat "$file"
    } > "$temp_file"
    
    # Replace the original file
    mv "$temp_file" "$file"
    echo -e "${GREEN}  ✅ Added license header${NC}"
    FIXED_FILES+=("$file")
}

# Process each file
while IFS= read -r file; do
    # Skip empty lines
    [[ -n "$file" ]] || continue
    # `git ls-files` includes tracked files that are deleted in the worktree.
    [[ -f "$file" ]] || continue
    
    echo -n "Checking: $file"
    
    # Call the function and capture result safely
    set +e
    check_license_header "$file"
    result=$?
    set -e
    
    case $result in
        0)
            echo -e " ${GREEN}✅${NC}"
            ;;
        1)
            echo -e " ${RED}❌ Missing license header${NC}"
            MISSING_FILES+=("$file")
            if [[ "$FIX_MODE" == true ]]; then
                add_license_header "$file"
            fi
            ;;
        2)
            echo -e " ${YELLOW}⚠️  Has different SPDX license${NC}"
            INVALID_FILES+=("$file")
            ;;
        *)
            echo -e " ${RED}❓ Error checking file${NC}"
            ;;
    esac
done <<< "$FILES"

echo ""

# Summary
total_issues=${#MISSING_FILES[@]}

if [[ $total_issues -eq 0 ]]; then
    if [[ ${#INVALID_FILES[@]} -gt 0 ]]; then
        echo -e "${GREEN}✅ All files have license headers!${NC}"
        echo -e "${BLUE}Note: Some files use different SPDX licenses (shown above)${NC}"
    else
        echo -e "${GREEN}✅ All files have correct license headers!${NC}"
    fi
    exit 0
else
    echo -e "${RED}📋 Summary:${NC}"
    
    if [[ ${#MISSING_FILES[@]} -gt 0 ]]; then
        echo -e "${RED}Files missing license headers: ${#MISSING_FILES[@]}${NC}"
        if [[ "$FIX_MODE" == false ]]; then
            for file in "${MISSING_FILES[@]}"; do
                echo "  - $file"
            done
        fi
    fi
    
    if [[ ${#INVALID_FILES[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Files with different SPDX licenses: ${#INVALID_FILES[@]}${NC}"
        for file in "${INVALID_FILES[@]}"; do
            echo "  - $file"
        done
        echo -e "${YELLOW}Note: These files have existing SPDX headers with different licenses${NC}"
        echo -e "${YELLOW}Please verify if they should use LGPL-3.0-only or keep their current license${NC}"
    fi
    
    if [[ ${#FIXED_FILES[@]} -gt 0 ]]; then
        echo -e "${GREEN}Files fixed: ${#FIXED_FILES[@]}${NC}"
        for file in "${FIXED_FILES[@]}"; do
            echo "  - $file"
        done
    fi
    
    echo ""
    echo -e "${BLUE}Expected license header format:${NC}"
    echo "$EXPECTED_HEADER"
    echo ""
    
    if [[ "$FIX_MODE" == true ]]; then
        if [[ ${#INVALID_FILES[@]} -gt 0 ]]; then
            echo -e "${YELLOW}Note: Some files have different SPDX licenses and were not modified.${NC}"
            echo -e "${YELLOW}This is informational only - no action needed unless you want to change their licenses.${NC}"
        fi
        if [[ $total_issues -eq 0 ]]; then
            echo -e "${GREEN}All missing headers have been fixed!${NC}"
            exit 0
        fi
    elif [[ "$CHECK_ONLY" == true ]]; then
        if [[ $total_issues -gt 0 ]]; then
            exit 1
        else
            exit 0
        fi
    else
        echo -e "${BLUE}Run with --fix to automatically add missing headers${NC}"
        echo -e "${BLUE}Run with --check-only for CI/CD usage (exits with code 1 if issues found)${NC}"
        if [[ ${#MISSING_FILES[@]} -gt 0 ]]; then
            exit 1
        else
            exit 0
        fi
    fi
fi
