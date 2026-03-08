#!/bin/bash
# verify_installation.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

ERRORS=0

echo "=== Ghost Installation Verification ==="
echo ""

# Check 1: DIR exists
if [[ -d /usr/local/lib/ghost ]]; then
    echo -e "${GREEN}✓${NC} Installation directory exists"
else
    echo -e "${RED}✗${NC} Installation directory missing"
    ((ERRORS++))
fi

# Check 2: Main script
if [[ -f /usr/local/bin/ghost ]]; then
    echo -e "${GREEN}✓${NC} Ghost executable found"
    
    DIR_VAR=$(grep "^DIR=" /usr/local/bin/ghost | cut -d'"' -f2)
    if [[ "$DIR_VAR" == "/usr/local/lib/ghost" ]]; then
        echo -e "${GREEN}✓${NC} DIR variable correct: $DIR_VAR"
    else
        echo -e "${RED}✗${NC} DIR variable wrong: $DIR_VAR"
        ((ERRORS++))
    fi
else
    echo -e "${RED}✗${NC} Ghost executable missing"
    ((ERRORS++))
fi

# Check 3: Required files
REQUIRED=(
    "/usr/local/lib/ghost/lib/apply_seccomp"
    "/usr/local/lib/ghost/lib/apply_landlock"
    "/usr/local/lib/ghost/lib/caps.sh"
    "/usr/local/lib/ghost/lib/setup.sh"
    "/usr/local/lib/ghost/lib/tor.sh"
)

for file in "${REQUIRED[@]}"; do
    if [[ -f "$file" ]] && [[ -x "$file" ]]; then
        echo -e "${GREEN}✓${NC} $(basename $file) OK"
    elif [[ -f "$file" ]]; then
        echo -e "${RED}✗${NC} $(basename $file) not executable"
        ((ERRORS++))
    else
        echo -e "${RED}✗${NC} $(basename $file) MISSING"
        ((ERRORS++))
    fi
done

echo ""
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}Installation OK - All checks passed${NC}"
    exit 0
else
    echo -e "${RED}Installation has $ERRORS errors${NC}"
    echo "Run: sudo bash install.sh"
    exit 1
fi
