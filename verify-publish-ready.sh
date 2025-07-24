#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Verifying dcrypt crates are ready for publishing ===${NC}"
echo ""

# All crates including tests
CRATES=(
    "."  # Root crate
    "crates/internal"
    "crates/params"
    "crates/api"
    "crates/common"
    "crates/algorithms"
    "crates/symmetric"
    "crates/kem"
    "crates/sign"
    "crates/pke"
    "crates/utils"
    "crates/hybrid"
    "tests"
)

all_good=true
missing_items=()

# Function to check if a crate should be published
should_publish_crate() {
    local cargo_toml=$1
    
    # Check if there's a [package.metadata.release] section
    if grep -q "^\[package\.metadata\.release\]" "$cargo_toml"; then
        # Extract the content of [package.metadata.release] section
        # This gets all lines from [package.metadata.release] until the next section or EOF
        local section_content=$(awk '/^\[package\.metadata\.release\]/{flag=1; next} /^\[/{flag=0} flag' "$cargo_toml")
        
        # Check if publish = false in this section
        if echo "$section_content" | grep -q "publish = false"; then
            return 1  # Should NOT publish
        fi
    fi
    
    return 0  # Should publish (default)
}

# Function to check a crate
check_crate() {
    local crate_path=$1
    local crate_name
    
    if [ "$crate_path" = "." ]; then
        crate_name="dcrypt"
    else
        crate_name=$(basename "$crate_path")
        if [ "$crate_name" = "tests" ]; then
            crate_name="tests"  # Or change to dcrypt-tests as suggested
        else
            crate_name="dcrypt-$crate_name"
        fi
    fi
    
    echo -e "\n${YELLOW}Checking $crate_name ($crate_path)...${NC}"
    
    local cargo_toml="$crate_path/Cargo.toml"
    
    # Check required fields
    local has_error=false
    
    # Check name
    if ! grep -q "^name = \"$crate_name\"" "$cargo_toml"; then
        echo -e "${RED}  ✗ Missing or incorrect crate name${NC}"
        has_error=true
    else
        echo -e "${GREEN}  ✓ name${NC}"
    fi
    
    # Check version (should use workspace)
    if ! grep -q "version.workspace = true" "$cargo_toml" && ! grep -q "version = \"0.9.0-beta.1\"" "$cargo_toml"; then
        echo -e "${RED}  ✗ Version not using workspace${NC}"
        has_error=true
    else
        echo -e "${GREEN}  ✓ version${NC}"
    fi
    
    # Check description
    if ! grep -q "description = " "$cargo_toml" && ! grep -q "description.workspace = true" "$cargo_toml"; then
        echo -e "${RED}  ✗ Missing description${NC}"
        missing_items+=("$crate_name needs description")
        has_error=true
    else
        echo -e "${GREEN}  ✓ description${NC}"
    fi
    
    # Check license
    if ! grep -q "license" "$cargo_toml"; then
        echo -e "${RED}  ✗ Missing license${NC}"
        missing_items+=("$crate_name needs license")
        has_error=true
    else
        echo -e "${GREEN}  ✓ license${NC}"
    fi
    
    # Check repository
    if ! grep -q "repository" "$cargo_toml"; then
        echo -e "${RED}  ✗ Missing repository${NC}"
        missing_items+=("$crate_name needs repository")
        has_error=true
    else
        echo -e "${GREEN}  ✓ repository${NC}"
    fi
    
    # Check publish settings properly
    if should_publish_crate "$cargo_toml"; then
        echo -e "${GREEN}  ✓ will be published${NC}"
    else
        echo -e "${YELLOW}  ⚠ publish = false in [package.metadata.release] (will skip)${NC}"
    fi
    
    # Check for README
    if [ ! -f "$crate_path/README.md" ]; then
        echo -e "${YELLOW}  ⚠ No README.md (optional but recommended)${NC}"
    fi
    
    # Check internal dependencies use exact versions
    if grep -E "dcrypt-[a-z]+ = \{ .* version = \"[^=]" "$cargo_toml" | grep -v "version = \"="; then
        echo -e "${YELLOW}  ⚠ Some internal dependencies don't use exact versions${NC}"
    fi
    
    if [ "$has_error" = true ]; then
        all_good=false
    fi
}

# Check each crate
for crate in "${CRATES[@]}"; do
    check_crate "$crate"
done

echo -e "\n${BLUE}=== Summary ===${NC}"

if [ "$all_good" = true ]; then
    echo -e "${GREEN}All crates are ready for publishing!${NC}"
else
    echo -e "${RED}Some issues need to be fixed:${NC}"
    for item in "${missing_items[@]}"; do
        echo "  - $item"
    done
fi

# Check cargo-release is installed
echo -e "\n${BLUE}=== Checking tools ===${NC}"
if command -v cargo-release &> /dev/null; then
    echo -e "${GREEN}✓ cargo-release is installed${NC}"
else
    echo -e "${RED}✗ cargo-release is not installed${NC}"
    echo "  Install with: cargo install cargo-release"
fi

# Check if logged into crates.io
echo -e "\n${BLUE}=== Checking crates.io authentication ===${NC}"
if [ -f "$HOME/.cargo/credentials.toml" ] && grep -q "token" "$HOME/.cargo/credentials.toml"; then
    echo -e "${GREEN}✓ Logged into crates.io${NC}"
else
    echo -e "${RED}✗ Not logged into crates.io${NC}"
    echo "  Login with: cargo login <your-token>"
fi

# Check workspace release settings
echo -e "\n${BLUE}=== Workspace release configuration ===${NC}"
if grep -q "^\[workspace\.metadata\.release\]" Cargo.toml; then
    # Extract the workspace.metadata.release section
    section=$(awk '/^\[workspace\.metadata\.release\]/{flag=1; next} /^\[/{flag=0} flag' Cargo.toml)
    
    if echo "$section" | grep -q "publish = false"; then
        echo -e "${GREEN}✓ Workspace has publish = false (two-step release process)${NC}"
        echo "  This means:"
        echo "  - cargo release version X.Y.Z --execute  (updates versions)"
        echo "  - cargo release publish --execute       (publishes crates)"
    elif echo "$section" | grep -q "publish = true"; then
        echo -e "${YELLOW}⚠ Workspace has publish = true (automatic publishing)${NC}"
        echo "  This means cargo release will publish immediately after version bump"
    else
        echo -e "${CYAN}ℹ Workspace publish not explicitly set (defaults to true)${NC}"
        echo "  This means cargo release will publish immediately after version bump"
    fi
else
    echo -e "${YELLOW}⚠ No [workspace.metadata.release] section found${NC}"
    echo "  cargo-release will use defaults"
fi

# Show current version
echo -e "\n${BLUE}=== Current version ===${NC}"
current_version=$(grep "^version" Cargo.toml | grep -oE "[0-9]+\.[0-9]+\.[0-9]+-[a-z]+\.[0-9]+|[0-9]+\.[0-9]+\.[0-9]+" | head -1)
echo "Current version: $current_version"

echo -e "\n${BLUE}=== Next steps ===${NC}"
echo "1. Fix any issues identified above"
echo "2. Run: cargo test --all"
echo "3. Update version: cargo release version <new-version> --execute"
echo "4. Review changes: git diff"
echo "5. Publish: cargo release publish --execute"
echo "6. Create and push git tag manually"
echo ""
echo "The two-step process (version then publish) is intentional for safety!"