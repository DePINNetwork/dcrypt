#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default values
VERSION=""
DRY_RUN=true
SKIP_TESTS=false
SKIP_CHECKS=false
CURRENT_VERSION="0.9.0-beta.1"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --execute)
            DRY_RUN=false
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --skip-checks)
            SKIP_CHECKS=true
            shift
            ;;
        --help)
            echo "Usage: $0 --version VERSION [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --version VERSION   Version to release (e.g., 0.9.0-beta.2)"
            echo "  --execute          Actually perform the release (default: dry-run)"
            echo "  --skip-tests       Skip running tests (use if already verified)"
            echo "  --skip-checks      Skip format/clippy checks (use if already verified)"
            echo ""
            echo "Examples:"
            echo "  $0 --version 0.9.0-beta.2                    # Full dry run"
            echo "  $0 --version 0.9.0-beta.2 --skip-tests      # Skip tests (faster)"
            echo "  $0 --version 0.9.0 --execute                # Release stable 0.9.0"
            echo ""
            echo "Note: Skipping tests is only recommended if you've already"
            echo "      verified all tests pass with 'cargo test --all'"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage"
            exit 1
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo -e "${RED}Error: --version is required${NC}"
    echo "Use --help for usage"
    exit 1
fi

echo -e "${BLUE}════════════════════════════════════════════════${NC}"
echo -e "${BLUE}     dcrypt Release Process v${VERSION}${NC}"
echo -e "${BLUE}════════════════════════════════════════════════${NC}"
echo -e "Current version: ${YELLOW}${CURRENT_VERSION}${NC}"
echo -e "New version: ${GREEN}${VERSION}${NC}"
echo -e "Mode: ${YELLOW}$([ "$DRY_RUN" = true ] && echo "DRY RUN" || echo "EXECUTE")${NC}"
if [ "$SKIP_TESTS" = true ] || [ "$SKIP_CHECKS" = true ]; then
    echo -e "Flags:"
    [ "$SKIP_TESTS" = true ] && echo -e "  ${YELLOW}--skip-tests${NC} (tests will not be run)"
    [ "$SKIP_CHECKS" = true ] && echo -e "  ${YELLOW}--skip-checks${NC} (fmt/clippy will not be run)"
fi
echo ""

# Function to run a command with nice output
run_step() {
    local step_name=$1
    shift
    echo -ne "${CYAN}▶ ${step_name}...${NC} "
    if "$@" > /tmp/release_output.log 2>&1; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        echo -e "${RED}Error output:${NC}"
        cat /tmp/release_output.log
        return 1
    fi
}

# Pre-flight checks
echo -e "${BLUE}Pre-flight checks${NC}"
echo -e "${BLUE}─────────────────${NC}"

# Check git status
run_step "Checking git status" bash -c '
    if [ -n "$(git status --porcelain)" ]; then
        echo "Uncommitted changes found:" >&2
        git status --short >&2
        exit 1
    fi
'

# Check branch
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ] && [ "$BRANCH" != "master" ]; then
    echo -e "${YELLOW}Warning: Not on main/master branch (currently on $BRANCH)${NC}"
    echo -n "Continue anyway? (y/N): "
    read -r response
    if [ "$response" != "y" ]; then
        exit 1
    fi
fi

# Pull latest
run_step "Pulling latest changes" git pull origin "$BRANCH"

# Run tests
if [ "$SKIP_TESTS" = false ]; then
    echo ""
    echo -e "${BLUE}Running tests${NC}"
    echo -e "${BLUE}─────────────${NC}"
    run_step "Running unit tests" cargo test --all
    run_step "Running doc tests" cargo test --all --doc
    
    if [ "$SKIP_CHECKS" = false ]; then
        run_step "Checking formatting" cargo fmt --all -- --check
        run_step "Running clippy" cargo clippy --all-targets --all-features -- -D warnings
        run_step "Building documentation" cargo doc --workspace --no-deps
    else
        echo -e "${YELLOW}⚠ Skipping format/clippy checks${NC}"
    fi
else
    echo ""
    echo -e "${YELLOW}⚠ Skipping tests (--skip-tests flag used)${NC}"
    echo -e "${YELLOW}  Make sure you've already verified all tests pass!${NC}"
    if [ "$DRY_RUN" = false ]; then
        echo -ne "${RED}  Are you sure tests have passed? (y/N): ${NC}"
        read -r response
        if [ "$response" != "y" ]; then
            echo "Aborting release"
            exit 1
        fi
    fi
fi

# Verify publishing metadata
echo ""
echo -e "${BLUE}Verifying metadata${NC}"
echo -e "${BLUE}──────────────────${NC}"
run_step "Checking crate metadata" ./verify-publish-ready.sh

# Version update
echo ""
echo -e "${BLUE}Version update${NC}"
echo -e "${BLUE}──────────────${NC}"

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}Would update version to ${VERSION}${NC}"
    echo "Dry run - checking what would change:"
    cargo release version "$VERSION" --verbose
else
    echo -e "${CYAN}Updating version to ${VERSION}...${NC}"
    cargo release version "$VERSION" --execute
    
    # Show what changed
    echo -e "${GREEN}Version updated. Changes:${NC}"
    git diff --stat
fi

# Publish
echo ""
echo -e "${BLUE}Publishing to crates.io${NC}"
echo -e "${BLUE}───────────────────────${NC}"

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}Would publish the following crates in order:${NC}"
    echo "1. dcrypt-internal"
    echo "2. dcrypt-params"
    echo "3. dcrypt-api"
    echo "4. dcrypt-common"
    echo "5. dcrypt-algorithms"
    echo "6. dcrypt-symmetric, dcrypt-kem, dcrypt-sign, dcrypt-pke, dcrypt-utils"
    echo "7. dcrypt-hybrid"
    echo "8. tests"
    echo "9. dcrypt"
    echo ""
    echo "Checking publish readiness..."
    cargo release publish --verbose
else
    echo -e "${RED}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  WARNING: About to publish to crates.io!     ║${NC}"
    echo -e "${RED}║  This action cannot be undone!               ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Publishing version ${GREEN}${VERSION}${NC}"
    echo -n "Type 'publish' to confirm: "
    read -r confirm
    
    if [ "$confirm" != "publish" ]; then
        echo -e "${YELLOW}Publishing cancelled${NC}"
        exit 0
    fi
    
    echo -e "${CYAN}Publishing all crates...${NC}"
    cargo release publish --execute --verbose
    
    echo -e "${GREEN}✓ All crates published successfully!${NC}"
fi

# Post-publish steps
echo ""
echo -e "${BLUE}Post-publish steps${NC}"
echo -e "${BLUE}──────────────────${NC}"

if [ "$DRY_RUN" = false ]; then
    # Create git tag
    echo -e "${CYAN}Creating git tag v${VERSION}...${NC}"
    git tag -s "v${VERSION}" -m "Release version ${VERSION}"
    
    echo -e "${GREEN}✓ Tag created${NC}"
    
    # Final instructions
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}    Release ${VERSION} completed!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Push changes: git push origin $BRANCH"
    echo "2. Push tag: git push origin v${VERSION}"
    echo "3. Create GitHub release at:"
    echo "   https://github.com/DePINNetwork/dcrypt/releases/new"
    echo "4. Verify on crates.io:"
    echo "   https://crates.io/crates/dcrypt"
    echo "5. Test installation:"
    echo "   cargo add dcrypt@=${VERSION}"
    
    if [ "$SKIP_TESTS" = true ]; then
        echo ""
        echo -e "${YELLOW}⚠️  IMPORTANT: Tests were skipped during release!${NC}"
        echo "   Please verify the release works correctly."
    fi
else
    echo ""
    echo -e "${GREEN}Dry run completed successfully!${NC}"
    echo ""
    echo -e "${YELLOW}To perform the actual release:${NC}"
    if [ "$SKIP_TESTS" = true ]; then
        echo -e "  $0 --version ${VERSION} --execute --skip-tests"
        echo ""
        echo -e "${YELLOW}⚠️  WARNING: You're skipping tests. Only do this if you've${NC}"
        echo -e "${YELLOW}   already verified all tests pass with: cargo test --all${NC}"
    else
        echo -e "  $0 --version ${VERSION} --execute"
    fi
fi