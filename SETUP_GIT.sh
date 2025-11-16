#!/bin/bash
# Initialize Git repository and prepare for GitHub

echo "==========================================="
echo "  Git Repository Setup"
echo "==========================================="
echo ""

cd "$(dirname "$0")"

# Initialize git
if [ ! -d ".git" ]; then
    echo "[*] Initializing Git repository..."
    git init
    echo "✓ Git initialized"
else
    echo "[*] Git already initialized"
fi

# Add all files
echo ""
echo "[*] Staging files..."
git add .

# Show what will be committed
echo ""
echo "[*] Files to be committed:"
git status --short | head -20
echo ""
TOTAL=$(git status --short | wc -l)
echo "Total files: $TOTAL"

# First commit
echo ""
echo "[*] Creating initial commit..."
git commit -m "Initial commit: WoW 3.3.5a security research

- Complete security assessment documentation
- CryptoLogger DLL source code
- Analysis scripts (Python)
- Diagrams and visualizations
- Research methodology and lessons learned

Educational security research conducted ethically with
responsible disclosure to affected party.

Total research time: 28 hours
Tools used: Ghidra, Radare2, x32dbg, MinGW, Python

For details see README.md"

echo ""
echo "✓ Initial commit created"

echo ""
echo "==========================================="
echo "  Next Steps:"
echo "==========================================="
echo ""
echo "1. Create GitHub repository:"
echo "   - Go to https://github.com/new"
echo "   - Name: wow-335a-security-research"
echo "   - Description: Educational security assessment of WoW 3.3.5a client"
echo "   - Visibility: Public or Private (your choice)"
echo "   - Do NOT initialize with README (we have one)"
echo ""
echo "2. Add remote and push:"
echo "   git remote add origin git@github.com:YOUR_USERNAME/wow-335a-security-research.git"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "3. Create release for CryptoLogger.dll:"
echo "   - Go to Releases → Create new release"
echo "   - Tag: v1.0.0"
echo "   - Title: CryptoLogger v1.0.0"
echo "   - Description: See RELEASE_NOTES.md"
echo "   - Upload: CryptoLogger.dll (compile first!)"
echo ""
echo "4. Update README with:"
echo "   - Your GitHub username in URLs"
echo "   - Your contact info"
echo "   - CryptoLogger SHA256 checksum"
echo ""
echo "==========================================="
