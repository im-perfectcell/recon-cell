#!/bin/bash
# Recon Suite Installer
echo "[*] Setting up Recon Suite v4.7"

# Create installation directory
INSTALL_DIR="$HOME/.recon-suite"
echo "[+] Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy files
echo "[*] Copying necessary files..."
cp recon.py "$INSTALL_DIR/recon"
cp requirements.txt "$INSTALL_DIR/"

# Create virtual environment
echo "[*] Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

# Install dependencies
echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r "$INSTALL_DIR/requirements.txt"

# Make executable
chmod +x "$INSTALL_DIR/recon"

# Create symlink
echo "[*] Creating global symlink (requires sudo)..."
sudo ln -sf "$INSTALL_DIR/recon" /usr/local/bin/recon

# System dependencies
echo "[*] Checking for system dependencies:"
dependencies=("nmap" "masscan" "chromedriver")
for dep in "${dependencies[@]}"; do
    if ! command -v $dep &> /dev/null; then
        echo "  [!] $dep not found - please install manually:"
        case $dep in
            "nmap")
                echo "      Debian/Ubuntu: sudo apt install nmap"
                ;;
            "masscan")
                echo "      Debian/Ubuntu: sudo apt install masscan"
                ;;
            "chromedriver")
                echo "      Download: https://chromedriver.chromium.org/downloads"
                ;;
        esac
    else
        echo "  [✓] $dep installed"
    fi
done

echo -e "\n[+] Installation complete!"
echo "  Run with: recon [options]"
echo "  Example: recon -d example.com --vuln-scan"
