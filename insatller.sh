#!/bin/bash
# Recon Suite Installer v3.0 - Kali Linux Compatible
echo "[*] Setting up Recon Suite v4.7"

# Create installation directory
INSTALL_DIR="$HOME/.recon-suite"
BIN_DIR="$HOME/.local/bin"
echo "[+] Creating directories: $INSTALL_DIR and $BIN_DIR"
mkdir -p "$INSTALL_DIR" "$BIN_DIR"

# Copy files
echo "[*] Copying necessary files..."
cp recon.py "$INSTALL_DIR/recon"
cp requirements.txt "$INSTALL_DIR/"

# Install system dependencies
echo -e "\n[*] Installing system dependencies..."
if command -v apt &> /dev/null; then
    sudo apt update
    sudo apt install -y libxml2-dev libxslt-dev python3-dev
    echo "[+] Installed libxml2 and libxslt development packages"
elif command -v yum &> /dev/null; then
    sudo yum install -y libxml2-devel libxslt-devel python3-devel
    echo "[+] Installed libxml2 and libxslt development packages"
elif command -v dnf &> /dev/null; then
    sudo dnf install -y libxml2-devel libxslt-devel python3-devel
    echo "[+] Installed libxml2 and libxslt development packages"
elif command -v pacman &> /dev/null; then
    sudo pacman -Syu --noconfirm libxml2 libxslt python
    echo "[+] Installed libxml2 and libxslt packages"
else
    echo "[!] Couldn't install system dependencies automatically"
    echo "    Please install libxml2 and libxslt development packages manually"
    echo "    Debian/Ubuntu/Kali: sudo apt install libxml2-dev libxslt-dev python3-dev"
    echo "    Red Hat/CentOS: sudo yum install libxml2-devel libxslt-devel python3-devel"
    echo "    Fedora: sudo dnf install libxml2-devel libxslt-devel python3-devel"
    echo "    Arch: sudo pacman -S libxml2 libxslt python"
fi

# Install Python dependencies
echo -e "\n[*] Installing Python dependencies in virtual environment..."
pip install --upgrade pip
pip install wheel  # Ensure wheel is installed first

# Install requirements with lxml workaround
if pip install -r "$INSTALL_DIR/requirements.txt"; then
    echo "[+] Dependencies installed successfully"
else
    echo "[!] Fallback: Installing lxml from system repository"
    if command -v apt &> /dev/null; then
        sudo apt install -y python3-lxml
    elif command -v yum &> /dev/null; then
        sudo yum install -y python3-lxml
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y python3-lxml
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm python-lxml
    fi
    # Reinstall other dependencies excluding lxml
    sed '/lxml/d' "$INSTALL_DIR/requirements.txt" > "$INSTALL_DIR/requirements_fallback.txt"
    pip install -r "$INSTALL_DIR/requirements_fallback.txt"
fi

# Create launcher script
echo -e "\n[*] Creating launcher script..."
cat > "$INSTALL_DIR/run_recon" <<EOL
#!/bin/bash
source "$INSTALL_DIR/venv/bin/activate"
"$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/recon" "\$@"
EOL

# Make scripts executable
chmod +x "$INSTALL_DIR/recon"
chmod +x "$INSTALL_DIR/run_recon"

# Create symlink
echo "[*] Creating user-level symlink..."
ln -sf "$INSTALL_DIR/run_recon" "$BIN_DIR/recon"

# Add to PATH if needed
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$HOME/.bashrc"
    echo "[+] Added $BIN_DIR to your PATH in .bashrc"
    echo "    Run 'source ~/.bashrc' or restart your terminal"
fi

# System dependencies
echo -e "\n[*] Checking for system dependencies:"
dependencies=("nmap" "masscan" "chromedriver")
for dep in "${dependencies[@]}"; do
    if ! command -v $dep &> /dev/null; then
        echo "  [!] $dep not found - please install manually:"
        case $dep in
            "nmap")
                echo "      sudo apt install nmap"
                ;;
            "masscan")
                echo "      sudo apt install masscan"
                ;;
            "chromedriver")
                echo "      Download: https://chromedriver.chromium.org/downloads"
                echo "      Extract to: /usr/local/bin or ~/.local/bin"
                ;;
        esac
    else
        echo "  [✓] $dep installed"
    fi
done

echo -e "\n[+] Installation complete!"
echo "  Run with: recon [options]"
echo "  Example: recon -d example.com --vuln-scan"
echo "  Note: First run might be slow while dependencies initialize"
