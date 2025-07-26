#!/bin/bash
# Recon Cell Installer v1.2

echo "[*] Installing Recon Cell v1.2"

# Create installation directory
INSTALL_DIR="$HOME/.recon-cell"
BIN_DIR="$HOME/.local/bin"
echo "[+] Creating directories: $INSTALL_DIR and $BIN_DIR"
mkdir -p "$INSTALL_DIR" "$BIN_DIR"

# Copy main script
echo "[*] Installing main script..."
cp recon-cell.py "$INSTALL_DIR/recon-cell.py"
chmod +x "$INSTALL_DIR/recon-cell.py"

# Create direct launcher
echo "[*] Creating launcher script..."
cat > "$INSTALL_DIR/recon-cell" <<EOL
#!/bin/bash
python3 "$INSTALL_DIR/recon-cell.py" "\$@"
EOL

chmod +x "$INSTALL_DIR/recon-cell"

# Create symlink
echo "[*] Creating symlink..."
ln -sf "$INSTALL_DIR/recon-cell" "$BIN_DIR/recon-cell"

# Add to PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$HOME/.bashrc"
    echo "[+] Added $BIN_DIR to PATH in .bashrc"
    echo "    Run: source ~/.bashrc"
fi

# Install system dependencies
echo -e "\n[*] Installing system dependencies..."
if command -v apt &> /dev/null; then
    sudo apt update
    sudo apt install -y nmap masscan chromium-driver
    echo "[+] Installed core dependencies"
    
    # Install ChromeDriver
    if ! command -v chromedriver &> /dev/null; then
        echo "[*] Installing ChromeDriver..."
        LATEST_CHROME=$(curl -s https://chromedriver.storage.googleapis.com/LATEST_RELEASE)
        wget https://chromedriver.storage.googleapis.com/$LATEST_CHROME/chromedriver_linux64.zip
        unzip chromedriver_linux64.zip
        sudo mv chromedriver /usr/local/bin/
        rm chromedriver_linux64.zip
        echo "[+] ChromeDriver installed"
    fi
fi

# Install Nuclei if requested
if [[ "$1" == "--with-nuclei" ]]; then
    if ! command -v nuclei &> /dev/null; then
        echo -e "\n[*] Installing Nuclei..."
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
        echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
        echo "[+] Nuclei installed - added to PATH in .bashrc"
    fi
fi

echo -e "\n[+] Installation complete!"
echo "  Run with: recon-cell [options]"
echo "  Example: recon-cell -d example.com --vuln-scan"
