#!/bin/bash

# GOLEM COPS - Universal Install Script
# Usage: curl -sSL https://raw.githubusercontent.com/GolemSecurity/golem-cops/main/install.sh | bash

set -e

REPO="GolemSecurity/golem-cops"
BINARY="golem-cops"
INSTALL_DIR="/usr/local/bin"

# colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}  GOLEM COPS - Continuous Operations Protection System${NC}"
echo -e "${BLUE}  Installing...${NC}"
echo ""

# detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)
    echo -e "${RED}  Unsupported architecture: $ARCH${NC}"
    exit 1
    ;;
esac

case $OS in
  linux)  PLATFORM="linux" ;;
  darwin) PLATFORM="darwin" ;;
  *)
    echo -e "${RED}  Unsupported OS: $OS${NC}"
    echo -e "${YELLOW}  For Windows, download the .exe from:${NC}"
    echo -e "${YELLOW}  https://github.com/$REPO/releases/latest${NC}"
    exit 1
    ;;
esac

BINARY_NAME="${BINARY}-${PLATFORM}-${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}"

echo -e "  Platform : ${GREEN}${PLATFORM}/${ARCH}${NC}"
echo -e "  Download : ${GREEN}${DOWNLOAD_URL}${NC}"
echo ""

# download binary
echo -e "  Downloading GOLEM COPS..."
curl -sSL "$DOWNLOAD_URL" -o "/tmp/${BINARY}"

if [ ! -f "/tmp/${BINARY}" ]; then
  echo -e "${RED}  Download failed.${NC}"
  exit 1
fi

chmod +x "/tmp/${BINARY}"

# install
echo -e "  Installing to ${INSTALL_DIR}..."
if [ -w "$INSTALL_DIR" ]; then
  mv "/tmp/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  sudo mv "/tmp/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

# verify
if command -v golem-cops &> /dev/null; then
  echo ""
  echo -e "${GREEN}  ✓ GOLEM COPS installed successfully!${NC}"
  echo ""
  echo -e "  Run: ${BLUE}golem-cops code scan .${NC}"
  echo ""
else
  echo -e "${RED}  Installation failed. Try adding ${INSTALL_DIR} to your PATH.${NC}"
  exit 1
fi