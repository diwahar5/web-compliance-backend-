#!/bin/bash

set -e  # Exit if any command fails

echo "🚀 Installing Python dependencies..."
pip install -r requirements.txt

echo "🧠 Installing Playwright browsers with dependencies..."
python -m playwright install chromium
python -m playwright install-deps chromium

echo "✅ Playwright browser installation complete!"
