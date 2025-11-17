#!/bin/bash
set -e

echo "🚀 Installing Python dependencies..."
pip install -r requirements.txt

echo "🧠 Installing Playwright browsers (Chromium only)..."
python -m playwright install --with-deps chromium

# Move browsers into a persistent app directory
echo "📦 Moving Playwright browsers into /app/.playwright..."
mkdir -p /app/.playwright
cp -r /root/.cache/ms-playwright /app/.playwright || true

echo "✅ Playwright setup complete!"
