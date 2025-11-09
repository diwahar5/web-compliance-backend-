#!/bin/bash

echo "🚀 Installing dependencies..."
pip install -r requirements.txt

echo "🧠 Installing Playwright browsers..."
python -m playwright install --with-deps chromium

echo "✅ Build complete."
