#!/bin/bash

echo "Setting up CovertDNS Project..."

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

echo "Setup complete! Run the project with: streamlit run app.py"