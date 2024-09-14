#!/bin/bash

# Update package lists
echo "Updating package lists..."
sudo apt-get update

# Install pip if not already installed
if ! command -v pip &> /dev/null
then
    echo "pip not found, installing pip..."
    sudo apt-get install -y python3-pip
fi

# Install required Python packages
echo "Installing required Python packages..."
pip install pycryptodome fuzzywuzzy

echo "Installation complete."
