#!/bin/bash
echo "🚀 Starting Enhanced Bug Bounty Assistant..."

# Set environment variables
export FLASK_ENV=development
export FLASK_DEBUG=0
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Apply patches
python3 -c "
import sys
sys.path.insert(0, 'src')
from advanced_assistant_v3 import EnhancedBugBountyAssistantV3

# Test token management patch
print('✅ Applying token management patches...')
assistant = EnhancedBugBountyAssistantV3('test', {})
assistant._patch_token_management()
print('✅ Patches applied successfully!')
"

# Start the application
cd src && python app.py
