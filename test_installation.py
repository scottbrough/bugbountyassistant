#!/usr/bin/env python3
import subprocess
import os
import sys

print("🔍 Testing Bug Bounty Assistant Installation\n")

# Check Python modules
print("Python modules:")
modules = ['openai', 'requests', 'yaml', 'flask', 'bs4']
for module in modules:
    try:
        __import__(module)
        print(f"✅ {module}")
    except ImportError:
        print(f"❌ {module} - run: pip install {module}")

# Check environment
print("\nEnvironment:")
if os.getenv('OPENAI_API_KEY'):
    print("✅ OPENAI_API_KEY is set")
else:
    print("❌ OPENAI_API_KEY not set")

# Check Go tools
print("\nGo tools:")
tools = ['subfinder', 'httpx', 'nuclei', 'gau']
for tool in tools:
    result = subprocess.run(['which', tool], capture_output=True)
    if result.returncode == 0:
        print(f"✅ {tool}: {result.stdout.decode().strip()}")
    else:
        print(f"❌ {tool} not found")

# Check file structure
print("\nFile structure:")
files = [
    'src/enhanced_personal_assistant.py',
    'src/platform_integration.py',
    'src/enhanced_vulnerability_testing.py',
    'src/web_api_backend.py',
    'config.yaml',
    '.env'
]
for file in files:
    if os.path.exists(file):
        print(f"✅ {file}")
    else:
        print(f"❌ {file} missing")

print("\n✅ Test complete!")
