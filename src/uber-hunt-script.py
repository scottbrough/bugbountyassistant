#!/usr/bin/env python3
"""
Quick start script for hunting on Uber
Run this to start an optimized hunt with proper configuration
"""

import os
import sys
import warnings
import urllib3
import requests
import json
from pathlib import Path

# Disable all SSL warnings
urllib3.disable_warnings()
warnings.filterwarnings('ignore')
os.environ['PYTHONWARNINGS'] = 'ignore:Unverified HTTPS request'

# Add src to path
sys.path.insert(0, 'src')

def setup_uber_hunt():
    """Setup optimized configuration for Uber testing"""
    
    print("🎯 Setting up Uber Bug Bounty Hunt\n")
    
    # Check for API key
    if not os.getenv('OPENAI_API_KEY'):
        print("❌ Please set OPENAI_API_KEY environment variable")
        print("   export OPENAI_API_KEY='your-key-here'")
        sys.exit(1)
    
    # Create optimized config
    config = {
        "openai": {
            "model": "gpt-4",
            "temperature": 0.7,
            "max_tokens": 4000
        },
        "aggressive_testing": {
            "enabled": True,
            "max_evasion_attempts": 15,
            "waf_detection": True
        },
        "scope_validation": {
            "enabled": False  # Disabled for Uber
        },
        "tools": {
            "subfinder": True,
            "httpx": True,
            "use_all": True
        },
        "rate_limiting": {
            "enabled": True,
            "base_delay": 0.5  # Faster for Uber
        },
        "javascript_analysis": {
            "enabled": True,
            "max_files_to_analyze": 20,
            "ai_analysis_for_large_files": True
        },
        "api_testing": {
            "graphql_introspection": True,
            "jwt_testing": True,
            "idor_testing": True
        }
    }
    
    # Save config
    config_path = Path("uber_hunt_config.yaml")
    with open(config_path, 'w') as f:
        import yaml
        yaml.dump(config, f)
    
    print("✅ Configuration created: uber_hunt_config.yaml")
    
    # Create test credentials prompt
    print("\n📝 To test authenticated endpoints, create a test Uber account and run:")
    print("   python add_uber_credentials.py")
    
    return config_path

def start_web_interface():
    """Start the web interface with proper configuration"""
    print("\n🚀 Starting Bug Bounty Assistant Web Interface...")
    print("   URL: http://localhost:5000")
    print("\n📋 Quick Start:")
    print("   1. Click 'Hunt' in the navigation")
    print("   2. Click 'New Hunt'")
    print("   3. Enter target: uber.com")
    print("   4. Enable: Aggressive Mode, Disable: Scope Validation")
    print("   5. Click 'Start Hunt'\n")
    
    # Set environment variables
    os.environ['FLASK_ENV'] = 'development'
    os.environ['DISABLE_SCOPE_VALIDATION'] = 'true'
    
    # Import and run app
    try:
        from app import app, socketio, initialize_app
        
        # Initialize
        initialize_app()
        
        # Disable request logging for cleaner output
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        
        # Run with eventlet
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
        
    except ImportError as e:
        print(f"❌ Error importing app: {e}")
        print("   Make sure you're in the project root directory")
        sys.exit(1)

def create_credentials_script():
    """Create a helper script for adding Uber credentials"""
    script_content = '''#!/usr/bin/env python3
"""Add Uber credentials for authenticated testing"""

import sys
sys.path.insert(0, 'src')

from auth_session_manager import AuthSessionManager
import getpass

print("🔐 Add Uber Test Account Credentials\\n")

email = input("Enter your Uber test account email: ")
password = getpass.getpass("Enter your Uber test account password: ")

auth_manager = AuthSessionManager()
auth_manager.add_credentials(
    target='uber.com',
    username=email,
    password=password,
    login_url='https://auth.uber.com/login/',
    additional_data={
        'client_id': 'uber-web',
        'response_type': 'token'
    }
)

print("\\n✅ Credentials saved!")
print("   These will be used automatically when hunting uber.com")
'''
    
    with open('add_uber_credentials.py', 'w') as f:
        f.write(script_content)
    os.chmod('add_uber_credentials.py', 0o755)
    
    print("✅ Created: add_uber_credentials.py")

def main():
    """Main entry point"""
    print("""
╔═══════════════════════════════════════════════╗
║     🎯 Uber Bug Bounty Hunt Setup 🎯          ║
║                                               ║
║  Optimized for finding vulnerabilities on     ║
║  Uber's bug bounty program                    ║
╚═══════════════════════════════════════════════╝
""")
    
    # Setup configuration
    config_path = setup_uber_hunt()
    
    # Create credentials script
    create_credentials_script()
    
    # Add Uber-specific wordlists
    print("\n📚 Creating Uber-specific wordlists...")
    
    uber_paths = [
        '/api/getfare', '/api/getuser', '/api/getrides', '/api/getpayments',
        '/api/v1/riders', '/api/v1/drivers', '/api/v1/trips', '/api/v1/payments',
        '/marketplace/api', '/m/api', '/rtapi', '/internal/api',
        '/debug', '/admin', '/swagger', '/docs', '/api-docs',
        '/.git', '/.env', '/config', '/backup'
    ]
    
    with open('uber_paths.txt', 'w') as f:
        f.write('\n'.join(uber_paths))
    
    print("✅ Created: uber_paths.txt")
    
    # Start the web interface
    try:
        start_web_interface()
    except KeyboardInterrupt:
        print("\n\n👋 Hunt stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()