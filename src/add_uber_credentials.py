#!/usr/bin/env python3
"""Add Uber credentials for authenticated testing"""

import sys
sys.path.insert(0, 'src')

from auth_session_manager import AuthSessionManager
import getpass

print("🔐 Add Uber Test Account Credentials\n")

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

print("\n✅ Credentials saved!")
print("   These will be used automatically when hunting uber.com")
