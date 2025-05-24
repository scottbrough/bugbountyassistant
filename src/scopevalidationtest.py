#!/usr/bin/env python3
import os
import sys
sys.path.insert(0, 'src')

from advanced_assistant_v3 import EnhancedBugBountyAssistantV3

# Test configuration loading
config = {
    'scope_validation': {'enabled': False},
    'aggressive_testing': {'enabled': True}
}

# Initialize assistant
api_key = os.getenv('OPENAI_API_KEY', 'test-key')
assistant = EnhancedBugBountyAssistantV3(api_key, config)

print(f"✅ Scope validation enabled: {assistant.scope_validation_enabled}")
print(f"✅ Aggressive mode enabled: {assistant.aggressive_mode}")

# Test subdomain validation
test_subdomains = [
    "www.example.com",
    "api.example.com", 
    "test-api.example.com",
    "2j2t1.example.com",  # Should be valid
    "invalid..example.com",  # Should be invalid
    "-invalid.example.com"  # Should be invalid
]

assistant.target = "example.com"
for sub in test_subdomains:
    valid = assistant._is_valid_subdomain(sub)
    print(f"{'✅' if valid else '❌'} {sub}: {'Valid' if valid else 'Invalid'}")
