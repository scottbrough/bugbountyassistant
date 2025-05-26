#!/usr/bin/env python3
# Save as: src/mobile_app_tester.py
# Mobile application testing capabilities

import re
import json
import subprocess
import requests
from typing import Dict, List, Optional
import logging
import os
import zipfile
import plistlib

logger = logging.getLogger(__name__)

class MobileAppTester:
    """Test mobile applications for vulnerabilities"""
    
    def __init__(self):
        self.findings = []
        self.session = requests.Session()
        
    def test_mobile_endpoints(self, base_url: str, app_type: str = 'both') -> List[Dict]:
        """Test mobile-specific endpoints"""
        findings = []
        
        # Common mobile API endpoints
        mobile_endpoints = {
            'ios': [
                '/api/ios/config',
                '/api/v1/ios/update',
                '/mobile/ios/api/',
                '/ios/version',
                '/api/device/register',
                '/api/push/register'
            ],
            'android': [
                '/api/android/config',
                '/api/v1/android/update',
                '/mobile/android/api/',
                '/android/version',
                '/api/gcm/register',
                '/api/fcm/register'
            ],
            'common': [
                '/api/mobile/auth',
                '/api/mobile/config',
                '/mobile/api/v1/',
                '/api/app/version',
                '/api/device/info',
                '/api/mobile/user',
                '/m/api/',
                '/mobile/oauth/'
            ]
        }
        
        # Test endpoints based on app type
        endpoints_to_test = []
        if app_type in ['ios', 'both']:
            endpoints_to_test.extend(mobile_endpoints['ios'])
        if app_type in ['android', 'both']:
            endpoints_to_test.extend(mobile_endpoints['android'])
        endpoints_to_test.extend(mobile_endpoints['common'])
        
        for endpoint in endpoints_to_test:
            test_url = f"{base_url}{endpoint}"
            
            # Test for exposed endpoints
            try:
                response = self.session.get(test_url, timeout=10)
                if response.status_code == 200:
                    findings.append({
                        'vulnerable': True,
                        'type': 'Exposed Mobile API Endpoint',
                        'url': test_url,
                        'severity': 'medium',
                        'evidence': f'Mobile endpoint accessible: {endpoint}',
                        'confidence': 'high'
                    })
                    
                    # Check for sensitive data in response
                    sensitive_patterns = {
                        'api_key': r'["\']api_key["\']\s*:\s*["\']([^"\']+)["\']',
                        'secret': r'["\']secret["\']\s*:\s*["\']([^"\']+)["\']',
                        'private_key': r'["\']private_key["\']\s*:\s*["\']([^"\']+)["\']',
                        'token': r'["\']token["\']\s*:\s*["\']([^"\']+)["\']'
                    }
                    
                    for key, pattern in sensitive_patterns.items():
                        match = re.search(pattern, response.text)
                        if match:
                            findings.append({
                                'vulnerable': True,
                                'type': 'Mobile API Key Exposure',
                                'url': test_url,
                                'severity': 'high',
                                'evidence': f'{key} exposed in mobile endpoint',
                                'value': match.group(1)[:20] + '...',
                                'confidence': 'high'
                            })
                            
            except:
                pass
        
        # Test for certificate pinning bypass
        findings.extend(self._test_certificate_pinning(base_url))
        
        # Test for mobile-specific authentication issues
        findings.extend(self._test_mobile_auth(base_url))
        
        # Test for deep link vulnerabilities
        findings.extend(self._test_deep_links(base_url))
        
        return findings
    
    def _test_certificate_pinning(self, base_url: str) -> List[Dict]:
        """Test for certificate pinning vulnerabilities"""
        findings = []
        
        # Mobile-specific headers that might bypass cert pinning
        bypass_headers = {
            'X-Pinning-Bypass': 'true',
            'X-SSL-Bypass': '1',
            'X-Certificate-Bypass': 'enabled',
            'X-Debug-Mode': 'true',
            'X-Dev-Mode': '1'
        }
        
        for header, value in bypass_headers.items():
            try:
                response = self.session.get(
                    base_url,
                    headers={header: value},
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 200:
                    findings.append({
                        'vulnerable': True,
                        'type': 'Certificate Pinning Bypass',
                        'url': base_url,
                        'severity': 'high',
                        'evidence': f'Certificate pinning bypassed with header {header}',
                        'confidence': 'medium'
                    })
            except:
                pass
        
        return findings
    
    def _test_mobile_auth(self, base_url: str) -> List[Dict]:
        """Test mobile-specific authentication vulnerabilities"""
        findings = []
        
        # Test biometric bypass
        auth_endpoints = ['/api/mobile/auth', '/api/biometric/verify', '/api/touchid/verify']
        
        for endpoint in auth_endpoints:
            test_url = f"{base_url}{endpoint}"
            
            # Test with bypass payloads
            bypass_payloads = [
                {"biometric_verified": True},
                {"touchid_success": True},
                {"faceid_success": True},
                {"bypass_biometric": True},
                {"debug_mode": True}
            ]
            
            for payload in bypass_payloads:
                try:
                    response = self.session.post(test_url, json=payload, timeout=10)
                    
                    if response.status_code == 200:
                        auth_indicators = ['success', 'authenticated', 'token', 'session']
                        if any(indicator in response.text.lower() for indicator in auth_indicators):
                            findings.append({
                                'vulnerable': True,
                                'type': 'Mobile Biometric Authentication Bypass',
                                'url': test_url,
                                'severity': 'critical',
                                'evidence': f'Biometric auth bypassed with {payload}',
                                'confidence': 'high'
                            })
                except:
                    pass
        
        return findings
    
    def _test_deep_links(self, base_url: str) -> List[Dict]:
        """Test for deep link vulnerabilities"""
        findings = []
        
        # Common deep link schemes
        deep_link_schemes = {
            'uber': ['uber://', 'uberx://', 'uberpool://'],
            'generic': ['app://', 'mobile://', 'deeplink://']
        }
        
        # Test for deep link information disclosure
        deep_link_endpoints = [
            '/api/deeplink/resolve',
            '/api/universal-link/resolve',
            '/api/app-link/resolve',
            '/.well-known/apple-app-site-association',
            '/.well-known/assetlinks.json'
        ]
        
        for endpoint in deep_link_endpoints:
            test_url = f"{base_url}{endpoint}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    # Check for sensitive information
                    if 'applinks' in response.text or 'appID' in response.text:
                        findings.append({
                            'vulnerable': True,
                            'type': 'Deep Link Configuration Exposure',
                            'url': test_url,
                            'severity': 'low',
                            'evidence': 'Deep link configuration exposed',
                            'confidence': 'high'
                        })
                        
                    # Parse for vulnerabilities
                    try:
                        data = response.json()
                        # Look for dangerous patterns
                        dangerous_patterns = ['*', 'wildcard', 'all']
                        
                        if any(pattern in str(data).lower() for pattern in dangerous_patterns):
                            findings.append({
                                'vulnerable': True,
                                'type': 'Overly Permissive Deep Link Configuration',
                                'url': test_url,
                                'severity': 'medium',
                                'evidence': 'Wildcard or overly permissive deep link rules',
                                'confidence': 'high'
                            })
                    except:
                        pass
                        
            except:
                pass
        
        return findings
    
    def analyze_mobile_api_security(self, base_url: str) -> Dict:
        """Comprehensive mobile API security analysis"""
        analysis = {
            'api_versioning': self._check_api_versioning(base_url),
            'rate_limiting': self._check_mobile_rate_limiting(base_url),
            'device_verification': self._check_device_verification(base_url),
            'jailbreak_detection': self._check_jailbreak_detection(base_url),
            'findings': []
        }
        
        # Aggregate findings
        for check, result in analysis.items():
            if isinstance(result, dict) and result.get('vulnerable'):
                analysis['findings'].append(result)
        
        return analysis
    
    def _check_api_versioning(self, base_url: str) -> Dict:
        """Check for API versioning vulnerabilities"""
        # Test accessing older API versions
        version_patterns = [
            '/api/v1/', '/api/v2/', '/api/v3/',
            '/v1/api/', '/v2/api/', '/v3/api/',
            '/api/1.0/', '/api/2.0/', '/api/3.0/'
        ]
        
        for pattern in version_patterns:
            test_url = f"{base_url}{pattern}user"
            try:
                response = self.session.get(test_url, timeout=10)
                if response.status_code == 200:
                    return {
                        'vulnerable': True,
                        'type': 'Outdated Mobile API Version Accessible',
                        'url': test_url,
                        'severity': 'medium',
                        'evidence': f'Old API version {pattern} is still accessible',
                        'confidence': 'high'
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def _check_mobile_rate_limiting(self, base_url: str) -> Dict:
        """Check for rate limiting on mobile endpoints"""
        test_endpoint = f"{base_url}/api/mobile/auth"
        
        # Send rapid requests
        responses = []
        for i in range(20):
            try:
                response = self.session.post(
                    test_endpoint,
                    json={"username": f"test{i}", "password": "test"},
                    timeout=5
                )
                responses.append(response.status_code)
            except:
                pass
        
        # Check if rate limiting is applied
        if responses.count(429) == 0 and len(responses) > 15:
            return {
                'vulnerable': True,
                'type': 'Missing Rate Limiting on Mobile API',
                'url': test_endpoint,
                'severity': 'medium',
                'evidence': f'Sent {len(responses)} requests without rate limiting',
                'confidence': 'high'
            }
        
        return {'vulnerable': False}
    
    def _check_device_verification(self, base_url: str) -> Dict:
        """Check for device verification bypass"""
        test_endpoint = f"{base_url}/api/device/verify"
        
        # Test with fake device information
        fake_devices = [
            {
                "device_id": "00000000-0000-0000-0000-000000000000",
                "device_type": "iOS",
                "jailbroken": False
            },
            {
                "device_id": "emulator",
                "device_type": "Android",
                "rooted": False
            }
        ]
        
        for device in fake_devices:
            try:
                response = self.session.post(test_endpoint, json=device, timeout=10)
                
                if response.status_code == 200:
                    return {
                        'vulnerable': True,
                        'type': 'Device Verification Bypass',
                        'url': test_endpoint,
                        'severity': 'high',
                        'evidence': f'Fake device accepted: {device}',
                        'confidence': 'high'
                    }
            except:
                pass
        
        return {'vulnerable': False}
    
    def _check_jailbreak_detection(self, base_url: str) -> Dict:
        """Check for jailbreak/root detection bypass"""
        test_endpoints = [
            '/api/device/status',
            '/api/security/check',
            '/api/device/verify'
        ]
        
        bypass_payloads = [
            {"jailbroken": False, "bypass": True},
            {"rooted": False, "debug": True},
            {"integrity_check": "passed", "emulator": False}
        ]
        
        for endpoint in test_endpoints:
            test_url = f"{base_url}{endpoint}"
            
            for payload in bypass_payloads:
                try:
                    response = self.session.post(test_url, json=payload, timeout=10)
                    
                    if response.status_code == 200 and 'approved' in response.text.lower():
                        return {
                            'vulnerable': True,
                            'type': 'Jailbreak/Root Detection Bypass',
                            'url': test_url,
                            'severity': 'high',
                            'evidence': f'Security check bypassed with {payload}',
                            'confidence': 'medium'
                        }
                except:
                    pass
        
        return {'vulnerable': False}
