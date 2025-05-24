#!/usr/bin/env python3
"""
Authentication Session Manager for Bug Bounty Assistant
Manages authenticated sessions for deeper testing
"""

import requests
import pickle
import json
from pathlib import Path
from typing import Dict, Optional, List
import logging
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

logger = logging.getLogger(__name__)

class AuthSessionManager:
    """Manages authenticated sessions for different targets"""
    
    def __init__(self, session_dir: str = "~/.bb_assistant/sessions"):
        self.session_dir = Path(session_dir).expanduser()
        self.session_dir.mkdir(exist_ok=True, parents=True)
        self.sessions = {}
        self.credentials = {}
        
    def add_credentials(self, target: str, username: str, password: str, 
                       login_url: str = None, additional_data: Dict = None):
        """Store credentials for a target"""
        self.credentials[target] = {
            'username': username,
            'password': password,
            'login_url': login_url or f"https://{target}/login",
            'additional_data': additional_data or {},
            'session_file': self.session_dir / f"{target.replace('.', '_')}_session.pkl"
        }
        logger.info(f"✅ Credentials added for {target}")
    
    def get_authenticated_session(self, target: str, force_refresh: bool = False) -> requests.Session:
        """Get or create authenticated session for target"""
        if target not in self.credentials:
            logger.warning(f"No credentials found for {target}")
            return requests.Session()
        
        session_file = self.credentials[target]['session_file']
        
        # Try to load existing session
        if not force_refresh and session_file.exists():
            try:
                with open(session_file, 'rb') as f:
                    session = pickle.load(f)
                    if self._verify_session(session, target):
                        logger.info(f"✅ Loaded existing session for {target}")
                        self.sessions[target] = session
                        return session
            except Exception as e:
                logger.debug(f"Failed to load session: {e}")
        
        # Create new authenticated session
        logger.info(f"🔐 Creating new authenticated session for {target}")
        session = self._create_authenticated_session(target)
        
        # Save session
        with open(session_file, 'wb') as f:
            pickle.dump(session, f)
        
        self.sessions[target] = session
        return session
    
    def _create_authenticated_session(self, target: str) -> requests.Session:
        """Create new authenticated session"""
        creds = self.credentials[target]
        session = requests.Session()
        
        # Common headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Try standard form-based login first
        try:
            login_response = self._perform_form_login(session, target, creds)
            if login_response:
                return session
        except Exception as e:
            logger.debug(f"Form login failed: {e}")
        
        # Try JavaScript-based login with Selenium
        try:
            selenium_session = self._perform_selenium_login(target, creds)
            if selenium_session:
                return selenium_session
        except Exception as e:
            logger.debug(f"Selenium login failed: {e}")
        
        logger.warning(f"⚠️ Could not authenticate to {target}")
        return session
    
    def _perform_form_login(self, session: requests.Session, target: str, creds: Dict) -> bool:
        """Perform standard form-based login"""
        login_url = creds['login_url']
        
        # Get login page to find form
        login_page = session.get(login_url, verify=False)
        
        # Common login parameters
        login_data = {
            'username': creds['username'],
            'password': creds['password'],
            'email': creds['username'],  # Some sites use email
            'user': creds['username'],
            'pass': creds['password'],
            'pwd': creds['password'],
            'login': creds['username'],
            'remember': '1',
            'remember_me': '1'
        }
        
        # Add any additional data
        login_data.update(creds.get('additional_data', {}))
        
        # Extract CSRF token if present
        csrf_token = self._extract_csrf_token(login_page.text)
        if csrf_token:
            login_data['csrf_token'] = csrf_token
            login_data['_csrf'] = csrf_token
            login_data['authenticity_token'] = csrf_token
        
        # Attempt login
        response = session.post(login_url, data=login_data, verify=False, allow_redirects=True)
        
        # Check if login was successful
        if response.status_code == 200:
            # Look for common success indicators
            success_indicators = ['dashboard', 'profile', 'logout', 'sign out', 'welcome']
            if any(indicator in response.text.lower() for indicator in success_indicators):
                logger.info(f"✅ Successfully logged in to {target}")
                return True
        
        return False
    
    def _perform_selenium_login(self, target: str, creds: Dict) -> Optional[requests.Session]:
        """Perform login using Selenium for JavaScript-heavy sites"""
        from selenium.webdriver.chrome.options import Options
        
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        
        driver = webdriver.Chrome(options=options)
        
        try:
            driver.get(creds['login_url'])
            time.sleep(2)
            
            # Find and fill username field
            username_selectors = ['#username', '#email', 'input[name="username"]', 
                                 'input[name="email"]', 'input[type="email"]']
            for selector in username_selectors:
                try:
                    username_field = driver.find_element(By.CSS_SELECTOR, selector)
                    username_field.send_keys(creds['username'])
                    break
                except:
                    continue
            
            # Find and fill password field
            password_selectors = ['#password', 'input[name="password"]', 
                                 'input[type="password"]']
            for selector in password_selectors:
                try:
                    password_field = driver.find_element(By.CSS_SELECTOR, selector)
                    password_field.send_keys(creds['password'])
                    break
                except:
                    continue
            
            # Find and click submit button
            submit_selectors = ['button[type="submit"]', 'input[type="submit"]', 
                               '#login-button', '.login-button', 'button:contains("Log in")']
            for selector in submit_selectors:
                try:
                    submit_button = driver.find_element(By.CSS_SELECTOR, selector)
                    submit_button.click()
                    break
                except:
                    continue
            
            # Wait for login to complete
            time.sleep(3)
            
            # Transfer cookies to requests session
            session = requests.Session()
            for cookie in driver.get_cookies():
                session.cookies.set(cookie['name'], cookie['value'], 
                                  domain=cookie.get('domain'))
            
            driver.quit()
            return session
            
        except Exception as e:
            logger.error(f"Selenium login failed: {e}")
            driver.quit()
            return None
    
    def _extract_csrf_token(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML"""
        import re
        
        # Common CSRF token patterns
        patterns = [
            r'<meta name="csrf-token" content="([^"]+)"',
            r'<input[^>]*name="csrf_token"[^>]*value="([^"]+)"',
            r'<input[^>]*name="_csrf"[^>]*value="([^"]+)"',
            r'<input[^>]*name="authenticity_token"[^>]*value="([^"]+)"',
            r'"csrf_token":\s*"([^"]+)"',
            r'"csrfToken":\s*"([^"]+)"'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)
        
        return None
    
    def _verify_session(self, session: requests.Session, target: str) -> bool:
        """Verify if session is still authenticated"""
        # Test common authenticated endpoints
        test_urls = [
            f"https://{target}/api/user",
            f"https://{target}/profile",
            f"https://{target}/dashboard",
            f"https://{target}/account"
        ]
        
        for url in test_urls:
            try:
                response = session.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    # Check if we're not redirected to login
                    if 'login' not in response.url.lower():
                        return True
            except:
                continue
        
        return False
    
    def get_session_info(self, target: str) -> Dict:
        """Get information about stored session"""
        if target not in self.credentials:
            return {'status': 'no_credentials'}
        
        session_file = self.credentials[target]['session_file']
        if session_file.exists():
            # Verify if session is still valid
            session = self.get_authenticated_session(target)
            if self._verify_session(session, target):
                return {
                    'status': 'authenticated',
                    'username': self.credentials[target]['username'],
                    'session_file': str(session_file)
                }
            else:
                return {
                    'status': 'expired',
                    'username': self.credentials[target]['username']
                }
        
        return {
            'status': 'not_authenticated',
            'username': self.credentials[target]['username']
        }


class AuthenticatedTester:
    """Enhanced vulnerability tester with authentication support"""
    
    def __init__(self, auth_manager: AuthSessionManager):
        self.auth_manager = auth_manager
        
    def test_authenticated_endpoints(self, target: str, endpoints: List[str]) -> List[Dict]:
        """Test endpoints that require authentication"""
        session = self.auth_manager.get_authenticated_session(target)
        findings = []
        
        # Test for common authenticated vulnerabilities
        for endpoint in endpoints:
            # Test IDOR
            findings.extend(self._test_authenticated_idor(session, endpoint))
            
            # Test privilege escalation
            findings.extend(self._test_privilege_escalation(session, endpoint))
            
            # Test account takeover vectors
            findings.extend(self._test_account_takeover(session, endpoint))
        
        return findings
    
    def _test_authenticated_idor(self, session: requests.Session, endpoint: str) -> List[Dict]:
        """Test for IDOR vulnerabilities with authentication"""
        findings = []
        
        # Get current user ID from authenticated endpoints
        user_id = self._get_current_user_id(session)
        if not user_id:
            return findings
        
        # Test accessing other users' data
        test_ids = [
            str(int(user_id) + 1) if user_id.isdigit() else 'test',
            str(int(user_id) - 1) if user_id.isdigit() else 'admin',
            '1', '0', '-1', 'admin', 'root'
        ]
        
        for test_id in test_ids:
            if test_id == user_id:
                continue
                
            test_url = endpoint.replace(user_id, test_id)
            
            try:
                response = session.get(test_url, verify=False)
                if response.status_code == 200:
                    # Check if we got different user's data
                    if test_id in response.text or 'email' in response.text:
                        findings.append({
                            'vulnerable': True,
                            'type': 'Authenticated IDOR',
                            'url': test_url,
                            'severity': 'high',
                            'evidence': f'Accessed user {test_id} data while authenticated as {user_id}',
                            'requires_auth': True
                        })
            except:
                pass
        
        return findings
    
    def _test_privilege_escalation(self, session: requests.Session, endpoint: str) -> List[Dict]:
        """Test for privilege escalation vulnerabilities"""
        findings = []
        
        # Try to access admin endpoints
        admin_endpoints = [
            '/admin', '/api/admin', '/administration',
            '/manage', '/management', '/superuser'
        ]
        
        for admin_path in admin_endpoints:
            if admin_path in endpoint:
                continue
                
            test_url = endpoint.rsplit('/', 1)[0] + admin_path
            
            try:
                response = session.get(test_url, verify=False)
                if response.status_code == 200:
                    findings.append({
                        'vulnerable': True,
                        'type': 'Privilege Escalation',
                        'url': test_url,
                        'severity': 'critical',
                        'evidence': 'Regular user can access admin endpoint',
                        'requires_auth': True
                    })
            except:
                pass
        
        return findings
    
    def _test_account_takeover(self, session: requests.Session, endpoint: str) -> List[Dict]:
        """Test for account takeover vulnerabilities"""
        findings = []
        
        # Test password reset without old password
        if 'password' in endpoint or 'account' in endpoint:
            try:
                # Try to change password without old password
                response = session.post(
                    endpoint,
                    json={'new_password': 'test123', 'confirm_password': 'test123'},
                    verify=False
                )
                
                if response.status_code in [200, 204]:
                    findings.append({
                        'vulnerable': True,
                        'type': 'Account Takeover - Missing Password Verification',
                        'url': endpoint,
                        'severity': 'critical',
                        'evidence': 'Password change without old password verification',
                        'requires_auth': True
                    })
            except:
                pass
        
        return findings
    
    def _get_current_user_id(self, session: requests.Session) -> Optional[str]:
        """Extract current user ID from authenticated session"""
        # Try common endpoints
        endpoints = ['/api/user', '/api/me', '/profile', '/account']
        
        for endpoint in endpoints:
            try:
                response = session.get(f"{session.headers.get('Origin', 'https://example.com')}{endpoint}", 
                                     verify=False)
                if response.status_code == 200:
                    data = response.json()
                    return str(data.get('id', data.get('user_id', data.get('userId'))))
            except:
                pass
        
        return None