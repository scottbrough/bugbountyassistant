# In your Python console or script:
from auth_session_manager import AuthSessionManager

auth_manager = AuthSessionManager()
auth_manager.add_credentials(
    target='uber.com',
    username='your_test_email@example.com',
    password='your_test_password',
    login_url='https://auth.uber.com/login/'
)