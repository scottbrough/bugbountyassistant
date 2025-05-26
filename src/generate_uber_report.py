import json
import os
from enhanced_personal_assistant import EnhancedBugBountyAssistant

api_key = os.environ.get('OPENAI_API_KEY', 'sk-xxx')
assistant = EnhancedBugBountyAssistant(api_key=api_key, config={})
assistant.target = 'uber.com'
assistant.workspace = 'src/hunt_uber_com_20250525_184932'

with open('src/hunt_uber_com_20250525_184932/findings.json') as f:
    assistant.findings = json.load(f)['findings']
with open('src/hunt_uber_com_20250525_184932/vulnerability_chains.json') as f:
    assistant.chains = json.load(f)
assistant.session_data = {}
assistant.program_info = {}
assistant.ai_report_generation()
