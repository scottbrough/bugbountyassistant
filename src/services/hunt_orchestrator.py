#!/usr/bin/env python3
"""
Hunt Orchestration Service - Core engine for coordinating bug hunts
"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
import logging
from dataclasses import dataclass, field
import json

logger = logging.getLogger(__name__)

class HuntPhase(Enum):
    INITIALIZATION = "initialization"
    RECONNAISSANCE = "reconnaissance"
    TESTING_PHASE_1 = "testing_phase_1"  # Standard tests
    TESTING_PHASE_2 = "testing_phase_2"  # Aggressive/WAF bypass
    TESTING_PHASE_3 = "testing_phase_3"  # Specialized tests
    VERIFICATION = "verification"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ERROR = "error"

@dataclass
class HuntContext:
    """Maintains hunt state and context"""
    hunt_id: str
    target: str
    platform: Optional[str] = None
    program: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)
    current_phase: HuntPhase = HuntPhase.INITIALIZATION
    findings: List[Dict] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    endpoints: List[Dict] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class HuntManager:
    """Manages multiple hunts and their lifecycle"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.active_hunts: Dict[str, 'HuntExecutor'] = {}
        self.completed_hunts: Dict[str, HuntContext] = {}
        self.event_handlers = {}
        
        # Dependencies will be injected
        self.llm_service = None
        self.verification_service = None
        self.report_generator = None
        self.platform_integration = None
        
    def set_dependencies(self, **kwargs):
        """Inject service dependencies"""
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    async def start_hunt(self, target: str, config: Dict[str, Any]) -> str:
        """Start a new hunt"""
        hunt_id = str(uuid.uuid4())
        context = HuntContext(
            hunt_id=hunt_id,
            target=target,
            platform=config.get('platform'),
            program=config.get('program'),
            config=config
        )
        
        executor = HuntExecutor(context, self)
        self.active_hunts[hunt_id] = executor
        
        # Start async execution
        asyncio.create_task(self._execute_hunt(executor))
        
        return hunt_id
    
    async def _execute_hunt(self, executor: 'HuntExecutor'):
        """Execute hunt with error handling"""
        try:
            await executor.execute()
            self.completed_hunts[executor.context.hunt_id] = executor.context
        except Exception as e:
            logger.error(f"Hunt {executor.context.hunt_id} failed: {e}")
            executor.context.current_phase = HuntPhase.ERROR
            await self._emit_event('hunt_error', {
                'hunt_id': executor.context.hunt_id,
                'error': str(e),
                'phase': executor.context.current_phase.value
            })
        finally:
            # Cleanup
            if executor.context.hunt_id in self.active_hunts:
                del self.active_hunts[executor.context.hunt_id]
    
    def get_hunt_status(self, hunt_id: str) -> Optional[Dict]:
        """Get current hunt status"""
        if hunt_id in self.active_hunts:
            executor = self.active_hunts[hunt_id]
            return {
                'status': 'active',
                'phase': executor.context.current_phase.value,
                'progress': executor.get_progress(),
                'findings_count': len(executor.context.findings),
                'duration': (datetime.now() - executor.context.start_time).total_seconds()
            }
        elif hunt_id in self.completed_hunts:
            context = self.completed_hunts[hunt_id]
            return {
                'status': 'completed',
                'phase': context.current_phase.value,
                'findings_count': len(context.findings),
                'duration': (datetime.now() - context.start_time).total_seconds()
            }
        return None
    
    def register_event_handler(self, event: str, handler):
        """Register event handler for hunt events"""
        if event not in self.event_handlers:
            self.event_handlers[event] = []
        self.event_handlers[event].append(handler)
    
    async def _emit_event(self, event: str, data: Dict):
        """Emit event to registered handlers"""
        if event in self.event_handlers:
            for handler in self.event_handlers[event]:
                try:
                    await handler(data)
                except Exception as e:
                    logger.error(f"Event handler error: {e}")

class HuntExecutor:
    """Executes a single hunt through all phases"""
    
    def __init__(self, context: HuntContext, manager: HuntManager):
        self.context = context
        self.manager = manager
        self.modules = {}
        self.progress = 0
        
    async def execute(self):
        """Execute hunt through all phases"""
        phases = {
            HuntPhase.INITIALIZATION: self._initialize,
            HuntPhase.RECONNAISSANCE: self._reconnaissance,
            HuntPhase.TESTING_PHASE_1: self._testing_phase_1,
            HuntPhase.TESTING_PHASE_2: self._testing_phase_2,
            HuntPhase.TESTING_PHASE_3: self._testing_phase_3,
            HuntPhase.VERIFICATION: self._verification,
            HuntPhase.REPORTING: self._reporting
        }
        
        for phase, handler in phases.items():
            self.context.current_phase = phase
            await self._emit_progress(phase.value, self.progress)
            
            try:
                await handler()
                self.progress = min(self.progress + 15, 90)
            except Exception as e:
                logger.error(f"Phase {phase.value} failed: {e}")
                raise
        
        self.context.current_phase = HuntPhase.COMPLETED
        self.progress = 100
        await self._emit_progress("completed", self.progress)
    
    async def _initialize(self):
        """Initialize hunt context and dependencies"""
        logger.info(f"Initializing hunt {self.context.hunt_id} for {self.context.target}")
        
        # Load modules based on config
        await self._load_modules()
        
        # Get program scope if available
        if self.context.platform and self.context.program:
            program_info = await self.manager.platform_integration.get_program_info(
                self.context.platform, 
                self.context.program
            )
            self.context.metadata['program_info'] = program_info
        
        # Initialize evidence collection
        self.context.evidence = {
            'screenshots': [],
            'requests': [],
            'responses': [],
            'timing_data': [],
            'verification_results': []
        }
    
    async def _reconnaissance(self):
        """Reconnaissance phase"""
        logger.info(f"Starting reconnaissance for {self.context.target}")
        
        # Get AI target analysis
        if self.manager.llm_service:
            analysis = await self.manager.llm_service.analyze_target(
                self.context.target,
                self.context.metadata.get('program_info')
            )
            self.context.metadata['ai_analysis'] = analysis
        
        # Discover endpoints
        from ..modules.recon_module import ReconModule
        recon = ReconModule(self.context)
        endpoints = await recon.discover_endpoints()
        
        # Classify endpoints with AI
        if self.manager.llm_service and endpoints:
            classified = await self.manager.llm_service.classify_endpoints(
                endpoints[:100]  # Limit for API
            )
            self.context.endpoints = classified
        else:
            self.context.endpoints = endpoints
        
        logger.info(f"Found {len(self.context.endpoints)} endpoints")
    
    async def _testing_phase_1(self):
        """Standard vulnerability testing"""
        logger.info("Starting standard vulnerability testing")
        
        # Test each endpoint with appropriate modules
        for endpoint in self.context.endpoints[:20]:  # Limit for demo
            for module_name, module in self.modules.items():
                if await module.can_test(endpoint):
                    findings = await module.test(endpoint)
                    
                    # Collect evidence for each finding
                    for finding in findings:
                        finding['evidence'] = await self._collect_evidence(finding)
                        self.context.findings.append(finding)
    
    async def _testing_phase_2(self):
        """Aggressive testing with WAF evasion"""
        if not self.context.config.get('aggressive_testing', {}).get('enabled', False):
            logger.info("Aggressive testing disabled, skipping phase 2")
            return
        
        logger.info("Starting aggressive testing with WAF evasion")
        
        # Use WAF evasion module on interesting endpoints
        from ..modules.waf_evasion_module import WAFEvasionModule
        waf_module = WAFEvasionModule(self.context)
        
        # Test high-value endpoints
        high_value_endpoints = [
            ep for ep in self.context.endpoints 
            if ep.get('interest_level') == 'high'
        ][:10]
        
        for endpoint in high_value_endpoints:
            findings = await waf_module.test_with_evasion(endpoint)
            for finding in findings:
                finding['evidence'] = await self._collect_evidence(finding)
                self.context.findings.append(finding)
    
    async def _testing_phase_3(self):
        """Specialized testing (API, JS analysis, etc.)"""
        logger.info("Starting specialized testing")
        
        # JavaScript analysis
        if self.context.config.get('js_analysis', {}).get('enabled', True):
            from ..modules.js_analysis_module import JSAnalysisModule
            js_module = JSAnalysisModule(self.context)
            js_findings = await js_module.analyze_javascript()
            self.context.findings.extend(js_findings)
        
        # API-specific testing
        api_endpoints = [
            ep for ep in self.context.endpoints 
            if 'api' in ep.get('url', '').lower()
        ]
        
        if api_endpoints:
            from ..modules.api_testing_module import APITestingModule
            api_module = APITestingModule(self.context)
            for endpoint in api_endpoints[:10]:
                findings = await api_module.test_api_endpoint(endpoint)
                self.context.findings.extend(findings)
    
    async def _verification(self):
        """Verify findings to reduce false positives"""
        logger.info(f"Verifying {len(self.context.findings)} findings")
        
        if not self.manager.verification_service:
            logger.warning("Verification service not available")
            return
        
        verified_findings = []
        for finding in self.context.findings:
            verification_result = await self.manager.verification_service.verify_finding(finding)
            
            if verification_result['verified']:
                finding['verification'] = verification_result
                finding['confidence'] = 'high'
                verified_findings.append(finding)
            else:
                finding['confidence'] = 'low'
                finding['false_positive_reason'] = verification_result.get('reason')
        
        # Update findings with only verified ones
        self.context.findings = verified_findings
        logger.info(f"Verified {len(verified_findings)} findings")
    
    async def _reporting(self):
        """Generate reports"""
        logger.info("Generating reports")
        
        if not self.manager.report_generator:
            logger.warning("Report generator not available")
            return
        
        # Generate different report formats
        reports = await self.manager.report_generator.generate_reports(
            self.context.findings,
            self.context.metadata,
            self.context.evidence
        )
        
        self.context.metadata['reports'] = reports
        
        # Auto-submit if configured
        if self.context.config.get('auto_submit', {}).get('enabled', False):
            await self._auto_submit_reports(reports)
    
    async def _auto_submit_reports(self, reports: Dict):
        """Auto-submit reports to platforms"""
        if not self.manager.platform_integration:
            return
        
        platform_report = reports.get('platform_report')
        if platform_report and self.context.platform:
            result = await self.manager.platform_integration.submit_report(
                self.context.platform,
                platform_report
            )
            self.context.metadata['submission_result'] = result
    
    async def _collect_evidence(self, finding: Dict) -> Dict:
        """Collect comprehensive evidence for a finding"""
        evidence = {
            'timestamp': datetime.now().isoformat(),
            'request': finding.get('request', {}),
            'response': finding.get('response', {}),
            'screenshots': [],
            'verification_steps': []
        }
        
        # Add request/response timing
        if 'response_time' in finding:
            evidence['timing'] = {
                'response_time': finding['response_time'],
                'timestamp': finding.get('timestamp')
            }
        
        # Store raw request/response for evidence
        if 'raw_request' in finding:
            evidence['raw_request'] = finding['raw_request']
        if 'raw_response' in finding:
            evidence['raw_response'] = finding['raw_response'][:5000]  # Limit size
        
        return evidence
    
    async def _load_modules(self):
        """Load vulnerability testing modules"""
        # Import modules based on config
        module_config = self.context.config.get('modules', {})
        
        if module_config.get('xss', {}).get('enabled', True):
            from ..modules.xss_module import XSSModule
            self.modules['xss'] = XSSModule(self.context)
        
        if module_config.get('sqli', {}).get('enabled', True):
            from ..modules.sqli_module import SQLiModule
            self.modules['sqli'] = SQLiModule(self.context)
        
        if module_config.get('ssrf', {}).get('enabled', True):
            from ..modules.ssrf_module import SSRFModule
            self.modules['ssrf'] = SSRFModule(self.context)
        
        logger.info(f"Loaded {len(self.modules)} testing modules")
    
    async def _emit_progress(self, phase: str, progress: int):
        """Emit progress update"""
        await self.manager._emit_event('hunt_progress', {
            'hunt_id': self.context.hunt_id,
            'phase': phase,
            'progress': progress,
            'message': f"Executing {phase}",
            'stats': {
                'endpoints': len(self.context.endpoints),
                'findings': len(self.context.findings),
                'duration': (datetime.now() - self.context.start_time).total_seconds()
            }
        })
    
    def get_progress(self) -> int:
        """Get current progress percentage"""
        return self.progress