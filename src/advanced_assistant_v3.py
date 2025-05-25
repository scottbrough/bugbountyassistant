#!/usr/bin/env python3
"""
Enhanced Personal Bug Bounty Assistant v3.0
Complete AI-powered bug bounty automation with revenue maximization
"""

import os
import sys
import json
import time
import subprocess
import argparse
import requests
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Any, cast
import openai
import asyncio
import threading
from urllib.parse import urlparse

# Import all modules
from platform_integration import PlatformIntegration, ScopeValidator
from aggressive_testing_waf_evasion import WAFEvasionTester, WAF_CONTINGENCY_GUIDE
from enhanced_vulnerability_testing import EnhancedVulnerabilityTester
from js_analysis_module import JavaScriptAnalyzer
from revenue_maximizer import RevenueMaximizer, CollaborationManager, AutoSubmitter
from continuous_monitor import ContinuousMonitor, ProgramWatcher
from api_testing_module import APITester

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"bb_hunt_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("enhanced_bb_assistant_v3")

class EnhancedBugBountyAssistantV3:
    """Enhanced Personal Bug Bounty Assistant with Revenue Maximization"""
    
    def __init__(self, api_key: str, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = {}
        self.client = openai.OpenAI(api_key=api_key)
        self.config = config
        self.target = None
        self.workspace = None
        self.findings = []
        self.chains = []
        self.session_data = {}
        self.program_info = {}
        self.scope_validator = None
        
        # Initialize all modules
        self.platform_integration = PlatformIntegration(self.config)
        self.vuln_tester = EnhancedVulnerabilityTester()
        self.aggressive_tester = WAFEvasionTester(self.config)
        self.js_analyzer = JavaScriptAnalyzer(self.client)
        self.api_tester = APITester(self.config)
        
        # Initialize revenue maximization modules
        self.revenue_maximizer = RevenueMaximizer()
        self.collaboration_manager = CollaborationManager()
        self.auto_submitter = AutoSubmitter(self.revenue_maximizer)
        self.continuous_monitor = ContinuousMonitor()
        self.program_watcher = ProgramWatcher(self.continuous_monitor)
        
        # Testing configuration
        self.aggressive_mode = self.config.get('aggressive_testing', {}).get('enabled', True)
        self.scope_validation_enabled = self.config.get('scope_validation', {}).get('enabled', True)
        self.auto_submit_enabled = self.config.get('auto_submit', {}).get('enabled', False)
        self.continuous_monitoring = self.config.get('continuous_monitoring', {}).get('enabled', True)
        
        # Start continuous monitoring if enabled
        if self.continuous_monitoring:
            self.continuous_monitor.start_monitoring()
        
        # Add notification handler for monitoring
        self.continuous_monitor.add_notification_handler(self._handle_monitoring_notification)
        
        logger.info("🚀 Enhanced Bug Bounty Assistant v3.0 initialized")
        logger.info("💰 Revenue maximization features enabled")
        
    def initialize_hunt(self, target: str, platform: str = '', program_handle: str = ''):
        """Initialize enhanced hunt with FIXED scope validation"""
        self.target = target
        self.workspace = Path(f"hunt_{target.replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.workspace.mkdir(exist_ok=True)
        
        logger.info(f"🎯 Starting enhanced hunt on {target}")
        logger.info(f"📁 Workspace: {self.workspace}")
        
        # Get program information if specified
        if platform and program_handle:
            logger.info(f"🔍 Fetching program info from {platform}")
            self.program_info = self.platform_integration.get_program_info(platform, program_handle)
            
            # FIXED: Only initialize scope validator if enabled AND we have valid program info
            if self.scope_validation_enabled and self.program_info and self.program_info.get('scope'):
                self.scope_validator = ScopeValidator(self.program_info)
                logger.info(f"🛡️ Scope validation enabled: {self.scope_validator.get_scope_summary()}")
            else:
                self.scope_validator = None
                logger.warning("⚠️ Scope validation disabled or no valid scope info")
        else:
            # Try to find programs for this target
            intelligence = self.platform_integration.get_target_intelligence(target)
            if intelligence['programs_found']:
                # Use revenue maximizer to pick best program
                prioritized = self.revenue_maximizer.prioritize_targets(intelligence['programs_found'])
                if prioritized:
                    self.program_info = prioritized[0]
                    logger.info(f"💡 Selected optimal program: {self.program_info.get('handle')} on {self.program_info.get('platform')} (ROI score: {self.program_info.get('roi_score', 0):.2f})")
                    
                    # FIXED: Only create scope validator if enabled AND we have scope info
                    if self.scope_validation_enabled and self.program_info.get('scope'):
                        self.scope_validator = ScopeValidator(self.program_info)
                    else:
                        self.scope_validator = None
                else:
                    self.program_info = {}
                    self.scope_validator = None
                    logger.info("ℹ️ No program information found - proceeding without scope validation")
            else:
                self.program_info = {}
                self.scope_validator = None
                logger.info("ℹ️ No program information found - proceeding without scope validation")
        
        # Add target to continuous monitoring
        if self.continuous_monitoring and self.program_info:
            platform_val = self.program_info.get('platform') or ''
            handle_val = self.program_info.get('handle') or ''
            self.continuous_monitor.add_monitoring_target(
                target, 
                platform_val,
                handle_val
            )
        
        # Check if we've tested this target recently
        recent_changes = self.continuous_monitor.get_recent_changes(24)
        if recent_changes:
            logger.info(f"🔄 Found {len(recent_changes)} recent changes on monitored targets")
        
        # Get revenue analytics
        analytics = self.revenue_maximizer.get_earnings_analytics()
        if analytics['total_earnings'] > 0:
            logger.info(f"💵 Career earnings: ${analytics['total_earnings']:.2f}")
            logger.info(f"📈 Success rate: {analytics['success_rate']*100:.1f}%")
            logger.info(f"⏱️ Hourly rate: ${analytics['hourly_rate']:.2f}/hr")
        
        # Save session metadata with CORRECT scope validation status
        self.session_data = {
            "target": target,
            "platform": platform,
            "program_handle": program_handle,
            "program_info": self.program_info,
            "start_time": datetime.now().isoformat(),
            "workspace": str(self.workspace),
            "findings": [],
            "chains": [],
            "reports": [],
            "aggressive_mode": self.aggressive_mode,
            "scope_validation": self.scope_validation_enabled and bool(self.scope_validator),  # FIXED
            "roi_score": self.program_info.get('roi_score', 0) if self.program_info else 0,
            "expected_earnings": self._estimate_earnings()
        }
        self._save_session()
        
    def _estimate_earnings(self) -> float:
        """Estimate potential earnings for this hunt"""
        if not self.program_info:
            return 0.0
        
        # Base estimate on program bounty range and historical success
        bounty_range = self.program_info.get('bounty_range', '')
        amounts = self.revenue_maximizer._extract_amounts(bounty_range)
        
        if amounts:
            avg_bounty = sum(amounts) / len(amounts)
            # Adjust by historical success rate
            analytics = self.revenue_maximizer.get_earnings_analytics()
            success_rate = analytics.get('success_rate', 0.1)
            
            # Estimate 5-10 findings
            estimated_findings = 7 * success_rate
            return avg_bounty * estimated_findings
        
        return 0.0
    
    def _assess_competition_level(self) -> str:
        """Assess competition level for the program (stub)"""
        # Placeholder: In a real implementation, this would use platform stats
        return "Unknown"

    def ai_target_analysis(self) -> Dict:
        """Enhanced AI-powered target analysis with revenue optimization"""
        logger.info("🧠 Analyzing target with AI...")
        
        # Get revenue optimization data
        revenue_data = ""
        if self.program_info:
            roi_score = self.program_info.get('roi_score', 0)
            revenue_data = f"""
            Revenue Analysis:
            - ROI Score: {roi_score:.2f}
            - Expected Earnings: ${self.session_data.get('expected_earnings', 0):.2f}
            - Competition Level: {self._assess_competition_level()}
            - Testing Schedule: {self.revenue_maximizer.optimize_testing_schedule().get('recommendations', [])}
            """
        
        # Check for recent changes
        recent_changes = self.continuous_monitor.get_recent_changes(168)  # Last week
        changes_context = ""
        if recent_changes:
            changes_context = f"""
            Recent Changes Detected:
            - {len(recent_changes)} changes in the last week
            - Focus on: {', '.join(set(c['change_type'] for c in recent_changes[:5]))}
            """
        
        prompt = f"""
        You are an expert bug bounty hunter analyzing a new target: {self.target}
        
        {self._get_program_context()}
        {revenue_data}
        {changes_context}
        
        Provide a comprehensive analysis including:
        1. Technology stack predictions based on domain/subdomain patterns
        2. Likely attack vectors to prioritize based on ROI
        3. API endpoints likely to exist (REST, GraphQL, etc)
        4. Mobile app API detection strategies
        5. Areas most likely to yield high-bounty findings
        6. Time-efficient testing approach (maximize $/hour)
        7. Collaboration opportunities (which findings to share)
        8. WAF detection expectations and evasion strategy
        9. Quick win opportunities (low effort, high reward)
        10. Long-term monitoring recommendations
        
        Focus on maximizing earnings per hour spent.
        
        Return your analysis as valid JSON with proper structure.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=2000
            )
            content = None
            if response and response.choices and response.choices[0].message and hasattr(response.choices[0].message, 'content'):
                content = response.choices[0].message.content
            if content and isinstance(content, str):
                if content.startswith("```json"):
                    content = content[7:]
                if content.endswith("```"):
                    content = content[:-3]
                try:
                    analysis = json.loads(content.strip()) if content else {}
                except json.JSONDecodeError:
                    analysis = {
                        "raw_analysis": content,
                        "technology_predictions": {"error": "JSON parsing failed"},
                        "attack_vectors": [],
                        "quick_wins": [],
                        "monitoring_recommendations": []
                    }
            else:
                analysis = {"raw_analysis": str(content), "error": "No content returned from AI"}
            # Add revenue insights
            if not isinstance(analysis, dict):
                analysis = {"raw_analysis": str(analysis)}
            if isinstance(analysis, dict):
                analysis['revenue_optimization'] = cast(Any, {
                    'roi_score': self.program_info.get('roi_score', 0) if self.program_info else 0,
                    'expected_hourly_rate': self._calculate_expected_hourly_rate(),
                    'optimal_testing_hours': self.revenue_maximizer.optimize_testing_schedule().get('best_hours', []),
                    'quick_wins': self._identify_quick_wins(analysis)
                })
            # Save analysis
            if self.workspace:
                analysis_file = self.workspace / "ai_analysis.json"
                try:
                    with open(analysis_file, 'w') as f:
                        json.dump(analysis, f, indent=2)
                except Exception as e:
                    logger.error(f"Failed to save AI analysis: {e}")
            logger.info("✅ Enhanced target analysis complete")
            return analysis
        except Exception as e:
            logger.error(f"❌ AI analysis failed: {e}")
            return {"error": str(e)}

    
    def intelligent_recon(self) -> Dict:
        """Enhanced reconnaissance with FIXED scope validation"""
        logger.info("🔍 Starting intelligent reconnaissance...")
        
        recon_results = {
            "subdomains": [],
            "endpoints": [],
            "technologies": [],
            "interesting_findings": [],
            "javascript_analysis": {},
            "scope_validation": {
                "in_scope_targets": [],
                "out_of_scope_targets": [],
                "validation_enabled": self.scope_validation_enabled
            }
        }
        
        # Subdomain enumeration
        logger.info("Finding subdomains...")
        subdomains = self._find_subdomains()
        
        # FIXED: Only apply scope validation if it's enabled AND we have valid program info
        if self.scope_validation_enabled and self.scope_validator and self.program_info:
            logger.info("🛡️ Applying scope validation...")
            in_scope_subdomains, out_of_scope_subdomains = self.scope_validator.validate_url_list(subdomains)
            recon_results["scope_validation"]["in_scope_targets"] = in_scope_subdomains
            recon_results["scope_validation"]["out_of_scope_targets"] = out_of_scope_subdomains
            recon_results["subdomains"] = in_scope_subdomains
            logger.info(f"🛡️ Scope validation: {len(in_scope_subdomains)} in scope, {len(out_of_scope_subdomains)} excluded")
        else:
            # No scope validation - test everything
            recon_results["subdomains"] = subdomains
            recon_results["scope_validation"]["in_scope_targets"] = subdomains
            logger.warning("⚠️ Scope validation disabled or no program info - testing all discovered targets")
        
        # Content discovery on validated targets
        logger.info("Discovering content...")
        # Include main target even if no subdomains found
        top_targets = [self.target or '']
        if recon_results["subdomains"]:
            top_targets.extend(recon_results["subdomains"][:5])
        
        for target in top_targets:
            if target:
                endpoints = self._discover_content(target)
                recon_results["endpoints"].extend(endpoints)
        
        # FIXED: Skip endpoint validation if scope validation is disabled
        if self.scope_validation_enabled and self.scope_validator and self.program_info:
            all_endpoint_urls = [ep.get('url', '') if isinstance(ep, dict) else str(ep) for ep in recon_results["endpoints"]]
            in_scope_urls, out_of_scope_urls = self.scope_validator.validate_url_list(all_endpoint_urls)
            
            # Filter endpoints to only in-scope ones
            filtered_endpoints = []
            for endpoint in recon_results["endpoints"]:
                endpoint_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if endpoint_url in in_scope_urls:
                    filtered_endpoints.append(endpoint)
            
            recon_results["endpoints"] = filtered_endpoints
        
        # AI-powered endpoint analysis
        logger.info("🧠 AI analyzing discovered endpoints...")
        if recon_results["endpoints"]:
            if hasattr(self, '_ai_classify_endpoints'):
                interesting_endpoints = self._ai_classify_endpoints(recon_results["endpoints"])
            else:
                interesting_endpoints = self._ai_classify_endpoints_revenue_focused(recon_results["endpoints"])
            recon_results["interesting_findings"] = interesting_endpoints
        else:
            logger.warning("⚠️ No endpoints found to analyze")
            recon_results["interesting_findings"] = []
        
        # Enhanced JavaScript analysis
        logger.info("🔍 Analyzing JavaScript files...")
        js_analysis = self.js_analyzer.discover_and_analyze_js(self.target or '', recon_results["endpoints"])
        recon_results["javascript_analysis"] = js_analysis
        
        # FIXED: Skip JS endpoint validation if scope validation is disabled
        if self.scope_validation_enabled and self.scope_validator and js_analysis.get("endpoints_discovered"):
            js_endpoints = [ep.get("endpoint", "") for ep in js_analysis["endpoints_discovered"]]
            full_js_urls = []
            for ep in js_endpoints:
                if ep.startswith('http'):
                    full_js_urls.append(ep)
                elif ep.startswith('/'):
                    full_js_urls.append(f"https://{self.target}{ep}")
                else:
                    full_js_urls.append(f"https://{self.target}/{ep}")
            
            in_scope_js, out_of_scope_js = self.scope_validator.validate_url_list(full_js_urls)
            recon_results["javascript_analysis"]["in_scope_endpoints"] = in_scope_js
            recon_results["javascript_analysis"]["out_of_scope_endpoints"] = out_of_scope_js
        
        # Save recon results
        if self.workspace:
            recon_file = self.workspace / "recon_results.json"
            try:
                with open(recon_file, 'w') as f:
                    json.dump(recon_results, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save recon results: {e}")
        else:
            logger.warning("Workspace is not set. Cannot save recon results.")
        logger.info(f"✅ Enhanced recon complete: {len(recon_results['endpoints'])} endpoints, {len(recon_results.get('interesting_findings', []))} interesting")
        return recon_results
    
    def ai_vulnerability_hunting(self, recon_data: Dict) -> List[Dict]:
        """Enhanced vulnerability hunting with revenue optimization"""
        logger.info("🎯 Starting enhanced vulnerability hunting...")
        
        findings = []
        tested_count = 0
        start_time = time.time()
        
        # Prioritize high-value targets
        interesting_endpoints = recon_data.get("interesting_findings", [])
        prioritized_endpoints = self._prioritize_endpoints_by_value(interesting_endpoints)
        
        # Test APIs first (usually higher bounties)
        for api_type, apis in recon_data.get("apis", {}).items():
            for api_info in apis:
                if api_type == 'graphql':
                    graphql_findings = self.api_tester.test_graphql_vulnerabilities(
                        api_info['info']['documentation_url']
                    )
                    findings.extend(graphql_findings)
                elif api_type == 'rest':
                    api_findings = self.api_tester.test_api_endpoints(
                        f"https://{api_info['subdomain']}",
                        self.api_tester.discovered_endpoints
                    )
                    findings.extend(api_findings)
                
                tested_count += 1
        
        # Test prioritized endpoints
        for endpoint in prioritized_endpoints[:20]:  # Limit for time efficiency
            logger.info(f"Testing: {endpoint['url']} (value score: {endpoint.get('value_score', 0):.2f})")
            endpoint_findings = []
            payloads = self._generate_ai_payloads(endpoint)
            
            # Test each payload
            for payload_data in payloads:
                # Check if similar vulnerability already reported
                is_duplicate, dup_info = self.revenue_maximizer.check_duplicate({
                    'type': payload_data.get('type'),
                    'url': endpoint['url'],
                    'parameter': payload_data.get('parameter')
                })
                
                if is_duplicate:
                    logger.warning(f"⚠️ Skipping potential duplicate: {payload_data.get('type')} on {endpoint['url']}")
                    continue
                
                if self.aggressive_mode:
                    result = self.aggressive_tester.test_payload_aggressive(endpoint['url'], payload_data)
                else:
                    result = self.vuln_tester.test_payload(endpoint['url'], payload_data)
                
                if result.get('vulnerable'):
                    result['discovery_method'] = 'endpoint_analysis'
                    result['estimated_bounty'] = self._estimate_finding_value(result)
                    endpoint_findings.append(result)
                    logger.info(f"🚨 Vulnerability found: {result['type']} in {endpoint['url']} (est. ${result['estimated_bounty']})")
            
            # Only add findings if they're worth reporting
            valuable_findings = [f for f in endpoint_findings if f.get('estimated_bounty', 0) > 50]
            findings.extend(valuable_findings)
            
            tested_count += 1
            
            # Time management - stop if taking too long
            elapsed_time = time.time() - start_time
            if elapsed_time > 3600:  # 1 hour limit
                logger.info("⏱️ Time limit reached, stopping vulnerability hunting")
                break
        
        # Test authentication if found
        auth_findings = self._test_authentication_endpoints(recon_data)
        findings.extend(auth_findings)
        
        # Calculate testing efficiency
        testing_time = time.time() - start_time
        findings_value = sum(f.get('estimated_bounty', 0) for f in findings)
        hourly_rate = (findings_value / testing_time) * 3600 if testing_time > 0 else 0
        
        logger.info(f"💰 Testing efficiency: ${hourly_rate:.2f}/hour")
        
        self.findings = findings
        
        # Save findings with revenue data
        if self.workspace:
            findings_file = self.workspace / "findings.json"
            try:
                with open(findings_file, 'w') as f:
                    json.dump({
                        'findings': findings,
                        'testing_metrics': {
                            'endpoints_tested': tested_count,
                            'time_spent_seconds': testing_time,
                            'estimated_value': findings_value,
                            'hourly_rate': hourly_rate
                        }
                    }, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save findings: {e}")
        else:
            logger.warning("Workspace is not set. Cannot save findings.")
        logger.info(f"✅ Enhanced vulnerability hunting complete: {len(findings)} findings worth ~${findings_value:.2f}")
        return findings
    
    def ai_chain_detection(self) -> List[Dict]:
        """Enhanced chain detection with bounty value estimation"""
        if not self.findings:
            logger.info("No findings to chain")
            return []
            
        logger.info("🔗 Analyzing vulnerability chains with AI...")
        
        prompt = f"""
        You are an expert bug bounty hunter analyzing vulnerabilities for potential chaining.
        Focus on chains that would maximize bounty payouts.
        
        Target: {self.target}
        {self._get_program_context()}
        
        Findings: {json.dumps(self.findings, indent=2)}
        
        Analyze these findings and identify:
        1. High-impact attack chains (prioritize critical business impact)
        2. Account takeover chains (usually highest bounties)
        3. Data exfiltration scenarios (PII = high bounties)
        4. Payment/financial system chains
        5. Admin access chains
        6. Cross-origin attack chains
        
        For each chain, provide:
        - Chain name and description
        - Step-by-step attack path
        - Business impact (focus on financial/data loss)
        - Estimated bounty range (based on similar reports)
        - Proof of concept outline
        - CVSS score estimation
        
        Prioritize chains by potential bounty value.
        
        Return as JSON object with 'chains' array.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7
            )
            content = None
            if response and response.choices and response.choices[0].message and hasattr(response.choices[0].message, 'content'):
                content = response.choices[0].message.content
            if content and isinstance(content, str):
                try:
                    result = json.loads(content)
                except Exception:
                    result = {"chains": []}
            else:
                result = {"chains": []}
            chains = result.get("chains", [])
            # Add bounty estimates
            for chain in chains:
                chain['estimated_bounty'] = self._estimate_chain_value(chain)
            # Sort by estimated value
            chains = sorted(chains, key=lambda x: x.get('estimated_bounty', 0), reverse=True)
            self.chains = chains
            # Save chains
            if self.workspace:
                chains_file = self.workspace / "vulnerability_chains.json"
                try:
                    with open(chains_file, 'w') as f:
                        json.dump(chains, f, indent=2)
                except Exception as e:
                    logger.error(f"Failed to save chains: {e}")
            logger.info(f"✅ Chain analysis complete: {len(chains)} chains worth ~${sum(c.get('estimated_bounty', 0) for c in chains):.2f}")
            return chains
        except Exception as e:
            logger.error(f"❌ Chain analysis failed: {e}")
            return []
    
    def auto_submit_findings(self) -> Dict:
        """Automatically submit validated findings"""
        logger.info("📤 Processing findings for submission...")
        
        submission_results = {
            'submitted': [],
            'queued': [],
            'rejected': [],
            'total_value': 0
        }
        
        # Process individual findings
        for finding in self.findings:
            if self.auto_submit_enabled and finding.get('confidence') == 'high':
                result = self.auto_submitter.queue_for_submission(
                    finding,
                    self.program_info,
                    self.platform_integration,
                    auto_submit=True
                )
                
                if result and result.get('success'):
                    submission_results['submitted'].append(result)
                    submission_results['total_value'] += finding.get('estimated_bounty', 0)
                else:
                    submission_results['queued'].append(finding)
            else:
                submission_results['queued'].append(finding)
        
        # Process high-value chains
        for chain in self.chains:
            if chain.get('estimated_bounty', 0) > 1000:
                # High-value chains always need manual review
                submission_results['queued'].append({
                    'type': 'chain',
                    'data': chain,
                    'reason': 'High-value chain requires manual review'
                })
        
        logger.info(f"📊 Submission summary: {len(submission_results['submitted'])} auto-submitted, {len(submission_results['queued'])} queued")
        
        return submission_results
    
    def generate_revenue_report(self) -> str:
        """Generate comprehensive revenue and efficiency report"""
        logger.info("💰 Generating revenue report...")
        
        # Get analytics
        analytics = self.revenue_maximizer.get_earnings_analytics()
        schedule = self.revenue_maximizer.optimize_testing_schedule()
        
        # Calculate hunt metrics - FIX for the time parsing error
        try:
            # Handle different datetime formats
            start_time_str = self.session_data['start_time']
            if '.' in start_time_str:
                # Has microseconds
                start_time_obj = datetime.strptime(start_time_str, "%Y-%m-%dT%H:%M:%S.%f")
            else:
                # No microseconds
                start_time_obj = datetime.strptime(start_time_str, "%Y-%m-%dT%H:%M:%S")
        except (ValueError, KeyError):
            # Fallback to current time minus 1 hour
            start_time_obj = datetime.now() - timedelta(hours=1)
            
        hunt_duration = time.time() - start_time_obj.timestamp()
        findings_value = sum(f.get('estimated_bounty', 0) for f in self.findings)
        chains_value = sum(c.get('estimated_bounty', 0) for c in self.chains)
        total_potential = findings_value + chains_value
        
        report = f"""# Revenue Report - {self.target}

## Hunt Summary
- **Duration:** {hunt_duration/3600:.1f} hours
- **Findings:** {len(self.findings)} vulnerabilities
- **Chains:** {len(self.chains)} attack chains
- **Potential Value:** ${total_potential:.2f}
- **Efficiency:** ${(total_potential/hunt_duration)*3600:.2f}/hour

## Career Statistics
- **Total Earnings:** ${analytics['total_earnings']:.2f}
- **Success Rate:** {analytics['success_rate']*100:.1f}%
- **Average Hourly Rate:** ${analytics['hourly_rate']:.2f}/hour
- **Best Platform:** {max(analytics['earnings_by_platform'].items(), key=lambda x: x[1])[0] if analytics['earnings_by_platform'] else 'N/A'}

## Top Earning Vulnerability Types
{chr(10).join(f"- {vtype}: ${amount:.2f} ({count} findings)" for vtype, amount, count in analytics['earnings_by_type'][:5])}

## Optimal Testing Schedule
- **Best Hours:** {', '.join(schedule['best_hours'])}
- **Best Days:** {', '.join(schedule['best_days'])}

## Recommendations
{chr(10).join(f"- {rec}" for rec in analytics['recommendations'])}

## Next Target Suggestion
{self._get_next_target_suggestion()}
"""
        
        # Save report
        if self.workspace:
            revenue_report_file = self.workspace / "revenue_report.md"
            try:
                with open(revenue_report_file, 'w') as f:
                    f.write(report)
            except Exception as e:
                logger.error(f"Failed to save revenue report: {e}")
        else:
            logger.warning("Workspace is not set. Cannot save revenue report.")
        return report
    
    def run_full_enhanced_hunt(self, target: str, platform: str = '', program_handle: str = '') -> Dict:
        """Run the complete enhanced bug bounty hunting workflow with revenue optimization"""
        start_time = time.time()
        
        try:
            # Initialize with platform integration
            self.initialize_hunt(target or '', platform or '', program_handle or '')
            
            # Check if target is worth testing
            if self.program_info and self.program_info.get('roi_score', 0) < 10:
                logger.warning(f"⚠️ Low ROI score ({self.program_info.get('roi_score', 0):.2f}) - consider different target")
            
            # Display revenue optimization info
            if self.revenue_maximizer:
                next_target = self.revenue_maximizer.suggest_next_target([self.program_info]) if self.program_info else None
                if next_target and next_target != self.program_info:
                    logger.info(f"💡 Consider testing {next_target['handle']} instead (ROI: {next_target.get('roi_score', 0):.2f})")
            
            # Phase 1: Enhanced AI Analysis
            analysis = self.ai_target_analysis()
            print(f"\n🎯 Enhanced Target Analysis Complete")
            if analysis.get('revenue_optimization'):
                rev_opt = analysis['revenue_optimization']
                print(f"   💰 Expected hourly rate: ${rev_opt.get('expected_hourly_rate', 0):.2f}/hr")
                print(f"   🎯 Quick wins identified: {len(rev_opt.get('quick_wins', []))}")
            
            # Phase 2: Enhanced Reconnaissance
            recon_data = self.intelligent_recon()
            print(f"\n🔍 Enhanced Reconnaissance Complete")
            print(f"   🌐 Subdomains: {len(recon_data['subdomains'])}")
            print(f"   🔗 Endpoints: {len(recon_data['endpoints'])}")
            print(f"   🚀 APIs found: {sum(len(v) for v in recon_data['apis'].values())}")
            
            # Phase 3: Revenue-Optimized Vulnerability Hunting
            findings = self.ai_vulnerability_hunting(recon_data)
            print(f"\n🎯 Vulnerability Hunting Complete")
            print(f"   🚨 Findings: {len(findings)}")
            print(f"   💵 Estimated value: ${sum(f.get('estimated_bounty', 0) for f in findings):.2f}")
            
            # Phase 4: Chain Detection
            chains = self.ai_chain_detection()
            print(f"\n🔗 Chain Analysis Complete")
            print(f"   ⛓️ Chains: {len(chains)}")
            print(f"   💰 Chain value: ${sum(c.get('estimated_bounty', 0) for c in chains):.2f}")
            
            # Phase 5: Auto-submission
            submission_results = self.auto_submit_findings()
            print(f"\n📤 Submission Processing Complete")
            print(f"   ✅ Auto-submitted: {len(submission_results['submitted'])}")
            print(f"   📋 Queued for review: {len(submission_results['queued'])}")
            
            # Phase 6: Revenue Report
            revenue_report = self.generate_revenue_report()
            
            # Phase 7: Collaboration Check
            collab_opportunities = self._identify_collaboration_opportunities()
            if collab_opportunities:
                print(f"\n🤝 Collaboration Opportunities: {len(collab_opportunities)}")
            
            # Final summary
            duration = time.time() - start_time
            total_value = sum(f.get('estimated_bounty', 0) for f in findings) + sum(c.get('estimated_bounty', 0) for c in chains)
            
            print(f"\n🎉 Enhanced Hunt Complete!")
            print(f"   ⏱️ Duration: {duration/60:.1f} minutes")
            print(f"   💰 Potential earnings: ${total_value:.2f}")
            print(f"   📈 Efficiency: ${(total_value/duration)*3600:.2f}/hour")
            print(f"   📁 Workspace: {self.workspace}")
            
            # Next steps
            print(f"\n📋 Next Steps:")
            print(f"   1. Review queued submissions in {self.workspace}")
            print(f"   2. Submit high-confidence findings immediately")
            if collab_opportunities:
                print(f"   3. Consider collaboration on complex findings")
            print(f"   4. Monitor target for changes (auto-enabled)")
            
            # Return comprehensive results
            return {
                'success': True,
                'target': target,
                'duration_minutes': duration / 60,
                'findings_count': len(findings),
                'chains_count': len(chains),
                'potential_earnings': total_value,
                'hourly_rate': (total_value/duration)*3600 if duration > 0 else 0,
                'workspace': str(self.workspace) if self.workspace else None,
                'program_info': self.program_info,
                'submission_results': submission_results,
                'roi_score': self.program_info.get('roi_score', 0) if self.program_info else 0
            }
        except Exception as e:
            logger.error(f"❌ Enhanced hunt failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'workspace': str(self.workspace) if self.workspace else None
            }
    
    # Helper methods
    def _get_program_context(self) -> str:
        """Get program context for prompts"""
        if not self.program_info:
            return ""
        
        return f"""
        Program Information:
        - Platform: {self.program_info.get('platform')}
        - Program: {self.program_info.get('name', self.program_info.get('handle'))}
        - Bounty Range: {self.program_info.get('bounty_range', 'Unknown')}
        - Scope: {len(self.program_info.get('scope', {}).get('in_scope', []))} targets in scope
        - Managed: {self.program_info.get('managed', False)}
        """
    
    def _calculate_expected_hourly_rate(self) -> float:
        """Calculate expected hourly rate for this target"""
        analytics = self.revenue_maximizer.get_earnings_analytics()
        base_rate = analytics.get('hourly_rate', 50)
        
        # Adjust based on program characteristics
        if self.program_info:
            if self.program_info.get('managed'):
                base_rate *= 1.2  # Managed programs typically pay faster
            
            roi_score = self.program_info.get('roi_score', 50)
            rate_multiplier = roi_score / 50  # Normalize around average
            
            return base_rate * rate_multiplier
        
        return base_rate
    
    def _identify_quick_wins(self, analysis: Dict) -> List[Dict]:
        """Identify quick win opportunities"""
        quick_wins = []
        
        # Default quick wins
        quick_win_patterns = [
            {'type': 'Exposed API docs', 'endpoint': '/swagger', 'effort': 'low', 'bounty': 'medium'},
            {'type': 'GraphQL introspection', 'endpoint': '/graphql', 'effort': 'low', 'bounty': 'medium'},
            {'type': 'Exposed .git', 'endpoint': '/.git/config', 'effort': 'low', 'bounty': 'medium'},
            {'type': 'API key in JS', 'endpoint': '/js/', 'effort': 'low', 'bounty': 'high'},
            {'type': 'Default credentials', 'endpoint': '/admin', 'effort': 'low', 'bounty': 'high'}
        ]
        
        return quick_win_patterns[:3]
    
    def _prioritize_endpoints_by_value(self, endpoints: List[Dict]) -> List[Dict]:
        """Prioritize endpoints by potential bounty value"""
        for endpoint in endpoints:
            score = 0
            url = endpoint.get('url', '').lower()
            
            # High-value patterns
            if any(pattern in url for pattern in ['admin', 'payment', 'auth', 'api/user']):
                score += 10
            if any(pattern in url for pattern in ['upload', 'file', 'import']):
                score += 8
            if any(pattern in url for pattern in ['graphql', 'api/v']):
                score += 7
            if any(pattern in url for pattern in ['config', 'setting', 'account']):
                score += 5
            
            endpoint['value_score'] = score
        
        return sorted(endpoints, key=lambda x: x.get('value_score', 0), reverse=True)
    
    def _estimate_finding_value(self, finding: Dict) -> float:
        """Estimate bounty value for a finding"""
        if not self.program_info:
            return 100  # Default estimate
        
        # Base values by severity
        base_values = {
            'critical': 2000,
            'high': 800,
            'medium': 300,
            'low': 100,
            'info': 0
        }
        
        severity = finding.get('severity', 'medium')
        base_value = base_values.get(severity, 100)
        
        # Adjust by vulnerability type
        vuln_type = finding.get('type', '').lower()
        if 'rce' in vuln_type or 'remote code' in vuln_type:
            base_value *= 2.5
        elif 'sql' in vuln_type:
            base_value *= 1.8
        elif 'ssrf' in vuln_type:
            base_value *= 1.5
        elif 'xss' in vuln_type and 'stored' in vuln_type:
            base_value *= 1.3
        
        # Adjust by program bounty range
        bounty_range = self.program_info.get('bounty_range', '')
        if '$10000' in bounty_range or '$20000' in bounty_range:
            base_value *= 2
        elif '$5000' in bounty_range:
            base_value *= 1.5
        
        return base_value
    
    def _estimate_chain_value(self, chain: Dict) -> float:
        """Estimate bounty value for a vulnerability chain"""
        # Chains typically pay 2-3x individual vulnerabilities
        impact = chain.get('impact', '').lower()
        
        if 'takeover' in impact or 'account' in impact:
            return 5000
        elif 'data' in impact or 'exfiltration' in impact:
            return 3000
        elif 'privilege' in impact or 'escalation' in impact:
            return 2000
        else:
            return 1000
    
    def _calculate_recon_revenue_potential(self, recon_data: Dict) -> Dict:
        """Calculate revenue potential from recon data"""
        potential = {
            'endpoints_value': len(recon_data['endpoints']) * 10,
            'apis_value': sum(len(v) for v in recon_data['apis'].values()) * 100,
            'js_secrets_value': len(recon_data.get('javascript_analysis', {}).get('secrets_found', [])) * 200,
            'total_potential': 0
        }
        
        potential['total_potential'] = sum(v for k, v in potential.items() if k != 'total_potential')
        
        return potential
    
    def _test_authentication_endpoints(self, recon_data: Dict) -> List[Dict]:
        findings = []
        auth_endpoints = []
        from urllib.parse import urlparse
        # Find auth endpoints
        for endpoint in recon_data.get('endpoints', []):
            url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
            if any(pattern in url.lower() for pattern in ['login', 'auth', 'signin', 'oauth', 'token']):
                auth_endpoints.append(url)
        
        # Test each auth endpoint
        for auth_url in auth_endpoints[:5]:  # Limit for efficiency
            # Detect auth type
            parsed_url = urlparse(auth_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            api_info = self.api_tester.detect_api_type(base_url)
            auth_findings = self.api_tester.test_authentication_vulnerabilities(
                base_url, 
                api_info.get('auth_type', 'unknown')
            )
            
            for finding in auth_findings:
                finding['estimated_bounty'] = self._estimate_finding_value(finding)
            
            findings.extend(auth_findings)
        
        return findings
    
    def _identify_collaboration_opportunities(self) -> List[Dict]:
        """Identify findings suitable for collaboration"""
        opportunities = []
        
        # Complex chains often benefit from collaboration
        for chain in self.chains:
            if len(chain.get('steps', [])) > 3 or chain.get('estimated_bounty', 0) > 2000:
                collaborators = self.collaboration_manager.find_collaborators(
                    chain.get('type', 'complex_chain')
                )
                
                if collaborators:
                    opportunities.append({
                        'finding': chain,
                        'collaborators': collaborators,
                        'reason': 'Complex chain requiring specialized skills'
                    })
        
        # Findings requiring specific expertise
        for finding in self.findings:
            if finding.get('type') in ['Cryptographic Issue', 'Race Condition', 'Business Logic']:
                collaborators = self.collaboration_manager.find_collaborators(finding['type'])
                
                if collaborators:
                    opportunities.append({
                        'finding': finding,
                        'collaborators': collaborators,
                        'reason': f'Specialized {finding["type"]} expertise needed'
                    })
        
        return opportunities
    
    def _get_next_target_suggestion(self) -> str:
        """Get suggestion for next target to test"""
        # Get programs from platforms
        available_programs = []
        
        # In practice, this would fetch from platform APIs
        # For now, return generic suggestion
        suggestion = self.revenue_maximizer.suggest_next_target(available_programs)
        
        if suggestion:
            return f"Test {suggestion['handle']} on {suggestion['platform']} next (ROI: {suggestion.get('roi_score', 0):.2f})"
        
        return "Check platform dashboards for new high-value programs"
    
    def _save_session(self):
        if self.workspace:
            session_file = self.workspace / "session.json"
            try:
                with open(session_file, 'w') as f:
                    json.dump(self.session_data, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save session: {e}")
        else:
            logger.warning("Workspace is not set. Cannot save session.")

    def _ai_classify_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """Use AI to classify interesting endpoints with batch processing and rate limiting"""
        if not endpoints:
            return []
        
        logger.info(f"Starting batch AI classification for {len(endpoints)} endpoints")
        
        max_endpoints = 500
        if len(endpoints) > max_endpoints:
            logger.warning(f"Limiting endpoints for classification to {max_endpoints} (from {len(endpoints)})")
            # Prioritize interesting endpoints
            interesting = [e for e in endpoints if e.get("interesting", False)]
            non_interesting = [e for e in endpoints if not e.get("interesting", False)]
            
            if len(interesting) > max_endpoints:
                endpoints = interesting[:max_endpoints]
            else:
                remaining = max_endpoints - len(interesting)
                endpoints = interesting + non_interesting[:remaining]
        
        # Process in smaller batches to avoid token limits
        batch_size = self.config.get('openai', {}).get('batch_size', 50)  # Default to 50, reduced from 100
        batches = [endpoints[i:i+batch_size] for i in range(0, len(endpoints), batch_size)]
        classified_endpoints = []
        
        for i, batch in enumerate(batches):
            logger.info(f"Processing batch {i+1}/{len(batches)} ({len(batch)} endpoints)")
            try:
                prompt = f"""
                Analyze these discovered endpoints and identify the most interesting ones for bug bounty hunting:
                {json.dumps(batch, indent=2)}
                
                For each endpoint, provide:
                1. interest_level: "high", "medium", or "low"
                2. potential_vulnerabilities: array of vulnerability types that might be present
                
                Focus on endpoints that might expose:
                - Admin/management interfaces
                - File upload/download capabilities  
                - API endpoints with parameters
                - Authentication mechanisms
                - Configuration files
                - Development artifacts
                
                Return a JSON object with 'endpoints' array containing the classified endpoints.
                """
                
                response = self.client.chat.completions.create(
                    model=self.config.get('openai', {}).get('model', "gpt-3.5-turbo"),  # Use 3.5 to reduce token usage
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.2,
                    max_tokens=self.config.get('openai', {}).get('max_tokens_per_request', 2000)  # Reduced token limit
                )
                
                content = response.choices[0].message.content if response and response.choices and response.choices[0].message else None
                if content:
                    try:
                        result = json.loads(content)
                        batch_result = result.get("endpoints", [])
                        if not batch_result and isinstance(result, list):
                            batch_result = result
                        
                        classified_endpoints.extend(batch_result if batch_result else batch)
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse AI response for batch {i+1}, using defaults")
                        classified_endpoints.extend(batch)
                else:
                    classified_endpoints.extend(batch)
                    
            except Exception as e:
                logger.error(f"Error in AI classification for batch {i+1}: {e}")
                for endpoint in batch:
                    endpoint["interest_level"] = "medium" if endpoint.get("interesting", False) else "low"
                    endpoint["potential_vulnerabilities"] = []
                classified_endpoints.extend(batch)
            
            if i < len(batches) - 1:
                time.sleep(self.config.get('openai', {}).get('rate_limit_delay', 2))
        
        logger.info(f"Completed AI classification for {len(classified_endpoints)} endpoints")
        return classified_endpoints

    def _ai_classify_endpoints_revenue_focused(self, endpoints: List[Dict]) -> List[Dict]:
        """Classify endpoints with focus on revenue potential"""
        if not endpoints:
            return []
        prompt = f"""
        Analyze these discovered endpoints and identify the most valuable ones for bug bounty hunting.
        Focus on endpoints likely to have high-impact vulnerabilities.
        {json.dumps(endpoints[:50], indent=2)}
        Return the top 15 most valuable endpoints with:
        - vulnerability types likely to yield high bounties
        - estimated bounty range for each vulnerability type
        - attack vectors to try
        - priority level (1-10)
        Format: JSON with 'interesting_endpoints' array
        """
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5
            )
            content = response.choices[0].message.content if response and response.choices and response.choices[0].message else None
            if content and isinstance(content, str):
                try:
                    result = json.loads(content)
                    return result.get("interesting_endpoints", [])
                except Exception:
                    return endpoints[:10]
            else:
                return endpoints[:10]
        except Exception as e:
            logger.error(f"AI endpoint classification failed: {e}")
            return endpoints[:10]

    def _generate_ai_payloads(self, endpoint: Dict) -> List[Dict]:
        """Generate AI-powered test payloads for an endpoint"""
        prompt = f"""
        Generate test payloads for this endpoint:
        URL: {endpoint['url']}
        Status: {endpoint.get('status')}
        Context: {endpoint.get('title', '')}
        Generate 10-15 targeted payloads focusing on HIGH-VALUE vulnerabilities:
        - Account takeover vectors
        - SQL injection (especially on user/admin endpoints)
        - Authentication bypass
        - IDOR with privilege escalation
        - XXE and SSRF (if XML/URL parameters detected)
        - File upload vulnerabilities
        - JWT manipulation
        Return as a JSON array with this structure:
        [
            {{
                "type": "vulnerability_type",
                "parameter": "parameter_name",
                "payload": "actual_payload",
                "estimated_bounty": 1000
            }}
        ]
        """
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.8,
                max_tokens=1500
            )
            content = response.choices[0].message.content if response and response.choices and response.choices[0].message else None
            if content and isinstance(content, str):
                if content.startswith("```json"):
                    content = content[7:]
                if content.endswith("```"):
                    content = content[:-3]
                try:
                    result = json.loads(content.strip()) if content else []
                    if isinstance(result, dict) and 'payloads' in result:
                        return result['payloads']
                    elif isinstance(result, list):
                        return result
                    else:
                        raise ValueError("Unexpected response format")
                except (json.JSONDecodeError, ValueError):
                    logger.warning("Failed to parse AI payloads, using defaults")
                    return [
                        {
                            'type': 'xss',
                            'payload': '<script>alert("XSS_TEST")</script>',
                            'parameter': 'input',
                            'estimated_bounty': 500
                        },
                        {
                            'type': 'sqli',
                            'payload': "' OR '1'='1",
                            'parameter': 'id',
                            'estimated_bounty': 1000
                        }
                    ]
            else:
                return []
        except Exception as e:
            logger.error(f"AI payload generation failed: {e}")
            return []
    
    def _find_subdomains(self) -> List[str]:
        import socket
        subdomains = set()
        # Using subfinder if available
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target or '', "-silent"],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '.' in line and not line.startswith('.'):
                        subdomains.add(line)
        except Exception as e:
            logger.debug(f"Subfinder failed: {e}")
        # Using amass if available
        try:
            result = subprocess.run(
                ["amass", "enum", "-passive", "-d", self.target or ''],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '.' in line and not line.startswith('.'):
                        subdomains.add(line)
        except Exception as e:
            logger.debug(f"Amass failed: {e}")
        # DNS bruteforce with common subdomains
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging', 
            'api-dev', 'api-staging', 'mobile', 'app', 'backend', 'internal',
            'portal', 'secure', 'vpn', 'remote', 'webmail', 'smtp', 'pop',
            'imap', 'blog', 'shop', 'store', 'cdn', 'media', 'static',
            'assets', 'img', 'images', 'video', 'help', 'support', 'docs',
            'documentation', 'wiki', 'git', 'gitlab', 'jenkins', 'jira'
        ]
        for sub in common_subs:
            try:
                subdomain = f"{sub}.{self.target or ''}"
                socket.gethostbyname(subdomain)
                subdomains.add(subdomain)
                logger.debug(f"Found subdomain via DNS: {subdomain}")
            except socket.gaierror:
                pass
            except Exception as e:
                logger.debug(f"DNS check failed for {sub}.{self.target}: {e}")
        valid_subdomains = []
        for subdomain in subdomains:
            if subdomain and subdomain != self.target and self._is_valid_subdomain(subdomain):
                valid_subdomains.append(subdomain)
        logger.info(f"📋 Found {len(valid_subdomains)} valid subdomains")
        return valid_subdomains[:30]

    def _discover_content(self, target: str) -> List[Dict]:
        """Enhanced content discovery with timeout and error handling"""
        import requests
        import time
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        endpoints = []
        
        common_paths = [
            '/', '/admin', '/api', '/api/v1', '/api/v2', '/api/v3',
            '/login', '/dashboard', '/config', '/backup', '/test',
            '/dev', '/staging', '/uploads', '/files', '/docs',
            '/swagger', '/swagger-ui', '/api-docs', '/graphql',
            '/robots.txt', '/sitemap.xml', '/.env', '/.git',
            '/wp-admin', '/phpmyadmin', '/payment', '/checkout',
            '/user', '/users', '/profile', '/account', '/settings',
            '/.gitlab-ci.yml', '/wp-config.php', '/config.php',
            '/server-status', '/phpinfo.php', '/info.php',
            '/.svn/entries', '/.DS_Store', '/backup.zip', '/dump.sql'
        ]
        
        def check_path(path):
            url = f"https://{target}{path}"
            try:
                response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                # Enhanced interestingness detection
                interesting = False
                interesting_reason = "Default"
                
                if response.status_code in (200, 201, 202, 203, 204):
                    interesting = True
                    interesting_reason = f"Accessible endpoint: {response.status_code}"
                elif response.status_code in (401, 403):
                    interesting = True
                    interesting_reason = f"Protected resource: {response.status_code}"
                elif any(keyword in path.lower() for keyword in ['.env', '.git', 'admin', 'config', 'backup', 'api']):
                    interesting = True
                    interesting_reason = f"Sensitive path detected: {path}"
                
                return {
                    "url": url,
                    "status": response.status_code,
                    "length": len(response.content),
                    "title": self._extract_title(response.text),
                    "headers": dict(response.headers),
                    "interesting": interesting,
                    "interesting_reason": interesting_reason,
                    "content_type": response.headers.get("Content-Type", "")
                }
            except Exception as e:
                logger.debug(f"Failed to fetch {url}: {e}")
                return None
        
        max_workers = 5  # Limit concurrent requests
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {executor.submit(check_path, path): path for path in common_paths}
            
            for future in as_completed(future_to_path):
                result = future.result()
                if result:
                    endpoints.append(result)
                
                time.sleep(0.1)
        
        logger.info(f"Content discovery completed for {target}: {len(endpoints)} endpoints found")
        return endpoints
    
    def _extract_title(self, html: str) -> str:
        import re
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ''
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        import re
        if not subdomain or len(subdomain) > 253:
            return False
        if not self.target or self.target not in subdomain:
            return False
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(pattern, subdomain):
            return False
        labels = subdomain.split('.')
        for label in labels:
            if not label or len(label) > 63:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
        return True
    
    def _handle_monitoring_notification(self, notification: Any):
        """Handle notifications from continuous monitoring (stub for now)"""
        logger.info(f"[Monitor Notification] {notification}")
