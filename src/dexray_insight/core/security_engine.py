#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from typing import Dict, List, Any
from dataclasses import dataclass
from collections import defaultdict

from .base_classes import BaseSecurityAssessment, SecurityFinding, AnalysisSeverity, registry
from .configuration import Configuration

@dataclass
class SecurityAssessmentResults:
    """Results from OWASP Top 10 security assessment"""
    findings: List[SecurityFinding]
    summary: Dict[str, Any]
    overall_risk_score: float
    owasp_categories_affected: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'findings': [finding.__dict__ for finding in self.findings],
            'summary': self.summary,
            'overall_risk_score': self.overall_risk_score,
            'owasp_categories_affected': self.owasp_categories_affected,
            'total_findings': len(self.findings),
            'findings_by_severity': self._group_by_severity()
        }
    
    def to_json(self) -> str:
        """Convert security results to JSON string for file output"""
        import json
        return json.dumps(self.to_dict(), indent=4, default=str)
    
    def _group_by_severity(self) -> Dict[str, int]:
        """Group findings by severity level"""
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
        return dict(severity_counts)

class SecurityAssessmentEngine:
    """Engine for coordinating OWASP Top 10 security assessments"""
    
    def __init__(self, config: Configuration):
        self.config = config
        self.security_config = config.get_security_config()
        self.logger = logging.getLogger(__name__)
        self.assessments = self._load_assessments()
    
    def assess(self, analysis_results: Dict[str, Any]) -> SecurityAssessmentResults:
        """
        Perform comprehensive security assessment using OWASP Top 10
        
        Args:
            analysis_results: Combined results from all analysis modules
            
        Returns:
            SecurityAssessmentResults with all security findings
        """
        all_findings = []
        assessment_summary = {}
        
        self.logger.info("Starting OWASP Top 10 security assessment")
        
        for assessment_name, assessment in self.assessments.items():
            if not assessment.is_enabled():
                self.logger.info(f"Assessment {assessment_name} is disabled, skipping")
                continue
            
            try:
                self.logger.info(f"Running {assessment_name} assessment")
                findings = assessment.assess(analysis_results)
                
                all_findings.extend(findings)
                assessment_summary[assessment_name] = {
                    'findings_count': len(findings),
                    'owasp_category': assessment.get_owasp_category(),
                    'status': 'completed'
                }
                
                self.logger.info(f"{assessment_name} completed with {len(findings)} findings")
                
                # Print findings to terminal with details
                if findings:
                    for finding in findings:
                        print(f"[+] {finding.category} - {finding.title}")
                        if hasattr(finding, 'location') and finding.location:
                            print(f"    Location: {finding.location}")
                        if hasattr(finding, 'description') and finding.description:
                            # Truncate description for terminal output
                            desc = finding.description[:100] + "..." if len(finding.description) > 100 else finding.description
                            print(f"    Description: {desc}")
                
            except Exception as e:
                self.logger.error(f"Assessment {assessment_name} failed: {str(e)}")
                assessment_summary[assessment_name] = {
                    'findings_count': 0,
                    'owasp_category': assessment.get_owasp_category(),
                    'status': 'failed',
                    'error': str(e)
                }
        
        # Calculate overall risk score and create summary
        overall_risk_score = self._calculate_risk_score(all_findings)
        owasp_categories = list(set(finding.category for finding in all_findings))
        
        summary = {
            'total_assessments_run': len([a for a in assessment_summary.values() if a['status'] == 'completed']),
            'total_assessments_failed': len([a for a in assessment_summary.values() if a['status'] == 'failed']),
            'assessments': assessment_summary,
            'risk_distribution': self._calculate_risk_distribution(all_findings)
        }
        
        results = SecurityAssessmentResults(
            findings=all_findings,
            summary=summary,
            overall_risk_score=overall_risk_score,
            owasp_categories_affected=owasp_categories
        )
        
        self.logger.info(f"Security assessment completed with {len(all_findings)} total findings, risk score: {overall_risk_score:.2f}")
        
        # Print summary to terminal
        if all_findings:
            print("\n[+] Security Assessment Summary:")
            print(f"    Total findings: {len(all_findings)}")
            print(f"    Risk score: {overall_risk_score:.2f}")
            print(f"    OWASP categories affected: {', '.join(owasp_categories)}")
        else:
            print("\n[+] Security Assessment completed with no findings")
        
        return results
    
    def _load_assessments(self) -> Dict[str, BaseSecurityAssessment]:
        """Load and initialize all enabled security assessments"""
        assessments = {}
        assessment_configs = self.security_config.get('assessments', {})
        
        # Get all registered assessments
        for assessment_name in registry.list_assessments():
            assessment_class = registry.get_assessment(assessment_name)
            if not assessment_class:
                continue
            
            assessment_config = assessment_configs.get(assessment_name, {})
            
            # Create assessment instance
            try:
                assessment = assessment_class(assessment_config)
                assessments[assessment_name] = assessment
                self.logger.info(f"Loaded assessment: {assessment_name} ({assessment.get_owasp_category()})")
            except Exception as e:
                self.logger.error(f"Failed to load assessment {assessment_name}: {str(e)}")
        
        return assessments
    
    def _calculate_risk_score(self, findings: List[SecurityFinding]) -> float:
        """
        Calculate overall risk score based on findings
        
        Risk score is calculated as:
        - Critical: 10 points each
        - High: 7 points each
        - Medium: 4 points each
        - Low: 1 point each
        
        Max score is normalized to 100
        """
        if not findings:
            return 0.0
        
        severity_weights = {
            AnalysisSeverity.CRITICAL: 10,
            AnalysisSeverity.HIGH: 7,
            AnalysisSeverity.MEDIUM: 4,
            AnalysisSeverity.LOW: 1
        }
        
        total_score = sum(severity_weights.get(finding.severity, 0) for finding in findings)
        
        # Normalize to 0-100 scale (assuming max of 50 critical findings as worst case)
        max_possible_score = 50 * severity_weights[AnalysisSeverity.CRITICAL]
        normalized_score = min(100.0, (total_score / max_possible_score) * 100)
        
        return round(normalized_score, 2)
    
    def _calculate_risk_distribution(self, findings: List[SecurityFinding]) -> Dict[str, Dict[str, int]]:
        """Calculate risk distribution by severity and OWASP category"""
        distribution = {
            'by_severity': defaultdict(int),
            'by_category': defaultdict(int),
            'by_category_and_severity': defaultdict(lambda: defaultdict(int))
        }
        
        for finding in findings:
            severity = finding.severity.value
            category = finding.category
            
            distribution['by_severity'][severity] += 1
            distribution['by_category'][category] += 1
            distribution['by_category_and_severity'][category][severity] += 1
        
        # Convert defaultdicts to regular dicts for JSON serialization
        return {
            'by_severity': dict(distribution['by_severity']),
            'by_category': dict(distribution['by_category']),
            'by_category_and_severity': {
                cat: dict(sevs) for cat, sevs in distribution['by_category_and_severity'].items()
            }
        }
    
    def get_assessment_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all available assessments"""
        status = {}
        
        for assessment_name, assessment in self.assessments.items():
            status[assessment_name] = {
                'enabled': assessment.is_enabled(),
                'owasp_category': assessment.get_owasp_category(),
                'class_name': assessment.__class__.__name__
            }
        
        return status
    
    def run_specific_assessment(self, assessment_name: str, analysis_results: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Run a specific security assessment
        
        Args:
            assessment_name: Name of the assessment to run
            analysis_results: Analysis results to assess
            
        Returns:
            List of security findings from the specific assessment
        """
        if assessment_name not in self.assessments:
            raise ValueError(f"Assessment {assessment_name} not found")
        
        assessment = self.assessments[assessment_name]
        if not assessment.is_enabled():
            self.logger.warning(f"Assessment {assessment_name} is disabled")
            return []
        
        try:
            findings = assessment.assess(analysis_results)
            self.logger.info(f"Assessment {assessment_name} completed with {len(findings)} findings")
            return findings
        except Exception as e:
            self.logger.error(f"Assessment {assessment_name} failed: {str(e)}")
            raise
    
    def get_owasp_coverage(self) -> Dict[str, bool]:
        """Get OWASP Top 10 coverage based on available assessments"""
        owasp_top_10_2021 = {
            'A01:2021-Broken Access Control': False,
            'A02:2021-Cryptographic Failures': False,
            'A03:2021-Injection': False,
            'A04:2021-Insecure Design': False,
            'A05:2021-Security Misconfiguration': False,
            'A06:2021-Vulnerable and Outdated Components': False,
            'A07:2021-Identification and Authentication Failures': False,
            'A08:2021-Software and Data Integrity Failures': False,
            'A09:2021-Security Logging and Monitoring Failures': False,
            'A10:2021-Server-Side Request Forgery': False
        }
        
        # Check which categories are covered by available assessments
        for assessment in self.assessments.values():
            category = assessment.get_owasp_category()
            if category in owasp_top_10_2021:
                owasp_top_10_2021[category] = True
        
        return owasp_top_10_2021