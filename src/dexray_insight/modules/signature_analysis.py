#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from typing import List, Dict, Any
from dataclasses import dataclass

from ..core.base_classes import BaseAnalysisModule, BaseResult, AnalysisContext, AnalysisStatus, register_module
from ..signature_detection.hash import get_sha256_hash_of_apk
from ..signature_detection.koodous import koodous_hash_check
from ..signature_detection.vt import vt_check_file_reputation
from ..signature_detection.triage import triage_hashcheck

@dataclass
class SignatureAnalysisResult(BaseResult):
    """Result class for signature analysis"""
    signatures: Dict[str, Any] = None
    apk_hash: str = ""
    providers_checked: List[str] = None
    
    def __post_init__(self):
        if self.signatures is None:
            self.signatures = {}
        if self.providers_checked is None:
            self.providers_checked = []
    
    def to_dict(self) -> Dict[str, Any]:
        base_dict = super().to_dict()
        base_dict.update({
            'signatures': self.signatures,
            'apk_hash': self.apk_hash,
            'providers_checked': self.providers_checked
        })
        return base_dict

@register_module('signature_detection')
class SignatureAnalysisModule(BaseAnalysisModule):
    """Signature detection and hash-based analysis module"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.providers = config.get('providers', {})
    
    def get_dependencies(self) -> List[str]:
        """No dependencies for signature analysis"""
        return []
    
    def analyze(self, apk_path: str, context: AnalysisContext) -> SignatureAnalysisResult:
        """
        Perform signature analysis on the APK
        
        Args:
            apk_path: Path to the APK file
            context: Analysis context
            
        Returns:
            SignatureAnalysisResult with analysis results
        """
        start_time = time.time()
        
        try:
            # Get SHA256 hash of the APK
            apk_hash = get_sha256_hash_of_apk(apk_path)
            
            signatures = {}
            providers_checked = []
            
            # Check each enabled provider
            if self.providers.get('koodous', {}).get('enabled', False):
                try:
                    signatures['koodous'] = koodous_hash_check(apk_hash, context.config)
                    providers_checked.append('koodous')
                except Exception as e:
                    self.logger.error(f"Koodous check failed: {str(e)}")
                    signatures['koodous'] = None
            
            if self.providers.get('virustotal', {}).get('enabled', False):
                try:
                    signatures['vt'] = vt_check_file_reputation(apk_hash, context.config)
                    providers_checked.append('virustotal')
                except Exception as e:
                    self.logger.error(f"VirusTotal check failed: {str(e)}")
                    signatures['vt'] = None
            
            if self.providers.get('triage', {}).get('enabled', False):
                try:
                    signatures['triage'] = triage_hashcheck(apk_hash, context.config)
                    providers_checked.append('triage')
                except Exception as e:
                    self.logger.error(f"Triage check failed: {str(e)}")
                    signatures['triage'] = None
            
            execution_time = time.time() - start_time
            
            return SignatureAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.SUCCESS,
                execution_time=execution_time,
                signatures=signatures,
                apk_hash=apk_hash,
                providers_checked=providers_checked
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return SignatureAnalysisResult(
                module_name=self.name,
                status=AnalysisStatus.FAILURE,
                execution_time=execution_time,
                error_message=str(e),
                signatures={},
                apk_hash="",
                providers_checked=[]
            )
    
    def validate_config(self) -> bool:
        """Validate module configuration"""
        # Check if at least one provider is enabled
        if not any(provider.get('enabled', False) for provider in self.providers.values()):
            return False
        
        # Check API keys for enabled providers
        for provider_name, provider_config in self.providers.items():
            if provider_config.get('enabled', False):
                api_key = provider_config.get('api_key')
                if provider_name in ['virustotal', 'koodous'] and not api_key:
                    self.logger.warning(f"{provider_name} is enabled but no API key provided")
        
        return True