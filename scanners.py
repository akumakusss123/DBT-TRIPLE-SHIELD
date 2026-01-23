"""
MAIN SCANNER ORCHESTRATOR
Coordinates between all scanning engines
"""

import os
import time
import hashlib
import json
from typing import Dict, Any, List
from datetime import datetime

from .clamav_scanner import clamav_scanner
from .virus_total_scanner import virus_total_scanner
from .cloudflare_scanner import cloudflare_scanner

class TripleShieldScanner:
    """Orchestrates all three scanning engines"""
    
    def __init__(self):
        self.scanners = {
            'clamav': clamav_scanner,
            'virustotal': virus_total_scanner,
            'cloudflare': cloudflare_scanner
        }
        
        # Engine status
        self.engine_status = {
            'clamav': self._check_clamav_status(),
            'virustotal': self._check_virustotal_status(),
            'cloudflare': self._check_cloudflare_status()
        }
        
        # Statistics
        self.stats = {
            'total_scans': 0,
            'malicious_detections': 0,
            'clean_files': 0,
            'last_scan': None
        }
    
    def scan_file(self, filepath: str, engines: List[str] = None) -> Dict[str, Any]:
        """
        Scan file with selected engines
        
        Args:
            filepath: Path to file
            engines: List of engines to use ['clamav', 'virustotal', 'cloudflare']
                   If None, use all available
        
        Returns:
            Dict with results from all engines
        """
        if engines is None:
            engines = ['clamav', 'virustotal', 'cloudflare']
        
        results = {
            'filename': os.path.basename(filepath),
            'filepath': filepath,
            'size': os.path.getsize(filepath),
            'timestamp': datetime.now().isoformat(),
            'engines_used': engines,
            'results': {},
            'overall_verdict': 'PENDING'
        }
        
        # Calculate file hashes
        results['hashes'] = self._calculate_hashes(filepath)
        
        # Run scans in parallel (simplified)
        for engine in engines:
            if engine in self.scanners:
                try:
                    engine_result = self._run_engine_scan(engine, filepath, results['hashes'])
                    results['results'][engine] = engine_result
                except Exception as e:
                    results['results'][engine] = {
                        'error': str(e),
                        'status': 'ERROR'
                    }
        
        # Calculate overall verdict
        results['overall_verdict'] = self._calculate_overall_verdict(results['results'])
        
        # Update statistics
        self._update_stats(results)
        
        return results
    
    def _run_engine_scan(self, engine: str, filepath: str, hashes: Dict) -> Dict[str, Any]:
        """Run specific engine scan"""
        if engine == 'clamav':
            return self.scanners['clamav'].scan_file_with_clamscan(filepath)
        
        elif engine == 'virustotal':
            # Use SHA256 hash for VirusTotal
            return self.scanners['virustotal'].scan_hash(hashes['sha256'])
        
        elif engine == 'cloudflare':
            # Use SHA256 hash for Cloudflare
            return self.scanners['cloudflare'].scan_hash(hashes['sha256'])
        
        else:
            return {'error': f'Unknown engine: {engine}', 'status': 'ERROR'}
    
    def _calculate_hashes(self, filepath: str) -> Dict[str, str]:
        """Calculate multiple hashes for file"""
        hashes = {}
        
        # SHA256
        sha256_hash = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256_hash.update(chunk)
        hashes['sha256'] = sha256_hash.hexdigest()
        
        # MD5
        md5_hash = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hash.update(chunk)
        hashes['md5'] = md5_hash.hexdigest()
        
        # SHA1
        sha1_hash = hashlib.sha1()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha1_hash.update(chunk)
        hashes['sha1'] = sha1_hash.hexdigest()
        
        return hashes
    
    def _calculate_overall_verdict(self, engine_results: Dict) -> str:
        """Calculate overall verdict based on engine results"""
        verdicts = []
        
        for engine, result in engine_results.items():
            if 'detected' in result and result['detected']:
                verdicts.append('MALICIOUS')
            elif 'status' in result:
                if result['status'] in ['INFECTED', 'MALICIOUS']:
                    verdicts.append('MALICIOUS')
                elif result['status'] == 'SUSPICIOUS':
                    verdicts.append('SUSPICIOUS')
                elif result['status'] == 'CLEAN':
                    verdicts.append('CLEAN')
        
        if 'MALICIOUS' in verdicts:
            return 'MALICIOUS'
        elif 'SUSPICIOUS' in verdicts:
            return 'SUSPICIOUS'
        elif all(v == 'CLEAN' for v in verdicts if v):
            return 'CLEAN'
        else:
            return 'UNKNOWN'
    
    def _check_clamav_status(self) -> Dict[str, Any]:
        """Check ClamAV status"""
        try:
            is_installed = clamav_scanner.check_clamav_installed()
            stats = clamav_scanner.get_statistics() if is_installed else {}
            
            return {
                'available': is_installed,
                'status': 'ONLINE' if is_installed else 'OFFLINE',
                'statistics': stats
            }
        except Exception as e:
            return {
                'available': False,
                'status': 'ERROR',
                'error': str(e)
            }
    
    def _check_virustotal_status(self) -> Dict[str, Any]:
        """Check VirusTotal status"""
        try:
            has_api_key = bool(os.getenv('VIRUSTOTAL_API_KEY'))
            return {
                'available': has_api_key,
                'status': 'ONLINE' if has_api_key else 'NO_API_KEY',
                'engines': 70
            }
        except:
            return {'available': False, 'status': 'UNKNOWN'}
    
    def _check_cloudflare_status(self) -> Dict[str, Any]:
        """Check Cloudflare status"""
        try:
            has_api_key = bool(os.getenv('CLOUDFLARE_API_KEY'))
            return {
                'available': has_api_key,
                'status': 'ONLINE' if has_api_key else 'NO_API_KEY'
            }
        except:
            return {'available': False, 'status': 'UNKNOWN'}
    
    def _update_stats(self, results: Dict):
        """Update scanning statistics"""
        self.stats['total_scans'] += 1
        self.stats['last_scan'] = datetime.now().isoformat()
        
        if results['overall_verdict'] == 'CLEAN':
            self.stats['clean_files'] += 1
        elif results['overall_verdict'] in ['MALICIOUS', 'SUSPICIOUS']:
            self.stats['malicious_detections'] += 1
    
    def get_engine_status(self) -> Dict[str, Any]:
        """Get status of all engines"""
        # Refresh status
        self.engine_status = {
            'clamav': self._check_clamav_status(),
            'virustotal': self._check_virustotal_status(),
            'cloudflare': self._check_cloudflare_status()
        }
        
        return self.engine_status
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        return {
            **self.stats,
            'engine_status': self.engine_status,
            'timestamp': datetime.now().isoformat()
        }
    
    def update_virus_databases(self) -> Dict[str, Any]:
        """Update all virus databases"""
        results = {}
        
        # Update ClamAV databases
        if self.engine_status['clamav']['available']:
            results['clamav'] = clamav_scanner.update_virus_databases()
        
        return results

# Global scanner instance
scanner = TripleShieldScanner()