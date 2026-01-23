"""

Professional antivirus scanning with signature detection


"""

import os
import subprocess
import time
import requests
import logging
from typing import Dict, Any, Optional
import tempfile
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealClamAVScanner:
    """Professional ClamAV scanner with multiple scanning modes"""
    
    def __init__(self, clamscan_path: str = None, clamdscan_path: str = None):
        """
        Initialize ClamAV scanner
        
        Args:
            clamscan_path: Path to clamscan binary
            clamdscan_path: Path to clamdscan binary
        """
        self.clamscan_path = clamscan_path or self._find_clamscan()
        self.clamdscan_path = clamdscan_path or self._find_clamdscan()
        self.signature_databases = [
            'main.cvd', 'daily.cvd', 'bytecode.cvd'
        ]
        
        # Malware categories
        self.malware_categories = {
            'Trojan': ['Trojan', 'Trojan.', 'Trj', 'Troj'],
            'Virus': ['Virus', 'Vir', 'W32/', 'W97M/'],
            'Worm': ['Worm', 'W32/Autorun', 'Net-Worm'],
            'Ransomware': ['Ransom', 'Crypt', 'Locky', 'WannaCry', 'Petya'],
            'Spyware': ['Spyware', 'Keylogger', 'Spy', 'PWS'],
            'Adware': ['Adware', 'AdLoad', 'AdClick'],
            'Backdoor': ['Backdoor', 'Bkdr', 'BackDoor'],
            'Rootkit': ['Rootkit', 'Rkit'],
            'Exploit': ['Exploit', 'Exp', 'Shellcode'],
            'Phishing': ['Phishing', 'Phish', 'HTML/Phish']
        }
        
    def _find_clamscan(self) -> str:
        """Find clamscan binary"""
        possible_paths = [
            '/usr/bin/clamscan',
            '/usr/local/bin/clamscan',
            '/opt/homebrew/bin/clamscan',
            'clamscan',  # Try PATH
        ]
        
        for path in possible_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        
        return 'clamscan'  # Fallback to PATH
    
    def _find_clamdscan(self) -> str:
        """Find clamdscan binary"""
        possible_paths = [
            '/usr/bin/clamdscan',
            '/usr/local/bin/clamdscan',
            '/opt/homebrew/bin/clamdscan',
            'clamdscan',  # Try PATH
        ]
        
        for path in possible_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        
        return 'clamdscan'  # Fallback to PATH
    
    def check_clamav_installed(self) -> bool:
        """Check if ClamAV is properly installed"""
        try:
            result = subprocess.run(
                [self.clamscan_path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return 'ClamAV' in result.stdout
        except Exception as e:
            logger.error(f"ClamAV check failed: {e}")
            return False
    
    def update_virus_databases(self) -> Dict[str, Any]:
        """Update ClamAV virus databases"""
        try:
            logger.info("Updating ClamAV virus databases...")
            
            # Try freshclam
            result = subprocess.run(
                ['freshclam', '--verbose'],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'message': 'Virus databases updated successfully',
                    'output': result.stdout[-500:]  # Last 500 chars
                }
            else:
                return {
                    'success': False,
                    'message': 'Failed to update databases',
                    'error': result.stderr
                }
                
        except Exception as e:
            return {
                'success': False,
                'message': f'Update error: {str(e)}'
            }
    
    def scan_file_with_clamscan(self, filepath: str) -> Dict[str, Any]:
        """
        Scan file using clamscan (standalone mode)
        
        Returns:
            Dict with scan results
        """
        try:
            if not os.path.exists(filepath):
                return {
                    'error': f'File not found: {filepath}',
                    'detected': False,
                    'status': 'ERROR'
                }
            
            logger.info(f"Scanning {filepath} with clamscan...")
            
            # Run clamscan with detailed output
            result = subprocess.run(
                [
                    self.clamscan_path,
                    '--stdout',           # Print to stdout
                    '--infected',         # Only print infected files
                    '--no-summary',       # Don't print summary at end
                    '--verbose',          # Be verbose
                    '--bell',             # Ring bell when virus found
                    filepath
                ],
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout
            )
            
            output = result.stdout.strip()
            
            # Parse results
            if result.returncode == 0:
                # No virus found
                return {
                    'detected': False,
                    'status': 'CLEAN',
                    'signature': None,
                    'output': output,
                    'engine': 'clamscan',
                    'categories': []
                }
            elif result.returncode == 1:
                # Virus found!
                # Parse signature from output
                signature = self._extract_signature(output, filepath)
                categories = self._categorize_malware(signature)
                
                return {
                    'detected': True,
                    'status': 'INFECTED',
                    'signature': signature,
                    'output': output,
                    'engine': 'clamscan',
                    'categories': categories,
                    'risk_level': self._calculate_risk_level(categories)
                }
            else:
                # Error
                return {
                    'error': f'clamscan error: {result.stderr}',
                    'detected': False,
                    'status': 'ERROR',
                    'output': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'error': 'Scan timeout (60 seconds)',
                'detected': False,
                'status': 'TIMEOUT'
            }
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return {
                'error': str(e),
                'detected': False,
                'status': 'ERROR'
            }
    
    def scan_file_with_clamdscan(self, filepath: str, 
                                 clamd_socket: str = '/var/run/clamav/clamd.ctl') -> Dict[str, Any]:
        """
        Scan file using clamdscan (daemon mode)
        Faster for multiple scans
        """
        try:
            if not os.path.exists(filepath):
                return {
                    'error': f'File not found: {filepath}',
                    'detected': False,
                    'status': 'ERROR'
                }
            
            logger.info(f"Scanning {filepath} with clamdscan...")
            
            # Run clamdscan
            result = subprocess.run(
                [
                    self.clamdscan_path,
                    '--fdpass',           # Pass file descriptor to clamd
                    '--stdout',
                    '--verbose',
                    f'--socket={clamd_socket}',
                    filepath
                ],
                capture_output=True,
                text=True,
                timeout=30  # 30 seconds timeout
            )
            
            output = result.stdout.strip()
            
            # Parse results
            if 'FOUND' in output:
                signature = self._extract_signature(output, filepath)
                categories = self._categorize_malware(signature)
                
                return {
                    'detected': True,
                    'status': 'INFECTED',
                    'signature': signature,
                    'output': output,
                    'engine': 'clamdscan',
                    'categories': categories,
                    'risk_level': self._calculate_risk_level(categories)
                }
            elif 'OK' in output:
                return {
                    'detected': False,
                    'status': 'CLEAN',
                    'signature': None,
                    'output': output,
                    'engine': 'clamdscan',
                    'categories': []
                }
            else:
                return {
                    'error': f'clamdscan error: {result.stderr}',
                    'detected': False,
                    'status': 'ERROR',
                    'output': result.stderr
                }
                
        except Exception as e:
            logger.error(f"clamdscan error: {e}")
            return self.scan_file_with_clamscan(filepath)  # Fallback to clamscan
    
    def scan_string_content(self, content: str, filename: str = "unknown.txt") -> Dict[str, Any]:
        """
        Scan string content for malware (useful for scripts, configs)
        """
        try:
            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix=filename, delete=False) as f:
                f.write(content)
                temp_file = f.name
            
            # Scan the temp file
            result = self.scan_file_with_clamscan(temp_file)
            
            # Clean up
            os.unlink(temp_file)
            
            return result
            
        except Exception as e:
            return {
                'error': str(e),
                'detected': False,
                'status': 'ERROR'
            }
    
    def scan_directory(self, directory: str) -> Dict[str, Any]:
        """
        Scan entire directory recursively
        """
        try:
            if not os.path.exists(directory):
                return {
                    'error': f'Directory not found: {directory}',
                    'scanned': 0,
                    'infected': 0
                }
            
            logger.info(f"Scanning directory: {directory}")
            
            # Run recursive scan
            result = subprocess.run(
                [
                    self.clamscan_path,
                    '--recursive',
                    '--infected',
                    '--verbose',
                    '--bell',
                    '--log=clamav_scan.log',
                    directory
                ],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            # Parse results
            lines = result.stdout.split('\n')
            infected_files = []
            
            for line in lines:
                if 'FOUND' in line:
                    infected_files.append(line.strip())
            
            return {
                'scanned': len(lines),
                'infected': len(infected_files),
                'infected_files': infected_files,
                'output': result.stdout[-1000:],  # Last 1000 chars
                'return_code': result.returncode
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'scanned': 0,
                'infected': 0
            }
    
    def _extract_signature(self, output: str, filepath: str) -> str:
        """Extract malware signature from clamscan output"""
        try:
            # Example: "/path/file.exe: Win.Trojan.Generic-1234 FOUND"
            for line in output.split('\n'):
                if filepath in line and 'FOUND' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        signature = parts[1].strip()
                        # Remove "FOUND" part
                        signature = signature.replace('FOUND', '').strip()
                        return signature
            return 'Unknown'
        except:
            return 'Unknown'
    
    def _categorize_malware(self, signature: str) -> list:
        """Categorize malware based on signature patterns"""
        categories = []
        
        if not signature or signature == 'Unknown':
            return categories
        
        signature_lower = signature.lower()
        
        for category, patterns in self.malware_categories.items():
            for pattern in patterns:
                if pattern.lower() in signature_lower:
                    if category not in categories:
                        categories.append(category)
                    break
        
        return categories
    
    def _calculate_risk_level(self, categories: list) -> str:
        """Calculate risk level based on malware categories"""
        high_risk = ['Ransomware', 'Rootkit', 'Exploit', 'Backdoor']
        medium_risk = ['Trojan', 'Spyware', 'Worm']
        
        for category in categories:
            if category in high_risk:
                return 'HIGH'
            elif category in medium_risk:
                return 'MEDIUM'
        
        return 'LOW'
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get ClamAV statistics"""
        try:
            # Get version info
            version_result = subprocess.run(
                [self.clamscan_path, '--version'],
                capture_output=True,
                text=True
            )
            
            # Count signatures (approximate)
            sig_count = 0
            db_dir = '/var/lib/clamav'
            if os.path.exists(db_dir):
                for file in os.listdir(db_dir):
                    if file.endswith('.cvd'):
                        sig_count += 1000000  # Approx per CVD file
            
            return {
                'version': version_result.stdout.strip()[:100],
                'signatures_approx': sig_count,
                'databases': self._get_database_info(),
                'last_update': self._get_last_update_time()
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'version': 'Unknown'
            }
    
    def _get_database_info(self) -> list:
        """Get information about virus databases"""
        databases = []
        db_dir = '/var/lib/clamav'
        
        if os.path.exists(db_dir):
            for file in os.listdir(db_dir):
                if file.endswith('.cvd'):
                    filepath = os.path.join(db_dir, file)
                    stat = os.stat(filepath)
                    databases.append({
                        'name': file,
                        'size_mb': stat.st_size / (1024 * 1024),
                        'modified': time.ctime(stat.st_mtime)
                    })
        
        return databases
    
    def _get_last_update_time(self) -> str:
        """Get last database update time"""
        try:
            freshclam_log = '/var/log/clamav/freshclam.log'
            if os.path.exists(freshclam_log):
                with open(freshclam_log, 'r') as f:
                    lines = f.readlines()
                    for line in reversed(lines):
                        if 'Database updated' in line:
                            return line.strip()
            return 'Unknown'
        except:
            return 'Unknown'

# Singleton instance
clamav_scanner = RealClamAVScanner()