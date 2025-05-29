import subprocess
import json
import os
import multiprocessing
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import time
import threading

class ThreatLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ScanResult:
    file_path: Path
    success: bool
    threat_level: ThreatLevel
    summary: str
    details: Dict[str, int]
    recommendations: List[str]
    error_message: Optional[str] = None
    scan_time: float = 0.0

class PDFScanner:
    """Enhanced PDF scanner with multi-core processing and file size limits"""
    
    # File size limits (in MB)
    MAX_FILE_SIZE_MB = 25
    WARNING_FILE_SIZE_MB = 10
    
    # Performance settings
    CPU_COUNT = multiprocessing.cpu_count()
    MAX_WORKERS = min(4, CPU_COUNT)  # Limit workers to prevent system overload
    
    THREAT_DEFINITIONS = {
        # Critical threats - immediate danger
        "/JS": {"level": ThreatLevel.CRITICAL, "desc": "JavaScript code execution"},
        "/JavaScript": {"level": ThreatLevel.CRITICAL, "desc": "JavaScript embedded"},
        "/AA": {"level": ThreatLevel.HIGH, "desc": "Auto-action triggers"},
        "/OpenAction": {"level": ThreatLevel.HIGH, "desc": "Automatic execution on open"},
        
        # High risk threats
        "/Launch": {"level": ThreatLevel.HIGH, "desc": "External program execution"},
        "/EmbeddedFile": {"level": ThreatLevel.MEDIUM, "desc": "Embedded files present"},
        "/RichMedia": {"level": ThreatLevel.MEDIUM, "desc": "Rich media content"},
        
        # Medium risk
        "/XFA": {"level": ThreatLevel.MEDIUM, "desc": "XML Forms Architecture"},
        "/Encrypt": {"level": ThreatLevel.LOW, "desc": "Encrypted content"},
        "/Names": {"level": ThreatLevel.LOW, "desc": "Named destinations"},
        "/AcroForm": {"level": ThreatLevel.LOW, "desc": "Interactive forms"}
    }
    
    def __init__(self):
        self.pdfid_path = self._find_pdfid()
        self._lock = threading.Lock()  # Thread safety for concurrent operations
    
    def _find_pdfid(self) -> Optional[Path]:
        """Find pdfid.py with better path resolution"""
        base_dir = Path(__file__).parent
        potential_paths = [
            base_dir / "pdfid" / "pdfid" / "pdfid.py",
            base_dir.parent / "pdfid" / "pdfid" / "pdfid.py",
            # Add more common locations
            Path.home() / "pdfid" / "pdfid.py",
            Path("/usr/local/bin/pdfid.py"),
            Path("/opt/pdfid/pdfid.py")
        ]
        
        for path in potential_paths:
            if path.exists():
                return path
        return None
    
    def scan_pdf(self, file_path: Path, timeout: int = 30, progress_callback=None) -> ScanResult:
        """Scan PDF with file size validation and performance optimization"""
        start_time = time.time()
        
        if progress_callback:
            progress_callback("Validating file...")
        
        # File existence check
        if not file_path.exists():
            return ScanResult(
                file_path=file_path,
                success=False,
                threat_level=ThreatLevel.SAFE,
                summary="File not found",
                details={},
                recommendations=[],
                error_message=f"File does not exist: {file_path}"
            )
        
        # File type validation
        if not file_path.suffix.lower() == '.pdf':
            return ScanResult(
                file_path=file_path,
                success=False,
                threat_level=ThreatLevel.SAFE,
                summary="Invalid file type",
                details={},
                recommendations=[],
                error_message="File is not a PDF document"
            )
        
        # File size validation
        try:
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            
            if file_size_mb > self.MAX_FILE_SIZE_MB:
                return ScanResult(
                    file_path=file_path,
                    success=False,
                    threat_level=ThreatLevel.SAFE,
                    summary="File too large",
                    details={"file_size_mb": round(file_size_mb, 2)},
                    recommendations=[
                        f"File size: {file_size_mb:.1f}MB exceeds limit of {self.MAX_FILE_SIZE_MB}MB",
                        "Try with a smaller PDF file (under 25MB)",
                        "Large files may contain complex threats requiring specialized tools",
                        "Consider splitting the PDF into smaller chunks"
                    ],
                    error_message=f"File size ({file_size_mb:.1f}MB) exceeds maximum allowed size ({self.MAX_FILE_SIZE_MB}MB)"
                )
            
            # Warning for large files
            if file_size_mb > self.WARNING_FILE_SIZE_MB:
                if progress_callback:
                    progress_callback(f"Large file detected ({file_size_mb:.1f}MB) - this may take longer...")
                # Increase timeout for large files
                timeout = max(timeout, int(file_size_mb * 3))  # 3 seconds per MB
                
        except OSError as e:
            return ScanResult(
                file_path=file_path,
                success=False,
                threat_level=ThreatLevel.SAFE,
                summary="File access error",
                details={},
                recommendations=[],
                error_message=f"Cannot access file: {str(e)}"
            )
        
        # Check if pdfid is available
        if not self.pdfid_path:
            return ScanResult(
                file_path=file_path,
                success=False,
                threat_level=ThreatLevel.SAFE,
                summary="Scanner not available",
                details={},
                recommendations=["Install pdfid tool"],
                error_message="pdfid.py not found in expected locations"
            )
        
        if progress_callback:
            progress_callback("Analyzing PDF structure...")
        
        try:
            # Use multi-processing for CPU-intensive analysis
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._run_pdfid_scan, file_path, timeout)
                
                # Wait for completion with progress updates
                while not future.done():
                    if progress_callback:
                        progress_callback("Processing PDF data...")
                    time.sleep(0.1)
                
                result = future.result(timeout=timeout + 5)  # Extra buffer time
            
            if result.returncode != 0:
                return ScanResult(
                    file_path=file_path,
                    success=False,
                    threat_level=ThreatLevel.SAFE,
                    summary="Scan failed",
                    details={},
                    recommendations=[
                        "PDF file may be corrupted or encrypted",
                        "Try with a different PDF file",
                        "Check if file is password protected"
                    ],
                    error_message=f"pdfid scan error: {result.stderr.strip() if result.stderr else 'Unknown error'}"
                )
            
            if progress_callback:
                progress_callback("Analyzing threats...")
            
            # Parse results using optimized parsing
            keyword_counts = self._parse_pdfid_output_fast(result.stdout)
            threat_level, recommendations = self._assess_threats_parallel(keyword_counts)
            summary = self._generate_summary(keyword_counts, threat_level)
            
            # Add file size info to details
            keyword_counts["file_size_mb"] = round(file_size_mb, 2)
            
            scan_time = time.time() - start_time
            
            return ScanResult(
                file_path=file_path,
                success=True,
                threat_level=threat_level,
                summary=summary,
                details=keyword_counts,
                recommendations=recommendations,
                scan_time=scan_time
            )
            
        except concurrent.futures.TimeoutError:
            return ScanResult(
                file_path=file_path,
                success=False,
                threat_level=ThreatLevel.SAFE,
                summary="Scan timeout",
                details={"file_size_mb": round(file_size_mb, 2)},
                recommendations=[
                    f"Scan timed out after {timeout} seconds",
                    "File may be too large or complex",
                    "Try with a smaller PDF file (under 10MB for faster processing)",
                    "Large PDFs require more processing time and resources"
                ],
                error_message=f"Scan timed out after {timeout} seconds - file may be too large or complex"
            )
        except Exception as e:
            return ScanResult(
                file_path=file_path,
                success=False,
                threat_level=ThreatLevel.SAFE,
                summary="Unexpected error",
                details={"file_size_mb": round(file_size_mb, 2) if 'file_size_mb' in locals() else 0},
                recommendations=[
                    "An unexpected error occurred during scanning",
                    "Try with a different PDF file",
                    "Ensure the file is not corrupted"
                ],
                error_message=f"Scan error: {str(e)}"
            )
    
    def _run_pdfid_scan(self, file_path: Path, timeout: int):
        """Run pdfid scan in separate process for better resource management"""
        try:
            return subprocess.run(
                ["python3", str(self.pdfid_path), str(file_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                # Use lower process priority to prevent system overload
                preexec_fn=lambda: os.nice(10) if hasattr(os, 'nice') else None
            )
        except Exception as e:
            # Create a mock result for error handling
            class MockResult:
                def __init__(self, error):
                    self.returncode = 1
                    self.stdout = ""
                    self.stderr = str(error)
            return MockResult(e)
    
    def _parse_pdfid_output_fast(self, output: str) -> Dict[str, int]:
        """Optimized pdfid output parsing with parallel processing"""
        lines = output.splitlines()[2:]  # Skip header
        keyword_counts = {}
        
        # Use list comprehension for faster processing
        valid_lines = [line.strip().split(maxsplit=1) for line in lines if line.strip()]
        
        for parts in valid_lines:
            if len(parts) == 2:
                key, value = parts
                try:
                    keyword_counts[key] = int(value)
                except ValueError:
                    continue
        
        return keyword_counts
    
    def _assess_threats_parallel(self, keywords: Dict[str, int]) -> Tuple[ThreatLevel, List[str]]:
        """Parallel threat assessment for better performance"""
        with self._lock:  # Thread safety
            threats_found = []
            max_threat_level = ThreatLevel.SAFE
            recommendations = []
            
            # Use parallel processing for threat analysis
            def analyze_keyword(item):
                keyword, count = item
                if count > 0 and keyword in self.THREAT_DEFINITIONS:
                    threat_info = self.THREAT_DEFINITIONS[keyword]
                    return (keyword, count, threat_info)
                return None
            
            # Process keywords in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
                results = list(executor.map(analyze_keyword, keywords.items()))
            
            # Filter and collect valid threats
            threats_found = [r for r in results if r is not None]
            
            # Find maximum threat level
            for _, _, threat_info in threats_found:
                if self._threat_level_priority(threat_info["level"]) > self._threat_level_priority(max_threat_level):
                    max_threat_level = threat_info["level"]
            
            # Generate recommendations based on threats found
            recommendations = self._generate_recommendations_fast(max_threat_level, len(threats_found))
            
            return max_threat_level, recommendations
    
    def _generate_recommendations_fast(self, threat_level: ThreatLevel, threat_count: int) -> List[str]:
        """Fast recommendation generation"""
        base_recommendations = {
            ThreatLevel.CRITICAL: [
                "🚨 CRITICAL THREAT DETECTED - DO NOT OPEN",
                "This PDF contains dangerous executable code",
                "Use isolated/sandboxed environment only",
                "Consider this file potentially malicious"
            ],
            ThreatLevel.HIGH: [
                "⚠️ HIGH RISK - Exercise extreme caution",
                "Disable JavaScript in PDF viewer",
                "Scan with updated antivirus software",
                "Do not enable any prompts or dialogs"
            ],
            ThreatLevel.MEDIUM: [
                "⚠️ Medium risk features detected",
                "Review embedded content before opening",
                "Use updated PDF viewer with security features",
                f"{threat_count} concerning feature(s) found"
            ],
            ThreatLevel.LOW: [
                "Low risk features present",
                "File appears relatively safe",
                "Standard PDF viewer precautions apply"
            ],
            ThreatLevel.SAFE: [
                "✅ No obvious threats detected",
                "File appears clean and safe to open"
            ]
        }
        
        return base_recommendations.get(threat_level, ["Unknown threat level"])
    
    def scan_multiple_pdfs(self, file_paths: List[Path], progress_callback=None) -> List[ScanResult]:
        """Scan multiple PDFs in parallel for maximum efficiency"""
        results = []
        total_files = len(file_paths)
        
        def scan_with_progress(i, file_path):
            if progress_callback:
                progress_callback(f"Scanning {i+1}/{total_files}: {file_path.name}")
            return self.scan_pdf(file_path, progress_callback=lambda msg: progress_callback(f"[{i+1}/{total_files}] {msg}") if progress_callback else None)
        
        # Use parallel processing for multiple files
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            future_to_file = {
                executor.submit(scan_with_progress, i, file_path): file_path 
                for i, file_path in enumerate(file_paths)
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    file_path = future_to_file[future]
                    error_result = ScanResult(
                        file_path=file_path,
                        success=False,
                        threat_level=ThreatLevel.SAFE,
                        summary="Scan failed",
                        details={},
                        recommendations=[],
                        error_message=f"Failed to scan {file_path.name}: {str(e)}"
                    )
                    results.append(error_result)
        
        return results
    
    def _assess_threats(self, keywords: Dict[str, int]) -> Tuple[ThreatLevel, List[str]]:
        """Legacy method - use _assess_threats_parallel for better performance"""
        return self._assess_threats_parallel(keywords)
    
    def _threat_level_priority(self, level: ThreatLevel) -> int:
        """Convert threat level to numeric priority"""
        priority_map = {
            ThreatLevel.SAFE: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        return priority_map[level]
    
    def _generate_summary(self, keywords: Dict[str, int], threat_level: ThreatLevel) -> str:
        """Generate human-readable summary"""
        threat_count = sum(1 for k, v in keywords.items() 
                          if v > 0 and k in self.THREAT_DEFINITIONS)
        
        if threat_level == ThreatLevel.SAFE:
            return f"✅ Clean - No threats detected"
        elif threat_level == ThreatLevel.LOW:
            return f"⚪ Low Risk - {threat_count} minor issue(s) found"
        elif threat_level == ThreatLevel.MEDIUM:
            return f"🟡 Medium Risk - {threat_count} concerning feature(s)"
        elif threat_level == ThreatLevel.HIGH:
            return f"🟠 High Risk - {threat_count} dangerous feature(s)"
        else:  # CRITICAL
            return f"🔴 CRITICAL - {threat_count} severe threat(s) detected"

# Convenience function for backward compatibility
def scan_pdf(path: Path, level: int = 2, timeout: int = 5) -> str:
    """Legacy function wrapper"""
    scanner = PDFScanner()
    result = scanner.scan_pdf(path, timeout)
    
    if not result.success:
        return f"Error: {result.error_message}"
    
    # Format output similar to original
    output = f"Scan Results for: {result.file_path.name}\n"
    output += f"Threat Level: {result.threat_level.value.upper()}\n"
    output += f"Summary: {result.summary}\n\n"
    
    output += "Detailed Analysis:\n"
    for keyword, count in result.details.items():
        if keyword in PDFScanner.THREAT_DEFINITIONS:
            desc = PDFScanner.THREAT_DEFINITIONS[keyword]["desc"]
            output += f"{keyword}: {count} - {desc}\n"
        else:
            output += f"{keyword}: {count}\n"
    
    if result.recommendations:
        output += "\nRecommendations:\n"
        for rec in result.recommendations:
            output += f"• {rec}\n"
    
    return output