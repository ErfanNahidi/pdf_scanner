import subprocess
import os
import sys
import platform
import multiprocessing
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import time
import shutil

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
    """Cross-platform PDF scanner with multi-core processing and 1GB file size limit"""
    
    # File size limits (in MB)
    MAX_FILE_SIZE_MB = 1024  # 1GB
    WARNING_FILE_SIZE_MB = 100  # Warning threshold
    LARGE_FILE_SIZE_MB = 500   # Large file threshold
    
    # Performance settings
    CPU_COUNT = multiprocessing.cpu_count()
    MAX_WORKERS = min(6, CPU_COUNT)
    
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
        self.python_executable = self._get_python_executable()
        self.system = platform.system()
    
    def _get_python_executable(self) -> str:
        """Get the correct Python executable for the current platform"""
        # Try to use the same Python interpreter that's running this script
        python_exe = sys.executable
        if python_exe and os.path.isfile(python_exe):
            return python_exe
        
        # Fallback options by platform
        if platform.system() == "Windows":
            candidates = ["python.exe", "python3.exe", "py.exe"]
        else:
            candidates = ["python3", "python"]
        
        for candidate in candidates:
            if shutil.which(candidate):
                return candidate
        
        # Last resort - return python and let subprocess handle the error
        return "python"
    
    def _find_pdfid(self) -> Optional[Path]:
        """Find pdfid.py with cross-platform path resolution"""
        base_dir = Path(__file__).parent
        
        # Common relative paths
        relative_paths = [
            "src/pdfid/pdfid.py",
            "pdfid/pdfid.py",
            "../src/pdfid/pdfid.py",
            "../pdfid/pdfid.py",
            "tools/pdfid.py",
            "scripts/pdfid.py"
        ]
        
        # Check relative paths first
        for rel_path in relative_paths:
            path = base_dir / rel_path
            if path.exists():
                return path
        
        # Platform-specific system paths
        if platform.system() == "Windows":
            system_paths = [
                Path.home() / "pdfid" / "pdfid.py",
                Path("C:/Tools/pdfid/pdfid.py"),
                Path("C:/Program Files/pdfid/pdfid.py"),
                Path("C:/Program Files (x86)/pdfid/pdfid.py")
            ]
        elif platform.system() == "Darwin":  # macOS
            system_paths = [
                Path.home() / "pdfid" / "pdfid.py",
                Path("/usr/local/bin/pdfid.py"),
                Path("/opt/homebrew/bin/pdfid.py"),
                Path("/Applications/pdfid/pdfid.py")
            ]
        else:  # Linux and other Unix-like systems
            system_paths = [
                Path.home() / "pdfid" / "pdfid.py",
                Path("/usr/local/bin/pdfid.py"),
                Path("/opt/pdfid/pdfid.py"),
                Path("/usr/bin/pdfid.py")
            ]
        
        for path in system_paths:
            if path.exists():
                return path
        
        return None
    
    def _calculate_timeout(self, file_size_mb: float) -> int:
        """Calculate appropriate timeout based on file size"""
        if file_size_mb <= 10:
            return 30
        elif file_size_mb <= 100:
            return 60
        elif file_size_mb <= 500:
            return 180
        else:
            return 300
    
    def _set_process_priority(self, file_size_mb: float) -> None:
        """Set process priority in a cross-platform way"""
        try:
            if platform.system() == "Windows":
                import psutil
                process = psutil.Process()
                if file_size_mb > self.LARGE_FILE_SIZE_MB:
                    process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
                else:
                    process.nice(psutil.NORMAL_PRIORITY_CLASS)
            else:
                # Unix-like systems
                if hasattr(os, 'nice'):
                    nice_value = 5 if file_size_mb > self.LARGE_FILE_SIZE_MB else 10
                    os.nice(nice_value)
        except (ImportError, OSError, AttributeError):
            # If we can't set priority, just continue
            pass
    
    def scan_pdf(self, file_path: Path, timeout: int = None, progress_callback: Optional[Callable[[str], None]] = None) -> ScanResult:
        """Scan PDF with cross-platform compatibility and enhanced error handling"""
        start_time = time.time()
        
        # Ensure file_path is a Path object
        if isinstance(file_path, str):
            file_path = Path(file_path)
        
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
        if file_path.suffix.lower() != '.pdf':
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
                        f"File size: {file_size_mb:.1f}MB exceeds limit of {self.MAX_FILE_SIZE_MB}MB (1GB)",
                        "Try with a smaller PDF file (under 1GB)",
                        "Very large files may contain complex threats requiring specialized tools",
                        "Consider splitting the PDF into smaller chunks if possible"
                    ],
                    error_message=f"File size ({file_size_mb:.1f}MB) exceeds maximum allowed size ({self.MAX_FILE_SIZE_MB}MB)"
                )
            
            if timeout is None:
                timeout = self._calculate_timeout(file_size_mb)
            
            # Progress messages for large files
            if file_size_mb > self.LARGE_FILE_SIZE_MB:
                if progress_callback:
                    progress_callback(f"Very large file detected ({file_size_mb:.1f}MB) - this will take several minutes...")
            elif file_size_mb > self.WARNING_FILE_SIZE_MB:
                if progress_callback:
                    progress_callback(f"Large file detected ({file_size_mb:.1f}MB) - this may take longer...")
                
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
                recommendations=[
                    "Install pdfid tool",
                    "Download from: https://blog.didierstevens.com/programs/pdf-tools/",
                    f"Place pdfid.py in one of these locations: {self._get_suggested_paths()}"
                ],
                error_message="pdfid.py not found in expected locations"
            )
        
        if progress_callback:
            progress_callback("Analyzing PDF structure...")
        
        try:
            # Run pdfid scan
            result = self._run_pdfid_scan(file_path, timeout, file_size_mb)
            
            if result.returncode != 0:
                stderr_msg = result.stderr.strip() if result.stderr else 'Unknown error'
                return ScanResult(
                    file_path=file_path,
                    success=False,
                    threat_level=ThreatLevel.SAFE,
                    summary="Scan failed",
                    details={},
                    recommendations=[
                        "PDF file may be corrupted, encrypted, or too complex",
                        "Try with a different PDF file",
                        "Check if file is password protected",
                        "Large files may require additional processing time"
                    ],
                    error_message=f"pdfid scan error: {stderr_msg}"
                )
            
            if progress_callback:
                progress_callback("Analyzing threats and generating report...")
            
            # Parse results
            keyword_counts = self._parse_pdfid_output(result.stdout)
            threat_level, recommendations = self._assess_threats(keyword_counts)
            summary = self._generate_summary(keyword_counts, threat_level)
            
            # Add file size info
            keyword_counts["file_size_mb"] = round(file_size_mb, 2)
            if file_size_mb > self.WARNING_FILE_SIZE_MB:
                keyword_counts["large_file"] = 1
            
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
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                file_path=file_path,
                success=False,
                threat_level=ThreatLevel.SAFE,
                summary="Scan timeout",
                details={"file_size_mb": round(file_size_mb, 2)},
                recommendations=[
                    f"Scan timed out after {timeout} seconds",
                    f"File size: {file_size_mb:.1f}MB may be too complex for current timeout",
                    "Very large PDFs (>500MB) may require extended processing time",
                    "Try scanning smaller sections of the PDF if possible",
                    "Consider using specialized tools for files approaching 1GB"
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
                    "Ensure the file is not corrupted",
                    "Large files may require more system resources"
                ],
                error_message=f"Scan error: {str(e)}"
            )
    
    def _run_pdfid_scan(self, file_path: Path, timeout: int, file_size_mb: float) -> subprocess.CompletedProcess:
        """Run pdfid scan with cross-platform process management"""
        try:
            # Set process priority if possible
            self._set_process_priority(file_size_mb)
            
            # Build command
            cmd = [self.python_executable, str(self.pdfid_path), str(file_path)]
            
            # Platform-specific subprocess options
            subprocess_kwargs = {
                'capture_output': True,
                'text': True,
                'timeout': timeout
            }
            
            if platform.system() == "Windows":
                # On Windows, prevent console window from appearing
                subprocess_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            
            return subprocess.run(cmd, **subprocess_kwargs)
            
        except subprocess.TimeoutExpired:
            # Re-raise timeout to be handled by caller
            raise
        except Exception as e:
            # Create a mock result for error handling
            class MockResult:
                def __init__(self, error):
                    self.returncode = 1
                    self.stdout = ""
                    self.stderr = str(error)
            return MockResult(e)
    
    def _parse_pdfid_output(self, output: str) -> Dict[str, int]:
        """Parse pdfid output with improved error handling"""
        lines = output.splitlines()
        keyword_counts = {}
        
        # Skip header lines (usually first 2 lines)
        data_lines = lines[2:] if len(lines) > 2 else lines
        
        for line in data_lines:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split(None, 1)  # Split on whitespace, max 1 split
            if len(parts) == 2:
                key, value_str = parts
                try:
                    value = int(value_str)
                    keyword_counts[key] = value
                except ValueError:
                    # Skip lines that don't have integer values
                    continue
        
        return keyword_counts
    
    def _assess_threats(self, keywords: Dict[str, int]) -> Tuple[ThreatLevel, List[str]]:
        """Assess threats based on keyword counts"""
        max_threat_level = ThreatLevel.SAFE
        threat_count = 0
        
        for keyword, count in keywords.items():
            if count > 0 and keyword in self.THREAT_DEFINITIONS:
                threat_info = self.THREAT_DEFINITIONS[keyword]
                threat_level = threat_info["level"]
                threat_count += 1
                
                if self._threat_level_priority(threat_level) > self._threat_level_priority(max_threat_level):
                    max_threat_level = threat_level
        
        recommendations = self._generate_recommendations(max_threat_level, threat_count, keywords)
        return max_threat_level, recommendations
    
    def _generate_recommendations(self, threat_level: ThreatLevel, threat_count: int, keywords: Dict[str, int]) -> List[str]:
        """Generate recommendations based on threat level"""
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
        
        recommendations = base_recommendations.get(threat_level, ["Unknown threat level"])
        
        # Add file size specific recommendations
        file_size_mb = keywords.get("file_size_mb", 0)
        if file_size_mb > self.LARGE_FILE_SIZE_MB:
            recommendations.append(f"📊 Very large file ({file_size_mb:.1f}MB) - ensure sufficient system resources")
            recommendations.append("Large PDFs may take time to open and may consume significant memory")
        elif file_size_mb > self.WARNING_FILE_SIZE_MB:
            recommendations.append(f"📊 Large file ({file_size_mb:.1f}MB) - may require extra loading time")
        
        return recommendations
    
    def scan_multiple_pdfs(self, file_paths: List[Path], progress_callback: Optional[Callable[[str], None]] = None) -> List[ScanResult]:
        """Scan multiple PDFs with improved error handling"""
        results = []
        total_files = len(file_paths)
        
        def scan_with_progress(i: int, file_path: Path) -> ScanResult:
            if progress_callback:
                progress_callback(f"Scanning {i+1}/{total_files}: {file_path.name}")
            return self.scan_pdf(
                file_path, 
                progress_callback=lambda msg: progress_callback(f"[{i+1}/{total_files}] {msg}") if progress_callback else None
            )
        
        # Limit concurrent processing for large files
        max_concurrent = min(self.MAX_WORKERS, 3)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            future_to_file = {
                executor.submit(scan_with_progress, i, file_path): file_path 
                for i, file_path in enumerate(file_paths)
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
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
        
        file_size_mb = keywords.get("file_size_mb", 0)
        size_indicator = ""
        if file_size_mb > self.LARGE_FILE_SIZE_MB:
            size_indicator = " (Very Large File)"
        elif file_size_mb > self.WARNING_FILE_SIZE_MB:
            size_indicator = " (Large File)"
        
        summary_map = {
            ThreatLevel.SAFE: f"✅ Clean - No threats detected{size_indicator}",
            ThreatLevel.LOW: f"⚪ Low Risk - {threat_count} minor issue(s) found{size_indicator}",
            ThreatLevel.MEDIUM: f"🟡 Medium Risk - {threat_count} concerning feature(s){size_indicator}",
            ThreatLevel.HIGH: f"🟠 High Risk - {threat_count} dangerous feature(s){size_indicator}",
            ThreatLevel.CRITICAL: f"🔴 CRITICAL - {threat_count} severe threat(s) detected{size_indicator}"
        }
        
        return summary_map.get(threat_level, f"Unknown threat level{size_indicator}")
    
    def _get_suggested_paths(self) -> str:
        """Get suggested installation paths for pdfid.py"""
        if platform.system() == "Windows":
            return "C:/Tools/pdfid/, C:/Program Files/pdfid/, or current directory"
        elif platform.system() == "Darwin":
            return "/usr/local/bin/, /opt/homebrew/bin/, or ~/pdfid/"
        else:
            return "/usr/local/bin/, /opt/pdfid/, or ~/pdfid/"


# Convenience function for backward compatibility
def scan_pdf(path: Path, level: int = 2, timeout: int = None) -> str:
    """Legacy function wrapper with cross-platform support"""
    scanner = PDFScanner()
    result = scanner.scan_pdf(path, timeout)
    
    if not result.success:
        return f"Error: {result.error_message}"
    
    # Format output similar to original
    output = f"Scan Results for: {result.file_path.name}\n"
    output += f"Threat Level: {result.threat_level.value.upper()}\n"
    output += f"Summary: {result.summary}\n"
    output += f"Scan Time: {result.scan_time:.1f}s\n"
    output += f"Platform: {platform.system()} {platform.release()}\n\n"
    
    output += "Detailed Analysis:\n"
    for keyword, count in result.details.items():
        if keyword in PDFScanner.THREAT_DEFINITIONS:
            desc = PDFScanner.THREAT_DEFINITIONS[keyword]["desc"]
            output += f"{keyword}: {count} - {desc}\n"
        elif keyword == "file_size_mb":
            output += f"File Size: {count} MB\n"
        elif keyword == "large_file":
            output += f"Large File Flag: {count}\n"
        else:
            output += f"{keyword}: {count}\n"
    
    if result.recommendations:
        output += "\nRecommendations:\n"
        for rec in result.recommendations:
            output += f"• {rec}\n"
    
    return output