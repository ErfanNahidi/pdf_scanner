import sys
from pathlib import Path
from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *
from backend import PDFScanner, ScanResult, ThreatLevel

class ScanWorker(QThread):
    """Enhanced worker thread with proper cancellation and error handling"""
    scanComplete = Signal(object)  # ScanResult
    progressUpdate = Signal(str)   # Status message
    progressValue = Signal(int)    # Progress percentage (0-100)
    scanError = Signal(str)        # Error message
    
    def __init__(self, file_paths):
        super().__init__()
        self.file_paths = file_paths if isinstance(file_paths, list) else [file_paths]
        self.scanner = PDFScanner()
        self._is_cancelled = False
        self._mutex = QMutex()
    
    def run(self):
        try:
            total_files = len(self.file_paths)
            
            if total_files == 1:
                self._scan_single_file()
            else:
                self._scan_multiple_files()
                
        except Exception as e:
            self.scanError.emit(f"Scanning failed: {str(e)}")
    
    def _scan_single_file(self):
        """Scan a single file with progress updates"""
        file_path = self.file_paths[0]
        
        if self._is_cancelled:
            return
            
        self.progressUpdate.emit(f"Preparing to scan: {file_path.name}")
        self.progressValue.emit(10)
        
        def progress_callback(message):
            if not self._is_cancelled:
                self.progressUpdate.emit(message)
        
        try:
            result = self.scanner.scan_pdf(file_path, progress_callback=progress_callback)
            
            if not self._is_cancelled:
                self.progressValue.emit(100)
                self.scanComplete.emit(result)
        except Exception as e:
            if not self._is_cancelled:
                self.scanError.emit(f"Failed to scan {file_path.name}: {str(e)}")
    
    def _scan_multiple_files(self):
        """Scan multiple files with batch progress"""
        total_files = len(self.file_paths)
        self.progressUpdate.emit(f"Preparing to scan {total_files} files...")
        self.progressValue.emit(0)
        
        def batch_progress_callback(message):
            if self._is_cancelled:
                return
            self.progressUpdate.emit(message)
            # Extract progress from message if possible
            if "/" in message:
                try:
                    parts = message.split()
                    for part in parts:
                        if "/" in part:
                            current = int(part.split("/")[0])
                            progress = int((current / total_files) * 100)
                            self.progressValue.emit(progress)
                            break
                except (ValueError, IndexError):
                    pass
        
        try:
            results = self.scanner.scan_multiple_pdfs(self.file_paths, batch_progress_callback)
            
            for result in results:
                if self._is_cancelled:
                    break
                self.scanComplete.emit(result)
                    
            if not self._is_cancelled:
                self.progressValue.emit(100)
        except Exception as e:
            if not self._is_cancelled:
                self.scanError.emit(f"Batch scanning failed: {str(e)}")
    
    def cancel(self):
        """Cancel the scanning operation"""
        with QMutexLocker(self._mutex):
            self._is_cancelled = True

class ThreatCard(QFrame):
    """Modern card widget with enhanced animations and interactions"""
    
    def __init__(self, result: ScanResult):
        super().__init__()
        self.result = result
        self.details_expanded = False
        self.setup_ui()
        self.setup_animations()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.NoFrame)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        
        # Enhanced color scheme with better accessibility
        colors = {
            ThreatLevel.SAFE: {
                "bg": "#f0f9f0", "bg_hover": "#e8f5e8", "border": "#4caf50", 
                "text": "#1b5e20", "accent": "#4caf50", "badge": "#2e7d32"
            },
            ThreatLevel.LOW: {
                "bg": "#fff9f0", "bg_hover": "#fff3e0", "border": "#ff9800", 
                "text": "#e65100", "accent": "#ff9800", "badge": "#ef6c00"
            },
            ThreatLevel.MEDIUM: {
                "bg": "#fffbf0", "bg_hover": "#fff8e1", "border": "#ffa726", 
                "text": "#f57c00", "accent": "#ffa726", "badge": "#f57c00"
            },
            ThreatLevel.HIGH: {
                "bg": "#fff5f0", "bg_hover": "#ffeaa7", "border": "#ff5722", 
                "text": "#d84315", "accent": "#ff5722", "badge": "#d84315"
            },
            ThreatLevel.CRITICAL: {
                "bg": "#ffebee", "bg_hover": "#ffcdd2", "border": "#f44336", 
                "text": "#c62828", "accent": "#f44336", "badge": "#c62828"
            }
        }
        
        theme = colors.get(self.result.threat_level, colors[ThreatLevel.SAFE])
        
        self.setStyleSheet(f"""
            ThreatCard {{
                background-color: {theme["bg"]};
                border: 2px solid {theme["border"]};
                border-radius: 16px;
                padding: 20px;
                margin: 10px 5px;
            }}
            ThreatCard:hover {{
                border-color: {theme["text"]};
                background-color: {theme["bg_hover"]};
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header with enhanced design
        header_widget = self.create_header(theme)
        layout.addWidget(header_widget)
        
        # File metadata
        if 'file_size_mb' in self.result.details:
            metadata = self.create_metadata_section(theme)
            layout.addWidget(metadata)
        
        # Summary with better typography
        summary = self.create_summary_section(theme)
        layout.addWidget(summary)
        
        # Collapsible details section
        self.details_widget = QWidget()
        self.details_layout = QVBoxLayout(self.details_widget)
        self.details_layout.setContentsMargins(0, 10, 0, 0)
        
        if self.result.success and (self.result.details or self.result.recommendations):
            self.setup_details_section(theme)
            self.toggle_btn = self.create_toggle_button(theme)
            layout.addWidget(self.toggle_btn)
            self.details_widget.setVisible(False)
        
        # Error section
        if not self.result.success and self.result.error_message:
            error_section = self.create_error_section()
            layout.addWidget(error_section)
        
        layout.addWidget(self.details_widget)
    
    def create_header(self, theme):
        """Create enhanced header with icons and badges"""
        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        # File icon with threat level indicator
        icon_container = QWidget()
        icon_container.setFixedSize(50, 50)
        icon_layout = QVBoxLayout(icon_container)
        icon_layout.setContentsMargins(0, 0, 0, 0)
        
        file_icon = QLabel("📄")
        file_icon.setFont(QFont("Segoe UI Emoji", 20))
        file_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_layout.addWidget(file_icon)
        
        # File name with enhanced typography
        name_container = QWidget()
        name_layout = QVBoxLayout(name_container)
        name_layout.setContentsMargins(10, 0, 0, 0)
        name_layout.setSpacing(2)
        
        file_name = QLabel(self.result.file_path.name)
        file_name.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        file_name.setStyleSheet(f"color: {theme['text']};")
        file_name.setWordWrap(True)
        
        file_path_label = QLabel(str(self.result.file_path.parent))
        file_path_label.setFont(QFont("Segoe UI", 10))
        file_path_label.setStyleSheet("color: #666; font-style: italic;")
        file_path_label.setWordWrap(True)
        
        name_layout.addWidget(file_name)
        name_layout.addWidget(file_path_label)
        
        # Enhanced threat badge
        threat_badge = self.create_threat_badge(theme)
        
        header_layout.addWidget(icon_container)
        header_layout.addWidget(name_container, 1)
        header_layout.addWidget(threat_badge)
        
        return header_widget
    
    def create_threat_badge(self, theme):
        """Create modern threat level badge"""
        badge_container = QWidget()
        badge_container.setFixedSize(100, 60)
        badge_layout = QVBoxLayout(badge_container)
        badge_layout.setContentsMargins(0, 0, 0, 0)
        badge_layout.setSpacing(2)
        
        # Threat level text
        threat_label = QLabel(self.result.threat_level.value.upper())
        threat_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        threat_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        threat_label.setStyleSheet(f"""
            background-color: {theme["badge"]};
            color: white;
            border-radius: 12px;
            padding: 6px 12px;
        """)
        
        # Scan time if available
        if hasattr(self.result, 'scan_time') and self.result.scan_time > 0:
            time_label = QLabel(f"{self.result.scan_time:.1f}s")
            time_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            time_label.setFont(QFont("Segoe UI", 8))
            time_label.setStyleSheet("color: #888;")
            badge_layout.addWidget(time_label)
        
        badge_layout.addWidget(threat_label)
        return badge_container
    
    def create_metadata_section(self, theme):
        """Create file metadata section"""
        metadata_widget = QWidget()
        metadata_layout = QHBoxLayout(metadata_widget)
        metadata_layout.setContentsMargins(0, 0, 0, 0)
        
        size_mb = self.result.details.get('file_size_mb', 0)
        size_info = QLabel(f"📊 {size_mb:.1f} MB")
        size_info.setFont(QFont("Segoe UI", 11))
        size_info.setStyleSheet("color: #666;")
        
        # Add modification time if available
        try:
            mtime = self.result.file_path.stat().st_mtime
            from datetime import datetime
            mod_time = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
            time_info = QLabel(f"🕒 Modified: {mod_time}")
            time_info.setFont(QFont("Segoe UI", 11))
            time_info.setStyleSheet("color: #666;")
            metadata_layout.addWidget(time_info)
        except:
            pass
        
        metadata_layout.addWidget(size_info)
        metadata_layout.addStretch()
        
        return metadata_widget
    
    def create_summary_section(self, theme):
        """Create enhanced summary section"""
        summary_label = QLabel(self.result.summary)
        summary_label.setFont(QFont("Segoe UI", 13))
        summary_label.setStyleSheet(f"color: {theme['text']}; line-height: 1.4;")
        summary_label.setWordWrap(True)
        return summary_label
    
    def create_error_section(self):
        """Create error display section"""
        error_widget = QFrame()
        error_widget.setStyleSheet("""
            QFrame {
                background-color: #ffebee;
                border: 1px solid #f44336;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        
        error_layout = QVBoxLayout(error_widget)
        error_layout.setContentsMargins(0, 0, 0, 0)
        
        error_label = QLabel(f"⚠️ Error: {self.result.error_message}")
        error_label.setStyleSheet("color: #d32f2f; font-weight: bold;")
        error_label.setWordWrap(True)
        error_layout.addWidget(error_label)
        
        return error_widget
    
    def create_toggle_button(self, theme):
        """Create modern toggle button with animation"""
        button = QPushButton("▼ Show Details")
        button.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: {theme["accent"]};
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 8px;
                text-align: left;
            }}
            QPushButton:hover {{
                background-color: {theme["text"]};
                
            }}
            QPushButton:pressed {{
                
            }}
        """)
        button.clicked.connect(self.toggle_details)
        return button
    
    def setup_details_section(self, theme):
        """Setup detailed analysis section"""
        if self.result.success and self.result.details:
            self.create_analysis_details(theme)
        
        if self.result.recommendations:
            self.create_recommendations_section(theme)
    
    def create_analysis_details(self, theme):
        """Create detailed threat analysis"""
        details_title = QLabel("🔍 Detailed Analysis")
        details_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        details_title.setStyleSheet(f"color: {theme['text']}; margin-bottom: 8px;")
        self.details_layout.addWidget(details_title)
        
        # Create scrollable area for details
        scroll_area = QScrollArea()
        scroll_area.setMaximumHeight(200)
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        details_content = QWidget()
        grid_layout = QGridLayout(details_content)
        grid_layout.setSpacing(8)
        
        row = 0
        for keyword, count in self.result.details.items():
            if keyword == 'file_size_mb':
                continue
            if count > 0:
                # Keyword
                key_label = QLabel(keyword)
                key_label.setFont(QFont("Consolas", 10))
                key_label.setStyleSheet("font-weight: bold;")
                
                # Count badge
                count_badge = QLabel(str(count))
                count_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
                count_badge.setFixedSize(30, 20)
                count_badge.setStyleSheet(f"""
                    background-color: {theme["accent"]};
                    color: white;
                    border-radius: 10px;
                    font-weight: bold;
                    font-size: 10px;
                """)
                
                # Description
                if keyword in PDFScanner.THREAT_DEFINITIONS:
                    desc = PDFScanner.THREAT_DEFINITIONS[keyword]["desc"]
                    desc_label = QLabel(desc)
                    desc_label.setFont(QFont("Segoe UI", 10))
                    desc_label.setStyleSheet("color: #666; font-style: italic;")
                    desc_label.setWordWrap(True)
                    
                    grid_layout.addWidget(key_label, row, 0)
                    grid_layout.addWidget(count_badge, row, 1)
                    grid_layout.addWidget(desc_label, row, 2)
                else:
                    grid_layout.addWidget(key_label, row, 0)
                    grid_layout.addWidget(count_badge, row, 1)
                
                row += 1
        
        scroll_area.setWidget(details_content)
        self.details_layout.addWidget(scroll_area)
    
    def create_recommendations_section(self, theme):
        """Create recommendations section"""
        rec_title = QLabel("💡 Security Recommendations")
        rec_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        rec_title.setStyleSheet(f"color: {theme['text']}; margin-top: 16px; margin-bottom: 8px;")
        self.details_layout.addWidget(rec_title)
        
        for i, rec in enumerate(self.result.recommendations):
            rec_widget = QFrame()
            rec_widget.setStyleSheet(f"""
                QFrame {{
                    background-color: rgba(0,0,0,0.03);
                    border-left: 4px solid {theme["accent"]};
                    border-radius: 4px;
                    padding: 8px 12px;
                    margin: 2px 0px;
                }}
            """)
            
            rec_layout = QHBoxLayout(rec_widget)
            rec_layout.setContentsMargins(0, 0, 0, 0)
            
            bullet = QLabel(f"{i+1}.")
            bullet.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            bullet.setStyleSheet(f"color: {theme['accent']};")
            bullet.setFixedWidth(20)
            
            rec_text = QLabel(rec)
            rec_text.setFont(QFont("Segoe UI", 10))
            rec_text.setWordWrap(True)
            rec_text.setStyleSheet("color: #444;")
            
            rec_layout.addWidget(bullet)
            rec_layout.addWidget(rec_text)
            
            self.details_layout.addWidget(rec_widget)
    
    def setup_animations(self):
        """Setup smooth animations for interactions"""
        self.expand_animation = QPropertyAnimation(self.details_widget, b"maximumHeight")
        self.expand_animation.setDuration(300)
        self.expand_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    
    def toggle_details(self):
        """Toggle details with smooth animation"""
        if self.details_expanded:
            # Collapse
            self.expand_animation.setStartValue(self.details_widget.height())
            self.expand_animation.setEndValue(0)
            self.expand_animation.finished.connect(lambda: self.details_widget.setVisible(False))
            self.toggle_btn.setText("▼ Show Details")
            self.details_expanded = False
        else:
            # Expand
            self.details_widget.setVisible(True)
            self.details_widget.adjustSize()
            target_height = self.details_widget.sizeHint().height()
            
            self.expand_animation.setStartValue(0)
            self.expand_animation.setEndValue(target_height)
            self.toggle_btn.setText("▲ Hide Details")
            self.details_expanded = True
        
        self.expand_animation.start()

class ModernDropArea(QFrame):
    """Ultra-modern drop area with enhanced animations and multiple file support"""
    
    fileDropped = Signal(list)  # List of Path objects
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.setAcceptDrops(True)
        self.is_dragging = False
        self.max_file_size_mb = 25
        self.setup_animations()
    
    def setup_ui(self):
        self.setMinimumHeight(250)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Animated icon container
        self.icon_container = QWidget()
        self.icon_container.setFixedSize(80, 80)
        icon_layout = QVBoxLayout(self.icon_container)
        icon_layout.setContentsMargins(0, 0, 0, 0)
        
        self.icon_label = QLabel("📄")
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label.setFont(QFont("Segoe UI Emoji", 48))
        self.icon_label.setStyleSheet("color: #666;")
        icon_layout.addWidget(self.icon_label)
        
        # Main text
        self.main_text = QLabel("Drop PDF files here to scan")
        self.main_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.main_text.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        self.main_text.setStyleSheet("color: #333;")
        
        # Subtitle with enhanced styling
        subtitle = QLabel("Supports multiple files • Max 25MB per file • Drag & Drop or Browse")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setStyleSheet("color: #888; line-height: 1.4;")
        subtitle.setWordWrap(True)
        
        # Enhanced button with gradient
        self.browse_btn = QPushButton("📁 Browse Files")
        self.browse_btn.setFixedSize(140, 45)
        self.browse_btn.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self.browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.browse_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2196F3, stop:1 #1976D2);
                color: white;
                border: none;
                border-radius: 22px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1976D2, stop:1 #0D47A1);
                
            }
            QPushButton:pressed {
                
            }
        """)
        self.browse_btn.clicked.connect(self.browse_files)
        
        layout.addWidget(self.icon_container, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.main_text)
        layout.addWidget(subtitle)
        layout.addWidget(self.browse_btn, 0, Qt.AlignmentFlag.AlignCenter)
        
        self.update_style(False)
    
    def setup_animations(self):
        """Setup smooth animations for drag interactions"""
        self.pulse_animation = QPropertyAnimation(self.icon_container, b"geometry")
        self.pulse_animation.setDuration(1000)
        self.pulse_animation.setLoopCount(-1)  # Infinite loop
        
        self.hover_animation = QPropertyAnimation(self, b"geometry")
        self.hover_animation.setDuration(200)
        self.hover_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    
    def update_style(self, is_dragging: bool):
        """Update visual style with enhanced gradients"""
        if is_dragging:
            self.setStyleSheet("""
                ModernDropArea {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #E3F2FD, stop:0.5 #BBDEFB, stop:1 #90CAF9);
                    border: 3px dashed #2196F3;
                    border-radius: 20px;
                }
            """)
            self.main_text.setText("🎯 Release to scan PDFs")
            self.main_text.setStyleSheet("color: #1976D2; font-weight: bold;")
            self.icon_label.setText("📥")
        else:
            self.setStyleSheet("""
                ModernDropArea {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #FAFAFA, stop:0.5 #F5F5F5, stop:1 #EEEEEE);
                    border: 2px dashed #CCCCCC;
                    border-radius: 20px;
                }
                ModernDropArea:hover {
                    border-color: #2196F3;
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #F8F9FA, stop:0.5 #E9ECEF, stop:1 #DEE2E6);
                }
            """)
            self.main_text.setText("Drop PDF files here to scan")
            self.main_text.setStyleSheet("color: #333;")
            self.icon_label.setText("📄")
    
    def dragEnterEvent(self, event):
        if self.is_valid_drop(event):
            event.acceptProposedAction()
            self.is_dragging = True
            self.update_style(True)
    
    def dragLeaveEvent(self, event):
        self.is_dragging = False
        self.update_style(False)
    
    def dropEvent(self, event):
        self.is_dragging = False
        self.update_style(False)
        
        urls = event.mimeData().urls()
        valid_files = []
        
        for url in urls:
            if url.isLocalFile():
                file_path = Path(url.toLocalFile())
                if file_path.suffix.lower() == '.pdf':
                    valid_files.append(file_path)
        
        if valid_files:
            self.fileDropped.emit(valid_files)
    
    def is_valid_drop(self, event):
        """Enhanced validation for dropped files"""
        if not event.mimeData().hasUrls():
            return False
        
        for url in event.mimeData().urls():
            if url.isLocalFile():
                path = Path(url.toLocalFile())
                if path.suffix.lower() == '.pdf':
                    return True
        return False
    
    def browse_files(self):
        """Browse for multiple PDF files"""
        file_paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select PDF Files",
            "",
            "PDF Files (*.pdf);;All Files (*)"
        )
        
        if file_paths:
            valid_files = [Path(fp) for fp in file_paths]
            self.fileDropped.emit(valid_files)

class PDFScannerGUI(QMainWindow):
    """Modern PDF Scanner with PySide6 and enhanced UX"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.scan_history = []
        self.current_worker = None
        
        # Apply modern theme
        self.apply_modern_theme()
    
    def apply_modern_theme(self):
        """Apply modern dark/light theme"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #FAFAFA;
                color: #333;
            }
            QMenuBar {
                background-color: white;
                border-bottom: 1px solid #E0E0E0;
                padding: 4px;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 8px 12px;
                border-radius: 4px;
            }
            QMenuBar::item:selected {
                background-color: #E3F2FD;
            }
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QScrollBar:vertical {
                background-color: #F0F0F0;
                width: 12px;
                border-radius: 6px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #CCCCCC;
                border-radius: 6px;
                min-height: 20px;
                margin: 2px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #AAAAAA;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QStatusBar {
                background-color: white;
                border-top: 1px solid #E0E0E0;
                color: #666;
            }
        """)
    
    def setup_ui(self):
        self.setWindowTitle("🛡️ PDF Threat Scanner - Enhanced Edition")
        self.setMinimumSize(1000, 800)
        self.resize(1200, 900)
        
        # Set window icon
        self.setWindowIcon(QIcon.fromTheme("application-pdf"))  # Placeholder icon :contentReference[oaicite:1]{index=1}

        # ---- Menu Bar ----
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # ---- Central Widget & Layout ----
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(12)
        
        # ---- Drop Area ----
        self.drop_area = ModernDropArea()
        main_layout.addWidget(self.drop_area)
        
        # ---- Status & Progress ----
        status_container = QWidget()
        status_layout = QHBoxLayout(status_container)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(10)
        
        self.status_label = QLabel("Ready")
        self.status_label.setFont(QFont("Segoe UI", 10))
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        
        status_layout.addWidget(self.status_label, 1)
        status_layout.addWidget(self.progress_bar, 0)
        main_layout.addWidget(status_container)
        
        # ---- Results Area ----
        self.results_area = QScrollArea()
        self.results_area.setWidgetResizable(True)
        self.results_widget = QWidget()
        self.results_layout = QVBoxLayout(self.results_widget)
        self.results_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.results_area.setWidget(self.results_widget)
        main_layout.addWidget(self.results_area, 1)
        
        # ---- Connections ----
        self.drop_area.fileDropped.connect(self.start_scan)
    
    # ---------- Scan Control & Handlers ----------
    def start_scan(self, file_paths):
        """Initiate scanning of one or more PDF files"""
        # Cancel any existing worker
        if self.current_worker is not None:
            self.current_worker.cancel()
        
        # Clear previous results
        self.clear_results()
        self.progress_bar.setValue(0)
        self.status_label.setText("Initializing scan...")
        
        # Start new worker
        self.current_worker = ScanWorker(file_paths)
        self.current_worker.progressUpdate.connect(self.on_progress_update)
        self.current_worker.progressValue.connect(self.progress_bar.setValue)
        self.current_worker.scanComplete.connect(self.on_scan_complete)
        self.current_worker.scanError.connect(self.on_scan_error)
        self.current_worker.start()
    
    def on_progress_update(self, message):
        """Update status label with progress messages"""
        self.status_label.setText(message)
    
    def on_scan_complete(self, result: ScanResult):
        """Add a ThreatCard to the results area when a file has been scanned"""
        card = ThreatCard(result)
        self.results_layout.addWidget(card)
        self.scan_history.append(result)
        self.status_label.setText(f"Finished scanning: {result.file_path.name}")
    
    def on_scan_error(self, message):
        """Show error dialog if scanning fails"""
        QMessageBox.critical(self, "Scan Error", message)
        self.status_label.setText("Error during scan")
    
    def clear_results(self):
        """Remove all existing threat cards from the results area"""
        for i in reversed(range(self.results_layout.count())):
            widget = self.results_layout.itemAt(i).widget()
            if widget is not None:
                widget.setParent(None)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PDFScannerGUI()
    window.show()
    sys.exit(app.exec())
