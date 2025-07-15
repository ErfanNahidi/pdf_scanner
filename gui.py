import sys
from pathlib import Path
import webbrowser
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QFrame, QFileDialog,
    QMessageBox, QScrollArea, QProgressBar, QGraphicsDropShadowEffect,
    QSplitter, QGraphicsOpacityEffect, QDialog, QDialogButtonBox
)
from PySide6.QtCore import (
    Qt, QThread, Signal, QPropertyAnimation,
    QEasingCurve, QSettings, QRectF, QAbstractAnimation, Property, QUrl, QSize
)
from PySide6.QtGui import QFont, QColor, QPainter, QPen, QIcon, QPixmap, QDesktopServices
from PySide6.QtSvgWidgets import QSvgWidget

# --- Real Backend Integration ---
try:
    from backend import PDFScanner, ScanResult, ThreatLevel
except ImportError:
    QMessageBox.critical(None, "Backend Error", "Could not find backend.py. Please ensure it's in the same directory as gui.py.")
    sys.exit(1)

# --- App Information ---
APP_VERSION = "4.0.0"
RELEASE_DATE = "July 2025"
GITHUB_URL = "https://github.com/ErfanNahidi/pdf_scanner/"

class ThemeManager:
    """Manages the application's visual themes."""
    THEMES = {
        "dark": {"window_bg":"#1a1b1e","header_bg":"rgba(35, 36, 40, 0.8)","content_bg":"#2b2d31","content_bg_light":"#383a40","primary_text":"#f2f3f5","secondary_text":"#b8b9bf","accent":"#5865f2","accent_fg":"#ffffff","border":"#35363a","drop_area_bg":"rgba(88,101,242,0.1)","drop_area_border":"#5865f2","danger":"#f23f42"},
        "light": {"window_bg":"#f2f3f5","header_bg":"rgba(255, 255, 255, 0.8)","content_bg":"#ffffff","content_bg_light":"#f8f9fa","primary_text":"#2e3338","secondary_text":"#5c6773","accent":"#0078d4","accent_fg":"#ffffff","border":"#e1e4e8","drop_area_bg":"rgba(0,120,212,0.05)","drop_area_border":"#0078d4","danger":"#d93025"}
    }
    THREAT_COLORS = {
        "dark": {ThreatLevel.SAFE:{"bar":"#2d7d46"}, ThreatLevel.LOW:{"bar":"#f0b232"}, ThreatLevel.MEDIUM:{"bar":"#f28c18"}, ThreatLevel.HIGH:{"bar":"#f25822"}, ThreatLevel.CRITICAL:{"bar":"#ed4245"}},
        "light": {ThreatLevel.SAFE:{"bar":"#4caf50"}, ThreatLevel.LOW:{"bar":"#ffc107"}, ThreatLevel.MEDIUM:{"bar":"#ff9800"}, ThreatLevel.HIGH:{"bar":"#ff5722"}, ThreatLevel.CRITICAL:{"bar":"#f44336"}}
    }

    def __init__(self): self.set_theme("dark")
    def set_theme(self, name): self.theme, self.colors, self.threat_palette = name, self.THEMES[name], self.THREAT_COLORS[name]
    def get_threat_color(self, level: ThreatLevel): return self.threat_palette.get(level, self.threat_palette[ThreatLevel.LOW])

theme_manager = ThemeManager()

class AboutDialog(QDialog):
    """A custom dialog to show application information."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About PDF Threat Scanner")
        self.setMinimumWidth(350)
        self.init_ui()
        self.update_stylesheet()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("PDF Threat Scanner"); title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold)); title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        creator = QLabel(f"Created by: Erfan Nahidi"); creator.setFont(QFont("Segoe UI", 11)); creator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version = QLabel(f"Version: {APP_VERSION} ({RELEASE_DATE})"); version.setFont(QFont("Segoe UI", 10)); version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        github_btn = self.create_github_button()
        
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        button_box.accepted.connect(self.accept)

        layout.addWidget(title)
        layout.addWidget(creator)
        layout.addWidget(version)
        layout.addWidget(github_btn, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(button_box)
        
    def create_github_button(self):
        github_btn = QPushButton(" View on GitHub")
        github_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        github_btn.setFont(QFont("Segoe UI", 10))
        github_btn.setIconSize(QSize(24, 24))
        github_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(GITHUB_URL)))
        self.github_button = github_btn # Store for theme updates
        return github_btn

    def update_stylesheet(self):
        colors = theme_manager.colors
        self.setStyleSheet(f"""
            QDialog {{ background-color: {colors['window_bg']}; color: {colors['primary_text']}; }}
            QPushButton {{ 
                background-color: {colors['content_bg_light']}; 
                color: {colors['primary_text']};
                border: 1px solid {colors['border']};
                padding: 8px 16px;
                border-radius: 8px;
            }}
            QPushButton:hover {{ background-color: {colors['border']}; }}
        """)
        
        # Update GitHub icon color based on theme
        svg_data = f"""
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">
          <path fill="{colors['primary_text']}" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
        </svg>
        """.encode('utf-8')
        pixmap = QPixmap()
        pixmap.loadFromData(svg_data)
        self.github_button.setIcon(QIcon(pixmap))

class ThemeToggle(QPushButton):
    """A custom animated toggle switch for changing themes."""
    theme_changed = Signal(str)
    def __init__(self, parent=None):
        super().__init__(parent); self.setCheckable(True); self.setChecked(theme_manager.theme == "dark"); self.setFixedSize(60, 30); self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._knob_position = 32 if self.isChecked() else 4
        self.knob_anim = QPropertyAnimation(self, b"knob_position", self); self.knob_anim.setDuration(200); self.knob_anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
        self.toggled.connect(self._on_toggle)

    def _on_toggle(self, checked): self.knob_anim.setStartValue(self.knob_position); self.knob_anim.setEndValue(32 if checked else 4); self.knob_anim.start(); self.theme_changed.emit("dark" if checked else "light")
    @Property(float)
    def knob_position(self): return self._knob_position
    @knob_position.setter
    def knob_position(self, pos): self._knob_position = pos; self.update()

    def paintEvent(self, event):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        track = QColor("#5865f2") if self.isChecked() else QColor("#747f8d"); knob, icon = QColor("#ffffff"), QColor("#1e2124") if self.isChecked() else QColor("#ffffff")
        p.setPen(Qt.PenStyle.NoPen); p.setBrush(track); p.drawRoundedRect(0,0,self.width(),self.height(),15,15)
        rect = QRectF(self.knob_position-2,3,24,24)
        p.setBrush(knob); p.drawEllipse(rect)
        font = QFont("Segoe UI Symbol",10); p.setFont(font); p.setPen(QPen(icon)); p.drawText(rect, Qt.AlignmentFlag.AlignCenter, "🌙" if self.isChecked() else "☀️")

class ScanWorker(QThread):
    """Worker thread that uses the real PDFScanner from backend.py."""
    scan_complete = Signal(ScanResult); progress_update = Signal(str, int); scan_error = Signal(str); finished = Signal(int)
    def __init__(self, scanner: PDFScanner, file_paths: list[Path]):
        super().__init__()
        self.scanner = scanner
        self.file_paths = file_paths
        self._is_cancelled = False

    def run(self):
        total = len(self.file_paths)
        for i, path in enumerate(self.file_paths):
            if self._is_cancelled: break
            self.progress_update.emit(f"Scanning [{i+1}/{total}]: {path.name}", int(((i + 1) / total) * 100))
            try:
                result = self.scanner.scan_pdf(path)
                self.scan_complete.emit(result)
            except Exception as e:
                self.scan_error.emit(f"An unexpected error occurred during scan of {path.name}: {e}")
        if not self._is_cancelled: self.finished.emit(total)

    def cancel(self): self._is_cancelled = True

class ThreatCard(QFrame):
    """Card widget with the user-preferred detailed UI and animations."""
    def __init__(self, result: ScanResult, parent=None):
        super().__init__(parent)
        self.result = result
        self.details_expanded = False
        self.toggle_btn = None
        self._init_ui()
        self.setup_animations()

    def _init_ui(self):
        self.setFrameStyle(QFrame.Shape.NoFrame)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        
        while self.layout() and self.layout().count():
            item = self.layout().takeAt(0)
            if widget := item.widget(): widget.deleteLater()

        card_layout = QVBoxLayout(self); card_layout.setSpacing(16)
        self.update_stylesheet()
        
        card_layout.addWidget(self.create_header())
        card_layout.addWidget(self.create_summary_section())
        self.details_widget = QWidget()
        self.details_layout = QVBoxLayout(self.details_widget)
        self.details_layout.setContentsMargins(0, 10, 0, 0)
        
        if self.result.success and (self.result.details or self.result.recommendations):
            self.setup_details_section()
            self.toggle_btn = self.create_toggle_button()
            card_layout.addWidget(self.toggle_btn)
            self.details_widget.setVisible(False)

        if not self.result.success and self.result.error_message:
            card_layout.addWidget(self.create_error_section())

        card_layout.addWidget(self.details_widget)

    def update_stylesheet(self):
        self.threat_colors = theme_manager.get_threat_color(self.result.threat_level)
        self.setStyleSheet(f"ThreatCard {{ background-color: {theme_manager.colors['content_bg']}; border: 1px solid {self.threat_colors['bar']}; border-radius: 12px; padding: 15px; }}")

    def create_header(self):
        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)

        threat_emojis = {"SAFE": "🛡️", "LOW": "🔔", "MEDIUM": "⚠️", "HIGH": "🔥", "CRITICAL": "💀"}
        icon = QLabel(threat_emojis.get(self.result.threat_level.value.upper(), "❓")); icon.setFont(QFont("Segoe UI Emoji", 24))
        
        name_container = QVBoxLayout()
        file_name = QLabel(self.result.file_path.name); file_name.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        file_path_label = QLabel(str(self.result.file_path.parent)); file_path_label.setFont(QFont("Segoe UI", 9)); file_path_label.setStyleSheet(f"color: {theme_manager.colors['secondary_text']};")
        name_container.addWidget(file_name); name_container.addWidget(file_path_label)

        badge = QLabel(self.result.threat_level.value.upper()); badge.setAlignment(Qt.AlignmentFlag.AlignCenter); badge.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        badge.setStyleSheet(f"background-color: {self.threat_colors['bar']}; color: #ffffff; padding: 6px 12px; border-radius: 15px;")

        header_layout.addWidget(icon); header_layout.addLayout(name_container, 1); header_layout.addWidget(badge)
        return header_widget

    def create_summary_section(self):
        summary_label = QLabel(self.result.summary); summary_label.setFont(QFont("Segoe UI", 11)); summary_label.setWordWrap(True)
        summary_label.setStyleSheet(f"color: {theme_manager.colors['secondary_text']};")
        return summary_label

    def create_error_section(self):
        error_widget = QFrame(); error_widget.setObjectName("DetailItem")
        error_layout = QVBoxLayout(error_widget)
        error_header = QLabel("❌ Scan Failed"); error_header.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold)); error_header.setStyleSheet(f"color: {theme_manager.colors['danger']};")
        error_label = QLabel(self.result.error_message); error_label.setWordWrap(True)
        error_layout.addWidget(error_header); error_layout.addWidget(error_label)
        return error_widget

    def create_toggle_button(self):
        button = QPushButton("▼ Show Full Report"); button.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold)); button.setCursor(Qt.CursorShape.PointingHandCursor); button.setFixedHeight(35)
        button.setStyleSheet(f"QPushButton {{ background-color: {theme_manager.colors['accent']}; color: {theme_manager.colors['accent_fg']}; border: none; border-radius: 8px; }} QPushButton:hover {{ background-color: {QColor(theme_manager.colors['accent']).lighter(110).name()}; }}")
        button.clicked.connect(self.toggle_details)
        return button
        
    def setup_details_section(self):
        if self.result.success and self.result.details: self.create_analysis_details()
        if self.result.recommendations: self.create_recommendations_section()

    def create_analysis_details(self):
        title = QLabel("🔍 Detailed Analysis"); title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold)); self.details_layout.addWidget(title)
        container = QFrame(); container.setObjectName("DetailItem"); grid_layout = QVBoxLayout(container)
        
        for keyword, count in self.result.details.items():
            if keyword == 'large_file' or count == 0: continue
            
            item_layout = QHBoxLayout()
            key_label = QLabel(f"<b>{keyword}</b>"); key_label.setFixedWidth(120)
            
            if keyword == 'file_size_mb': value_label = QLabel(f"{count:.2f} MB")
            else: value_label = QLabel(str(count))
            
            item_layout.addWidget(key_label); item_layout.addWidget(value_label, 1)
            
            if keyword in self.scanner.THREAT_DEFINITIONS:
                desc = self.scanner.THREAT_DEFINITIONS[keyword]["desc"]
                desc_label = QLabel(f"<i>({desc})</i>"); desc_label.setWordWrap(True); desc_label.setStyleSheet(f"color: {theme_manager.colors['secondary_text']};")
                item_layout.addWidget(desc_label, 2)

            grid_layout.addLayout(item_layout)
        self.details_layout.addWidget(container)

    def create_recommendations_section(self):
        title = QLabel("💡 Security Recommendations"); title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold)); self.details_layout.addWidget(title)
        container = QFrame(); container.setObjectName("DetailItem"); layout = QVBoxLayout(container)
        for rec in self.result.recommendations:
            rec_label = QLabel(f"• {rec}"); rec_label.setWordWrap(True); layout.addWidget(rec_label)
        self.details_layout.addWidget(container)

    def setup_animations(self):
        shadow = QGraphicsDropShadowEffect(self); shadow.setBlurRadius(15); shadow.setColor(QColor(0,0,0,60)); shadow.setOffset(0,4); self.setGraphicsEffect(shadow)
        self.expand_animation = QPropertyAnimation(self.details_widget, b"maximumHeight", self); self.expand_animation.setDuration(350); self.expand_animation.setEasingCurve(QEasingCurve.Type.InOutCubic)

    def toggle_details(self):
        if self.details_expanded:
            self.expand_animation.setStartValue(self.details_widget.height()); self.expand_animation.setEndValue(0)
            self.expand_animation.finished.connect(lambda: self.details_widget.setVisible(False))
            self.toggle_btn.setText("▼ Show Full Report")
        else:
            self.details_widget.setVisible(True)
            target_height = self.details_widget.sizeHint().height()
            self.expand_animation.setStartValue(0); self.expand_animation.setEndValue(target_height)
            self.toggle_btn.setText("▲ Hide Full Report")
        self.expand_animation.start(); self.details_expanded = not self.details_expanded

class ModernDropArea(QFrame):
    """A stylish area for dragging and dropping files."""
    fileDropped = Signal(list)
    def __init__(self, parent=None): super().__init__(parent); self.setAcceptDrops(True); self._init_ui()
    def _init_ui(self):
        self.setMinimumHeight(250); layout = QVBoxLayout(self); layout.setAlignment(Qt.AlignmentFlag.AlignCenter); layout.setSpacing(15)
        icon = QLabel("📂"); icon.setFont(QFont("Segoe UI Emoji", 50)); icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        text = QLabel("Drop PDF Files to Scan"); text.setFont(QFont("Segoe UI",20,QFont.Weight.Bold)); text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.browse_btn = QPushButton("Or Browse Files"); self.browse_btn.setFixedSize(200,50); self.browse_btn.setFont(QFont("Segoe UI",11,QFont.Weight.Bold)); self.browse_btn.setCursor(Qt.CursorShape.PointingHandCursor); self.browse_btn.clicked.connect(self.browse_files)
        layout.addWidget(icon); layout.addWidget(text); layout.addWidget(self.browse_btn); self.update_style(False)
    def update_style(self, hovering):
        color = theme_manager.colors["drop_area_border"] if hovering else theme_manager.colors["border"]; bg = theme_manager.colors["drop_area_bg"] if hovering else "transparent"; accent, accent_fg = theme_manager.colors["accent"], theme_manager.colors["accent_fg"]
        self.setStyleSheet(f"ModernDropArea{{border:2px dashed {color};border-radius:12px;background-color:{bg};}} QPushButton{{background-color:{accent};color:{accent_fg};border:none;border-radius:8px;}} QPushButton:hover{{background-color:{QColor(accent).lighter(110).name()};}}")
    def browse_files(self):
        settings = QSettings("MyCompany","PDFScanner"); last_dir = settings.value("last_dir",str(Path.home())); files, _ = QFileDialog.getOpenFileNames(self,"Select PDF(s)",last_dir,"PDF Files (*.pdf)")
        if files: settings.setValue("last_dir",str(Path(files[0]).parent)); self.fileDropped.emit([Path(f) for f in files])
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls() and any(u.toLocalFile().lower().endswith('.pdf') for u in e.mimeData().urls()): e.acceptProposedAction(); self.update_style(True)
    def dragLeaveEvent(self, e): self.update_style(False)
    def dropEvent(self, e):
        self.update_style(False); files = [Path(u.toLocalFile()) for u in e.mimeData().urls() if u.toLocalFile().lower().endswith('.pdf')]
        if files: self.fileDropped.emit(files)

class PDFThreatScannerApp(QMainWindow):
    """The main application window."""
    def __init__(self):
        super().__init__()
        self._scan_worker = None
        self._is_scanning = False
        self.about_dialog = None # BUG FIX: Initialize before use
        self._load_settings()
        self.scanner = PDFScanner()
        ThreatCard.scanner = self.scanner
        self._init_ui()
        self._apply_theme(theme_manager.theme)

    def _init_ui(self):
        self.setWindowTitle("PDF Threat Scanner"); self.setMinimumSize(800,700); self.resize(1000,800)
        central_widget = QWidget(); self.setCentralWidget(central_widget); main_layout = QVBoxLayout(central_widget); main_layout.setContentsMargins(0,0,0,0); main_layout.setSpacing(0)
        main_layout.addWidget(self._create_header_bar())
        content_widget = QWidget(); content_layout = QVBoxLayout(content_widget); content_layout.setContentsMargins(20,20,20,20); main_layout.addWidget(content_widget,1)
        self.splitter = QSplitter(Qt.Orientation.Vertical); self.splitter.setHandleWidth(4)
        self.drop_area = ModernDropArea(); self.drop_area.fileDropped.connect(self.start_scan)
        self._create_progress_area(); self._create_results_area()
        top_container = QWidget(); top_layout = QVBoxLayout(top_container); top_layout.setContentsMargins(0,0,0,0)
        top_layout.addWidget(self.drop_area); top_layout.addWidget(self.progress_widget)
        self.splitter.addWidget(top_container); self.splitter.addWidget(self.results_area)
        self.splitter.setSizes([300,400]); content_layout.addWidget(self.splitter)

    def _create_header_bar(self):
        header = QFrame(); header.setObjectName("Header"); header.setFixedHeight(50); layout = QHBoxLayout(header); layout.setContentsMargins(20,0,10,0)
        title = QLabel("PDF Threat Scanner"); title.setFont(QFont("Segoe UI",12,QFont.Weight.Bold))
        
        self.theme_toggle = ThemeToggle(); self.theme_toggle.theme_changed.connect(self._apply_theme)
        
        about_btn = QPushButton("ℹ️"); about_btn.setFont(QFont("Segoe UI Emoji", 12)); about_btn.setFixedSize(40, 40); about_btn.setObjectName("HeaderButton")
        about_btn.setCursor(Qt.CursorShape.PointingHandCursor); about_btn.clicked.connect(self.show_about_dialog)

        layout.addWidget(title); layout.addStretch(); layout.addWidget(about_btn); layout.addWidget(self.theme_toggle)
        return header

    def show_about_dialog(self):
        if not self.about_dialog:
            self.about_dialog = AboutDialog(self)
        self.about_dialog.update_stylesheet() # Ensure it has the latest theme
        self.about_dialog.exec()

    def _create_progress_area(self):
        self.progress_widget = QWidget(); layout = QVBoxLayout(self.progress_widget); layout.setContentsMargins(0,15,0,0)
        self.status_label = QLabel("Starting scan..."); self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_bar = QProgressBar(); self.progress_bar.setFixedHeight(6); self.progress_bar.setTextVisible(False)
        self.cancel_btn = QPushButton("Cancel Scan"); self.cancel_btn.setObjectName("CancelButton"); self.cancel_btn.setFixedSize(150,40); self.cancel_btn.setFont(QFont("Segoe UI",10,QFont.Weight.Bold)); self.cancel_btn.clicked.connect(self.cancel_or_clear_scan)
        layout.addWidget(self.status_label); layout.addWidget(self.progress_bar); layout.addWidget(self.cancel_btn, alignment=Qt.AlignmentFlag.AlignCenter)
        self.progress_widget.setVisible(False)

    def _create_results_area(self):
        self.results_area = QWidget(); layout = QVBoxLayout(self.results_area); layout.setContentsMargins(0,15,0,0)
        self.scroll_area = QScrollArea(); self.scroll_area.setWidgetResizable(True); self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_content = QWidget(); self.scroll_layout = QVBoxLayout(self.scroll_content); self.scroll_layout.setSpacing(10); self.scroll_layout.addStretch()
        self.scroll_area.setWidget(self.scroll_content); layout.addWidget(self.scroll_area)
        self._show_no_results_placeholder()

    def _show_no_results_placeholder(self):
        self._clear_results_widgets(); placeholder = QWidget(); layout = QVBoxLayout(placeholder); layout.setAlignment(Qt.AlignmentFlag.AlignCenter); layout.setSpacing(15)
        icon = QLabel("🔎"); icon.setFont(QFont("Segoe UI Emoji", 50)); text = QLabel("Scan a file to see the results here"); text.setObjectName("PlaceholderText"); text.setFont(QFont("Segoe UI",14,QFont.Weight.Bold))
        layout.addWidget(icon); layout.addWidget(text); self.scroll_layout.insertWidget(0, placeholder)

    def _clear_results_widgets(self):
        while self.scroll_layout.count() > 1:
            if widget := self.scroll_layout.takeAt(0).widget(): widget.deleteLater()

    def start_scan(self, file_paths):
        if self._is_scanning: return
        self._is_scanning = True; self.drop_area.setVisible(False); self.progress_widget.setVisible(True); self._clear_results_widgets()
        self.status_label.setText("Initializing..."); self.progress_bar.setValue(0); self.cancel_btn.setText("Cancel Scan"); self.cancel_btn.setObjectName("CancelButton"); self._apply_theme_to_buttons()
        self._scan_worker = ScanWorker(self.scanner, file_paths)
        self._scan_worker.scan_complete.connect(lambda r: self.scroll_layout.insertWidget(0, ThreatCard(r)))
        self._scan_worker.progress_update.connect(lambda msg, val: (self.status_label.setText(msg), self.progress_bar.setValue(val)))
        self._scan_worker.scan_error.connect(lambda e: QMessageBox.critical(self, "Scan Error", e))
        self._scan_worker.finished.connect(self.on_scan_finished)
        self._scan_worker.start()

    def on_scan_finished(self, file_count):
        self._is_scanning = False; self.status_label.setText(f"Scan Complete: {file_count} file(s) analyzed.")
        self.cancel_btn.setText("Clear & Scan Again"); self.cancel_btn.setObjectName("AccentButton"); self._apply_theme_to_buttons()

    def cancel_or_clear_scan(self):
        if self._is_scanning and self._scan_worker: self._scan_worker.cancel(); self._scan_worker.wait()
        self._is_scanning = False; self.progress_widget.setVisible(False); self.drop_area.setVisible(True); self._show_no_results_placeholder()
        self.cancel_btn.setText("Cancel Scan"); self.cancel_btn.setObjectName("CancelButton"); self._apply_theme_to_buttons()

    def _apply_theme(self, theme_name):
        theme_manager.set_theme(theme_name); colors = theme_manager.colors
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{ background-color:{colors['window_bg']}; color:{colors['primary_text']}; border:none; }}
            QLabel {{ border: none; background-color: transparent; }}
            QFrame#Header {{ background-color:{colors['header_bg']}; border-bottom:1px solid {colors['border']}; }}
            QScrollArea, QScrollArea > QWidget > QWidget {{ background-color:transparent; }}
            QSplitter::handle {{ background-color:transparent; }}
            QProgressBar {{ border:none; border-radius:3px; background-color:{colors['content_bg_light']}; }}
            QProgressBar::chunk {{ background-color:{colors['accent']}; border-radius:3px; }}
            QFrame#DetailItem {{ background-color:{colors['content_bg_light']}; border-radius:5px; padding:12px; }}
            QLabel#PlaceholderText {{ color: {colors['secondary_text']}; }}
            QPushButton#HeaderButton {{ background-color: transparent; border-radius: 20px; }}
            QPushButton#HeaderButton:hover {{ background-color: {colors['border']}; }}
        """)
        self._apply_theme_to_buttons(); self.theme_toggle.setChecked(theme_name == "dark"); self.drop_area.update_style(False)
        for i in range(self.scroll_layout.count()):
            if isinstance(widget := self.scroll_layout.itemAt(i).widget(), ThreatCard): widget._init_ui()
        if self.about_dialog: self.about_dialog.update_stylesheet()

    def _apply_theme_to_buttons(self):
        colors = theme_manager.colors
        self.setStyleSheet(self.styleSheet() + f"""
            QPushButton#CancelButton {{ background-color:{colors['danger']}; color:#fff; border-radius:8px; font-weight:bold; }}
            QPushButton#CancelButton:hover {{ background-color:{QColor(colors['danger']).lighter(110).name()}; }}
            QPushButton#AccentButton {{ background-color:{colors['accent']}; color:{colors['accent_fg']}; border-radius:8px; font-weight:bold; }}
            QPushButton#AccentButton:hover {{ background-color:{QColor(colors['accent']).lighter(110).name()}; }}
        """)
        for i in range(self.scroll_layout.count()):
            if isinstance(widget := self.scroll_layout.itemAt(i).widget(), ThreatCard) and widget.toggle_btn:
                widget.toggle_btn.setStyleSheet(f"QPushButton {{ background-color: {colors['accent']}; color: {colors['accent_fg']}; border: none; border-radius: 8px; font-weight: bold; }} QPushButton:hover {{ background-color: {QColor(colors['accent']).lighter(110).name()}; }}")

    def _load_settings(self): settings = QSettings("MyCompany","PDFScanner"); theme_manager.set_theme(settings.value("theme","dark",type=str))
    def _save_settings(self): settings = QSettings("MyCompany","PDFScanner"); settings.setValue("theme",theme_manager.theme)
    def closeEvent(self, e): self._save_settings(); self.cancel_or_clear_scan(); e.accept()

def main():
    app = QApplication(sys.argv); app.setStyle('Fusion'); app.setApplicationName("PDFThreatScanner")
    pixmap = QPixmap(128, 128); pixmap.fill(Qt.GlobalColor.transparent)
    p = QPainter(pixmap); p.setFont(QFont("Segoe UI Emoji", 80)); p.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "🛡️"); p.end()
    app.setWindowIcon(QIcon(pixmap)); window = PDFThreatScannerApp(); window.show(); sys.exit(app.exec())

if __name__ == "__main__":
    main()
