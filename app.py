#!/usr/bin/env python3
"""
Pattern Search Toolkit - Standalone Application
Advanced Pattern Search & Replace Tool for Firmware Files
"""

import sys
import os
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import required modules
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QLabel, QFileDialog, QMessageBox
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QFont

# Import our core modules
from core.pattern_engine import PatternSearchDialog
from ui_theme import apply_theme

class PatternSearchApp(QMainWindow):
    """Main application window for Pattern Search Toolkit"""
    
    def __init__(self):
        super().__init__()
        self.workspace_dir = str(Path.cwd())
        self.init_ui()
        self.apply_styling()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("🔍 Pattern Search Toolkit")
        self.setGeometry(100, 100, 600, 400)
        
        # Set window icon if available
        icon_path = Path(__file__).parent / "icons" / "hex.svg"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Title
        title = QLabel("🔍 Pattern Search Toolkit")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setStyleSheet("""
            QLabel {
                color: #2c3e50;
                margin: 20px 0;
                padding: 15px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                    stop:0 #f8f9fa, stop:1 #e9ecef);
                border-radius: 10px;
                border: 2px solid #3498db;
            }
        """)
        layout.addWidget(title)
        
        # Description
        desc = QLabel("Advanced Pattern Search & Replace Tool for Firmware Files\n\n"
                     "✨ Beautiful Modern Interface\n"
                     "🛡️ Advanced Safety Mechanisms\n" 
                     "🔍 Text, Binary & Config Pattern Support\n"
                     "💾 Automatic Backup System")
        desc.setAlignment(Qt.AlignCenter)
        desc.setFont(QFont("Arial", 11))
        desc.setStyleSheet("""
            QLabel {
                color: #34495e;
                padding: 20px;
                background: #f8f9fa;
                border-radius: 8px;
                border: 1px solid #dee2e6;
                line-height: 1.6;
            }
        """)
        layout.addWidget(desc)
        
        # Launch button
        launch_btn = QPushButton("🚀 Launch Pattern Search")
        launch_btn.setFont(QFont("Arial", 14, QFont.Bold))
        launch_btn.setMinimumHeight(60)
        launch_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #3498db, stop:1 #2980b9);
                color: white;
                border: none;
                border-radius: 10px;
                padding: 15px;
                font-size: 16px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2980b9, stop:1 #1f5582);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1f5582, stop:1 #174a6e);
            }
        """)
        launch_btn.clicked.connect(self.launch_pattern_search)
        layout.addWidget(launch_btn)
        
        # Tools section
        tools_label = QLabel("🛠️ Additional Tools:")
        tools_label.setFont(QFont("Arial", 12, QFont.Bold))
        tools_label.setStyleSheet("color: #2c3e50; margin-top: 10px;")
        layout.addWidget(tools_label)
        
        # Tool buttons
        tools_layout = QVBoxLayout()
        
        integrity_btn = QPushButton("🔍 Firmware Integrity Checker")
        integrity_btn.clicked.connect(self.launch_integrity_checker)
        integrity_btn.setStyleSheet(self.get_tool_button_style("#27ae60"))
        tools_layout.addWidget(integrity_btn)
        
        fixer_btn = QPushButton("🔧 Pattern Search Fixer")
        fixer_btn.clicked.connect(self.launch_pattern_fixer)
        fixer_btn.setStyleSheet(self.get_tool_button_style("#e67e22"))
        tools_layout.addWidget(fixer_btn)
        
        monitor_btn = QPushButton("📊 Firmware Monitor")
        monitor_btn.clicked.connect(self.launch_firmware_monitor)
        monitor_btn.setStyleSheet(self.get_tool_button_style("#9b59b6"))
        tools_layout.addWidget(monitor_btn)
        
        layout.addLayout(tools_layout)
        
        # Status
        status = QLabel("Ready to search patterns in firmware files! 🎯")
        status.setAlignment(Qt.AlignCenter)
        status.setStyleSheet("color: #27ae60; font-weight: bold; margin-top: 10px;")
        layout.addWidget(status)
        
    def get_tool_button_style(self, color):
        """Get styling for tool buttons"""
        return f"""
            QPushButton {{
                background: {color};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 12px;
                margin: 2px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background: {color}dd;
            }}
            QPushButton:pressed {{
                background: {color}bb;
            }}
        """
        
    def apply_styling(self):
        """Apply theme to the application"""
        try:
            apply_theme(self)
        except:
            pass  # Fallback to default styling
            
    def launch_pattern_search(self):
        """Launch the Pattern Search Dialog"""
        try:
            dialog = PatternSearchDialog(self, self.workspace_dir)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch Pattern Search:\n{str(e)}")
            
    def launch_integrity_checker(self):
        """Launch Firmware Integrity Checker"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Firmware File for Integrity Check",
            self.workspace_dir,
            "Firmware Files (*.bin *.img *.fw *.rom);;All Files (*)"
        )
        
        if file_path:
            try:
                import subprocess
                import sys
                script_path = Path(__file__).parent / "firmware_integrity_checker.py"
                subprocess.Popen([sys.executable, str(script_path), "--check", file_path])
                QMessageBox.information(self, "Info", "Firmware Integrity Checker launched in terminal.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to launch integrity checker:\n{str(e)}")
                
    def launch_pattern_fixer(self):
        """Launch Pattern Search Fixer"""
        try:
            import subprocess
            import sys
            script_path = Path(__file__).parent / "pattern_search_fixer.py"
            subprocess.Popen([sys.executable, str(script_path), "--scan"])
            QMessageBox.information(self, "Info", "Pattern Search Fixer launched in terminal.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch pattern fixer:\n{str(e)}")
            
    def launch_firmware_monitor(self):
        """Launch Firmware Monitor"""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Directory to Monitor",
            self.workspace_dir
        )
        
        if dir_path:
            try:
                import subprocess
                import sys
                script_path = Path(__file__).parent / "firmware_monitor.py"
                subprocess.Popen([sys.executable, str(script_path), dir_path])
                QMessageBox.information(self, "Info", f"Firmware Monitor started for:\n{dir_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to launch firmware monitor:\n{str(e)}")

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Pattern Search Toolkit")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Firmware Tools")
    
    # Create and show main window
    window = PatternSearchApp()
    window.show()
    
    return app.exec()

if __name__ == "__main__":
    sys.exit(main())
