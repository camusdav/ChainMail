import os
import datetime
import requests
from fpdf import FPDF
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QTextEdit, QPushButton, QTabWidget, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QMessageBox, QFileDialog, QLineEdit)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon, QFont, QColor
from security import CredentialManager

class LoginWindow(QMainWindow):
    def __init__(self, main_app_callback):
        super().__init__()
        self.main_app_callback = main_app_callback
        self.setWindowTitle("ChainMail - Enlace de Cuenta")
        self.resize(450, 300)
        if os.path.exists("icon.ico"):
            self.setWindowIcon(QIcon("icon.ico"))
        self.vault = CredentialManager()
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl_title = QLabel("Bienvenido a ChainMail")
        lbl_title.setObjectName("titleLabel")
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl_title)
        
        lbl_sub = QLabel("Inicia sesión de forma segura a través de Google para conectar el escudo OAuth 2.0.")
        lbl_sub.setWordWrap(True)
        lbl_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl_sub)
        
        layout.addSpacing(30)

        self.btn_login = QPushButton("Conectar con Google")
        self.btn_login.setObjectName("btnAnalyze")
        self.btn_login.clicked.connect(self.auth_google)
        layout.addWidget(self.btn_login)

    def apply_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #180A2B; }
            QLabel { color: #E0AAFF; font-family: "Trebuchet MS"; font-size: 13px; }
            #titleLabel { color: #00F0FF; font-size: 24px; font-weight: bold; }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #00F0FF, stop:1 #0077B6);
                color: #03045E;
                border: 1px solid #90E0EF;
                border-radius: 15px;
                padding: 12px;
                font-family: "Trebuchet MS";
                font-weight: bold;
                font-size: 15px;
            }
            QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #90E0EF, stop:1 #0096C7); }
        """)

    def auth_google(self):
        self.btn_login.setEnabled(False)
        self.btn_login.setText("Abriendo navegador...")
        QApplication.processEvents()
        try:
            creds = self.vault.authenticate_via_browser()
            if creds and creds.valid:
                self.close()
                self.main_app_callback()
        except Exception as e:
            QMessageBox.critical(self, "Error de Autenticación", f"No se pudo completar el enlace con Google.\n\nDetalle: {str(e)}")
            self.btn_login.setEnabled(True)
            self.btn_login.setText("Conectar con Google")

class AnalyzeWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    def __init__(self, api_url, email_content):
        super().__init__()
        self.api_url = api_url
        self.email_content = email_content
    def run(self):
        try:
            payload = {"email_content": self.email_content, "source": "Manual"}
            response = requests.post(self.api_url, json=payload, timeout=15)
            if response.status_code == 200:
                self.finished.emit(response.json())
            else:
                self.error.emit(f"Código de error {response.status_code}")
        except Exception as e:
            self.error.emit(str(e))

class PhishingAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ChainMail - Centro de Operaciones")
        self.resize(900, 750)
        
        if os.path.exists("icon.ico"):
            self.setWindowIcon(QIcon("icon.ico"))
            
        self.api_url = "http://127.0.0.1:5000/api/v1/analyze"
        self.history_url = "http://127.0.0.1:5000/api/v1/history"
        self.clear_history_url = "http://127.0.0.1:5000/api/v1/history/clear"
        self.shutdown_url = "http://127.0.0.1:5000/api/v1/shutdown"
        self.last_scan_data = None
        self.vault = CredentialManager()

        self.setup_ui()
        self.apply_frutiger_aero_theme()
        
        self.live_timer = QTimer(self)
        self.live_timer.timeout.connect(self.load_history)
        self.live_timer.start(5000) 
        
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)

        self.lbl_title = QLabel("ChainMail: Phishing Engine")
        self.lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_title.setObjectName("titleLabel")
        main_layout.addWidget(self.lbl_title)

        self.tabs = QTabWidget()
        self.tab_scan = QWidget()
        self.tab_history = QWidget()
        self.tabs.addTab(self.tab_scan, "Escáner Manual")
        self.tabs.addTab(self.tab_history, "Centro de Monitoreo")
        main_layout.addWidget(self.tabs)

        self.build_scan_tab()
        self.build_history_tab()

        footer_layout = QHBoxLayout()
        self.lbl_dev = QLabel("@Camus_Dav")
        self.lbl_dev.setObjectName("footerLabel")
        
        self.btn_logout = QPushButton("Desconectar Cuenta")
        self.btn_logout.setObjectName("btnLogout")
        self.btn_logout.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_logout.clicked.connect(self.logout_user)
        
        footer_layout.addWidget(self.lbl_dev)
        footer_layout.addStretch()
        footer_layout.addWidget(self.btn_logout)
        main_layout.addLayout(footer_layout)

    def build_scan_tab(self):
        layout = QVBoxLayout(self.tab_scan)
        self.lbl_inst = QLabel("Código fuente (.eml) o texto plano del correo:")
        layout.addWidget(self.lbl_inst)
        self.txt_email = QTextEdit()
        self.txt_email.setFont(QFont("Consolas", 11))
        layout.addWidget(self.txt_email)
        btn_layout = QHBoxLayout()
        self.btn_analyze = QPushButton("Escanear Amenazas")
        self.btn_analyze.setObjectName("btnAnalyze")
        self.btn_analyze.clicked.connect(self.analyze_email)
        self.btn_clear = QPushButton("Limpiar")
        self.btn_clear.setObjectName("btnClear")
        self.btn_clear.clicked.connect(self.clear_fields)
        self.btn_export = QPushButton("Exportar Reporte PDF")
        self.btn_export.setObjectName("btnExport")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self.export_to_pdf)
        btn_layout.addWidget(self.btn_analyze)
        btn_layout.addWidget(self.btn_clear)
        btn_layout.addWidget(self.btn_export)
        layout.addLayout(btn_layout)

        self.result_container = QWidget()
        self.result_container.setObjectName("resultContainer")
        result_layout = QVBoxLayout(self.result_container)
        self.lbl_score = QLabel("Puntaje de Riesgo: -")
        self.lbl_score.setObjectName("scoreLabel")
        self.lbl_risk = QLabel("Nivel de Amenaza: -")
        self.lbl_risk.setObjectName("riskLabel")
        self.txt_details = QTextEdit()
        self.txt_details.setFont(QFont("Consolas", 10))
        self.txt_details.setReadOnly(True)
        result_layout.addWidget(self.lbl_score)
        result_layout.addWidget(self.lbl_risk)
        result_layout.addWidget(self.txt_details)
        layout.addWidget(self.result_container)

    def build_history_tab(self):
        layout = QVBoxLayout(self.tab_history)
        btn_layout = QHBoxLayout()
        self.btn_refresh = QPushButton("Actualizar Datos")
        self.btn_refresh.setObjectName("btnInfo")
        self.btn_refresh.clicked.connect(self.load_history)
        self.btn_purge = QPushButton("Purgar Historial Antiguo")
        self.btn_purge.setObjectName("btnDanger")
        self.btn_purge.clicked.connect(self.purge_history)
        btn_layout.addWidget(self.btn_refresh)
        btn_layout.addWidget(self.btn_purge)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Estado", "Origen", "Remitente", "Veredicto", "Acción"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)
        self.load_history()

    def analyze_email(self):
        content = self.txt_email.toPlainText().strip()
        if not content:
            QMessageBox.warning(self, "Advertencia", "El campo de texto está vacío.")
            return
        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setText("Analizando...")
        self.btn_export.setEnabled(False)
        self.worker = AnalyzeWorker(self.api_url, content)
        self.worker.finished.connect(self.display_results)
        self.worker.error.connect(self.display_error)
        self.worker.start()

    def display_results(self, data):
        self.last_scan_data = data
        self.btn_analyze.setEnabled(True)
        self.btn_analyze.setText("Escanear Amenazas")
        self.btn_export.setEnabled(True)

        score = data.get("score", 0)
        risk = data.get("risk_level", "DESCONOCIDO")
        details = data.get("details", [])
        self.lbl_score.setText(f"Puntaje de Riesgo: {score}")
        self.lbl_risk.setText(f"Nivel de Amenaza: {risk}")

        if "CRÍTICO" in risk:
            self.lbl_risk.setStyleSheet("color: #FF0055; font-weight: bold; font-size: 18px;")
        elif "SOSPECHOSO" in risk:
            self.lbl_risk.setStyleSheet("color: #FFAA00; font-weight: bold; font-size: 18px;")
        else:
            self.lbl_risk.setStyleSheet("color: #00FF66; font-weight: bold; font-size: 18px;")

        self.txt_details.clear()
        if not details:
            self.txt_details.append("✓ No se detectaron anomalías heurísticas ni reportes en OSINT.")
        else:
            for idx, det in enumerate(details, 1):
                self.txt_details.append(f"[{idx}] {det}")

    def display_error(self, err_msg):
        self.btn_analyze.setEnabled(True)
        self.btn_analyze.setText("Escanear Amenazas")
        QMessageBox.critical(self, "Error API", f"No se pudo conectar al motor:\n{err_msg}")

    def clear_fields(self):
        self.txt_email.clear()
        self.lbl_score.setText("Puntaje de Riesgo: -")
        self.lbl_risk.setText("Nivel de Amenaza: -")
        self.lbl_risk.setStyleSheet("color: white; font-weight: bold; font-size: 18px;")
        self.txt_details.clear()
        self.btn_export.setEnabled(False)
        self.last_scan_data = None

    def export_to_pdf(self):
        if not self.last_scan_data:
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar Reporte ChainMail", 
            f"Reporte_ChainMail_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            "Documentos PDF (*.pdf)"
        )
        if not file_path:
            return
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("helvetica", "B", 22)
            pdf.set_text_color(157, 78, 221)
            pdf.cell(0, 15, "ChainMail: Reporte de Inteligencia", align="C", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "I", 10)
            pdf.set_text_color(100, 100, 100)
            fecha = datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            pdf.cell(0, 10, f"Documento generado el: {fecha}", align="C", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(5)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(10)

            score = self.last_scan_data.get("score", 0)
            risk = self.last_scan_data.get("risk_level", "DESCONOCIDO")
            pdf.set_font("helvetica", "B", 14)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 10, f"Puntaje de Riesgo Heurístico: {score} / 100", new_x="LMARGIN", new_y="NEXT")
            
            if "CRÍTICO" in risk:
                pdf.set_text_color(231, 76, 60)
            elif "SOSPECHOSO" in risk:
                pdf.set_text_color(230, 126, 34)
            else:
                pdf.set_text_color(46, 204, 113)
                
            pdf.cell(0, 10, f"Veredicto Final: {risk}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(10)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("helvetica", "B", 12)
            pdf.cell(0, 10, "Desglose de Amenazas y Evidencia OSINT:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", "", 11)
            details = self.last_scan_data.get("details", [])
            
            if not details:
                pdf.multi_cell(0, 8, "No se detectaron indicadores de compromiso (IoC). El correo analizado cumple con las directrices de seguridad estándar y no presenta enlaces listados en bases de datos maliciosas.")
            else:
                for idx, det in enumerate(details, 1):
                    pdf.multi_cell(0, 8, f"[{idx}] {det}")
                    pdf.ln(2)

            pdf.set_y(-30)
            pdf.set_font("helvetica", "I", 8)
            pdf.set_text_color(150, 150, 150)
            pdf.cell(0, 10, "Este reporte de ciberseguridad fue generado automáticamente por ChainMail Phishing Engine.", align="C", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 5, "Analista Principal: David Fernando Medina Neires", align="C", new_x="LMARGIN", new_y="NEXT")
            pdf.output(file_path)
            QMessageBox.information(self, "Exportación Exitosa", f"Reporte guardado en:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error Crítico", f"No se pudo generar el documento PDF:\n{str(e)}")

    def load_history(self):
        try:
            response = requests.get(self.history_url, timeout=5)
            if response.status_code == 200:
                historial = response.json()
                scroll_bar = self.table.verticalScrollBar()
                current_scroll = scroll_bar.value()

                self.table.setRowCount(len(historial))
                for row_idx, item in enumerate(historial):
                    self.table.setItem(row_idx, 0, QTableWidgetItem(f"[{item.get('status')}]"))
                    
                    origen_full = str(item.get("source", ""))
                    msg_id = None
                    if " | ID: " in origen_full:
                        origen_display, msg_id = origen_full.split(" | ID: ")
                    else:
                        origen_display = origen_full

                    self.table.setItem(row_idx, 1, QTableWidgetItem(origen_display))
                    
                    sender = str(item.get("sender", "Desconocido")).replace("\n", " ")
                    self.table.setItem(row_idx, 2, QTableWidgetItem(sender))
                    
                    riesgo = item.get("risk_level", "Desconocido")
                    risk_item = QTableWidgetItem(riesgo)
                    if "CRÍTICO" in riesgo:
                        risk_item.setForeground(QColor("#FF0055"))
                    elif "SOSPECHOSO" in riesgo:
                        risk_item.setForeground(QColor("#FFAA00"))
                    else:
                        risk_item.setForeground(QColor("#00FF66"))
                        
                    self.table.setItem(row_idx, 3, risk_item)
                    
                    if msg_id:
                        btn_delete = QPushButton("Destruir")
                        btn_delete.setObjectName("btnDestroy")
                        btn_delete.setCursor(Qt.CursorShape.PointingHandCursor)
                        btn_delete.clicked.connect(lambda checked, m=msg_id: self.delete_email_remote(m))
                        
                        widget_center = QWidget()
                        layout_center = QHBoxLayout(widget_center)
                        layout_center.setContentsMargins(4, 4, 4, 4)
                        layout_center.addWidget(btn_delete)
                        layout_center.setAlignment(Qt.AlignmentFlag.AlignCenter)
                        self.table.setCellWidget(row_idx, 4, widget_center)
                    else:
                        no_action = QTableWidgetItem("N/A")
                        no_action.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                        self.table.setItem(row_idx, 4, no_action)
                        
                scroll_bar.setValue(current_scroll)
        except Exception:
            pass

    def delete_email_remote(self, msg_id):
        reply = QMessageBox.question(self, 'Confirmar Destrucción', 
                                     '¿Estás seguro de que deseas eliminar este correo PERMANENTEMENTE de Gmail?\n\nEsta acción no se puede deshacer.',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                     QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                from googleapiclient.discovery import build
                creds = self.vault.authenticate_via_browser()
                service = build('gmail', 'v1', credentials=creds)
                service.users().messages().delete(userId='me', id=msg_id).execute()
                QMessageBox.information(self, "Amenaza Neutralizada", "El correo ha sido destruido permanentemente de los servidores de Google.")
                self.load_history()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo destruir el correo.\nDetalle: {str(e)}")

    def purge_history(self):
        reply = QMessageBox.question(self, 'Confirmar Purga', 
                                     '¿Eliminar registros antiguos y conservar solo los 10 más recientes?',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                     QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                response = requests.post(self.clear_history_url, timeout=5)
                if response.status_code == 200:
                    deleted = response.json().get("deleted", 0)
                    QMessageBox.information(self, "Éxito", f"Se han depurado {deleted} registros.")
                    self.load_history()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Fallo de conexión: {str(e)}")

    def logout_user(self):
        reply = QMessageBox.question(self, 'Cerrar Sesión', 
                                     '¿Estás seguro de que deseas desconectar tu cuenta de Google?\n\nEl escudo IMAP se detendrá y la aplicación se cerrará.',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                     QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.vault.logout()
            QApplication.quit()

    def apply_frutiger_aero_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #180A2B; }
            QLabel { color: #FFFFFF; font-family: "Trebuchet MS"; font-size: 14px; }
            #titleLabel { color: #00F0FF; font-size: 26px; font-weight: bold; margin-bottom: 15px; }
            #footerLabel { color: #9D4EDD; font-size: 12px; font-style: italic; margin-top: 10px; }
            #scoreLabel { font-size: 16px; }
            #riskLabel { font-size: 18px; font-weight: bold; }
            QTextEdit { background-color: #2D134D; border: 2px solid #7B2CBF; border-radius: 12px; color: #E0AAFF; padding: 10px; }
            QPushButton { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #9D4EDD, stop:1 #5A189A); color: white; border: 1px solid #E0AAFF; border-radius: 15px; padding: 8px 15px; font-family: "Trebuchet MS"; font-weight: bold; font-size: 14px; }
            QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #C77DFF, stop:1 #7B2CBF); border: 1px solid #FFFFFF; }
            QPushButton:pressed { background: #3C096C; }
            QPushButton:disabled { background: #361A5C; color: #7B2CBF; border: 1px solid #361A5C; }
            #btnAnalyze, #btnInfo { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #00F0FF, stop:1 #0077B6); color: #03045E; border: 1px solid #90E0EF; }
            #btnAnalyze:hover, #btnInfo:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #90E0EF, stop:1 #0096C7); }
            #btnDanger, #btnClear, #btnLogout { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FF006E, stop:1 #C1121F); }
            #btnDanger:hover, #btnClear:hover, #btnLogout:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FF4D6D, stop:1 #780000); }
            #btnDestroy { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FF006E, stop:1 #C1121F); color: white; border: 1px solid #FF4D6D; border-radius: 8px; padding: 4px 10px; font-family: "Trebuchet MS"; font-weight: bold; font-size: 12px; }
            #btnDestroy:hover { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FF4D6D, stop:1 #780000); }
            QTabWidget::pane { border: 2px solid #7B2CBF; background-color: #241142; border-radius: 10px; }
            QTabBar::tab { background: #180A2B; color: #7B2CBF; border: 2px solid #361A5C; border-bottom: none; border-top-left-radius: 10px; border-top-right-radius: 10px; padding: 10px 25px; font-family: "Trebuchet MS"; font-weight: bold; font-size: 14px; }
            QTabBar::tab:selected { background: #241142; color: #00F0FF; border: 2px solid #7B2CBF; border-bottom: 2px solid #241142; }
            QTableWidget { background-color: #1F0D38; border: 2px solid #7B2CBF; border-radius: 10px; color: white; gridline-color: #361A5C; font-family: "Trebuchet MS"; }
            QHeaderView::section { background-color: #361A5C; color: #00F0FF; font-weight: bold; border: none; border-right: 1px solid #1F0D38; padding: 6px; }
        """)

    def closeEvent(self, event):
        try:
            requests.post(self.shutdown_url, timeout=1)
        except:
            pass
        event.accept()

def run_gui():
    import sys
    app = QApplication(sys.argv)
    
    def open_dashboard():
        window = PhishingAnalyzerGUI()
        window.show()
        app.main_window = window 

    vault = CredentialManager()
    
    if vault.has_valid_token():
        open_dashboard()
    else:
        login = LoginWindow(open_dashboard)
        login.show()
        app.login_window = login
        
    sys.exit(app.exec())