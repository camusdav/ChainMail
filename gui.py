import customtkinter as ctk
from tkinter import messagebox, filedialog
import requests
import datetime
from fpdf import FPDF

# Forzamos modo oscuro para que los colores neón/morados resalten
ctk.set_appearance_mode("dark")

class PhishingAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ChainMail - Centro de Operaciones")
        self.root.geometry("780x740")
        
        # Fondo general de la aplicación (Morado profundo)
        self.root.configure(fg_color="#180A2B")
        
        self.api_url = "http://127.0.0.1:5000/api/v1/analyze"
        self.shutdown_url = "http://127.0.0.1:5000/api/v1/shutdown"
        self.history_url = "http://127.0.0.1:5000/api/v1/history"
        self.clear_history_url = "http://127.0.0.1:5000/api/v1/history/clear"

        self.last_scan_data = None
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.create_widgets()

    def create_widgets(self):
        # Título estilo Frutiger con color Cyan brillante
        self.lbl_title = ctk.CTkLabel(
            self.root, 
            text="ChainMail: Phishing Engine", 
            font=ctk.CTkFont(family="Trebuchet MS", size=28, weight="bold"),
            text_color="#00F0FF"
        )
        self.lbl_title.pack(pady=(20, 10))

        # Contenedor principal de pestañas (simulando cristal oscuro morado)
        self.tabview = ctk.CTkTabview(
            self.root, 
            width=720, 
            height=580,
            fg_color="#281347",
            segmented_button_fg_color="#180A2B",
            segmented_button_selected_color="#9D4EDD",
            segmented_button_selected_hover_color="#C77DFF",
            segmented_button_unselected_color="#180A2B",
            text_color="#FFFFFF"
        )
        self.tabview.pack(padx=20, pady=10, fill="both", expand=True)

        self.tab_scan = self.tabview.add("Escáner Manual")
        self.tab_history = self.tabview.add("Centro de Monitoreo")

        self.build_scan_tab()
        self.build_history_tab()

        self.lbl_dev = ctk.CTkLabel(
            self.root, 
            text="@Camus_Dav", 
            font=ctk.CTkFont(family="Trebuchet MS", size=11, slant="italic"), 
            text_color="#9D4EDD"
        )
        self.lbl_dev.pack(side="bottom", pady=10)

    def build_scan_tab(self):
        self.lbl_inst = ctk.CTkLabel(self.tab_scan, text="Código fuente (.eml) o texto plano del correo:", font=("Trebuchet MS", 14))
        self.lbl_inst.pack(anchor="w", padx=20, pady=(10, 0))

        # Caja de texto con bordes morados vibrantes
        self.txt_email = ctk.CTkTextbox(
            self.tab_scan, 
            height=180, 
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#361A5C",
            border_color="#7B2CBF",
            border_width=2,
            corner_radius=15
        )
        self.txt_email.pack(pady=10, padx=20, fill="x")

        self.frame_buttons = ctk.CTkFrame(self.tab_scan, fg_color="transparent")
        self.frame_buttons.pack(pady=5)
        
        # Botones estilo píldora de los 2000s
        self.btn_analyze = ctk.CTkButton(
            self.frame_buttons, 
            text="Escanear Amenazas", 
            command=self.analyze_email, 
            fg_color="#9D4EDD", 
            hover_color="#C77DFF",
            font=("Trebuchet MS", 13, "bold"),
            corner_radius=20,
            border_width=1,
            border_color="#FFFFFF"
        )
        self.btn_analyze.pack(side="left", padx=10)
        
        self.btn_clear = ctk.CTkButton(
            self.frame_buttons, 
            text="Limpiar", 
            command=self.clear_fields, 
            fg_color="#FF006E", 
            hover_color="#FF4793",
            font=("Trebuchet MS", 13, "bold"),
            corner_radius=20,
            border_width=1,
            border_color="#FFFFFF"
        )
        self.btn_clear.pack(side="left", padx=10)

        self.btn_export = ctk.CTkButton(
            self.frame_buttons, 
            text="Exportar Reporte PDF", 
            command=self.export_to_pdf, 
            fg_color="#00F0FF", 
            hover_color="#80F8FF", 
            text_color="#000000",
            font=("Trebuchet MS", 13, "bold"),
            corner_radius=20,
            border_width=1,
            border_color="#FFFFFF",
            state="disabled"
        )
        self.btn_export.pack(side="left", padx=10)

        # Contenedor de resultados
        self.frame_results = ctk.CTkFrame(self.tab_scan, fg_color="#1F0D38", corner_radius=15)
        self.frame_results.pack(fill="both", expand=True, padx=20, pady=15)
        
        self.lbl_score = ctk.CTkLabel(self.frame_results, text="Puntaje de Riesgo: -", font=ctk.CTkFont(family="Trebuchet MS", size=16))
        self.lbl_score.pack(anchor="w", padx=15, pady=(15, 5))
        
        self.lbl_risk = ctk.CTkLabel(self.frame_results, text="Nivel de Amenaza: -", font=ctk.CTkFont(family="Trebuchet MS", size=18, weight="bold"))
        self.lbl_risk.pack(anchor="w", padx=15, pady=0)
        
        self.txt_details = ctk.CTkTextbox(
            self.frame_results, 
            height=100, 
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#2D134D",
            corner_radius=10
        )
        self.txt_details.pack(pady=15, padx=15, fill="x")
        self.txt_details.configure(state="disabled")

    def build_history_tab(self):
        frame_hist_buttons = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        frame_hist_buttons.pack(pady=10)

        self.btn_refresh = ctk.CTkButton(
            frame_hist_buttons, text="Actualizar Datos", command=self.load_history, 
            fg_color="#00F0FF", text_color="#000000", hover_color="#80F8FF", corner_radius=20, font=("Trebuchet MS", 12, "bold")
        )
        self.btn_refresh.pack(side="left", padx=5)

        self.btn_purge = ctk.CTkButton(
            frame_hist_buttons, text="Purgar Historial Antiguo", command=self.purge_history, 
            fg_color="#FF006E", hover_color="#FF4793", corner_radius=20, font=("Trebuchet MS", 12, "bold")
        )
        self.btn_purge.pack(side="left", padx=5)
        
        headers_frame = ctk.CTkFrame(self.tab_history, fg_color="#361A5C", corner_radius=10)
        headers_frame.pack(fill="x", padx=20, pady=(10, 5))
        
        ctk.CTkLabel(headers_frame, text="Estado", width=90, anchor="w", font=ctk.CTkFont(family="Trebuchet MS", weight="bold"), text_color="#00F0FF").pack(side="left", padx=5)
        ctk.CTkLabel(headers_frame, text="Origen", width=80, anchor="w", font=ctk.CTkFont(family="Trebuchet MS", weight="bold"), text_color="#00F0FF").pack(side="left")
        ctk.CTkLabel(headers_frame, text="Remitente", width=220, anchor="w", font=ctk.CTkFont(family="Trebuchet MS", weight="bold"), text_color="#00F0FF").pack(side="left")
        ctk.CTkLabel(headers_frame, text="Veredicto", width=150, anchor="w", font=ctk.CTkFont(family="Trebuchet MS", weight="bold"), text_color="#00F0FF").pack(side="left")

        self.scroll_history = ctk.CTkScrollableFrame(self.tab_history, fg_color="transparent")
        self.scroll_history.pack(fill="both", expand=True, padx=20, pady=5)
        
        self.load_history()

    def load_history(self):
        for widget in self.scroll_history.winfo_children():
            widget.destroy()
        
        try:
            response = requests.get(self.history_url, timeout=5)
            if response.status_code == 200:
                historial = response.json()
                if not historial:
                    ctk.CTkLabel(self.scroll_history, text="No hay registros en la base de datos.", font=("Trebuchet MS", 13)).pack(pady=20)
                    return

                for item in historial:
                    row = ctk.CTkFrame(self.scroll_history, fg_color="#1F0D38", corner_radius=8)
                    row.pack(fill="x", pady=3)
                    
                    riesgo = item.get("risk_level", "Desconocido")
                    # Colores neón para los veredictos
                    color_riesgo = "#FF0055" if "CRÍTICO" in riesgo else ("#FFAA00" if "SOSPECHOSO" in riesgo else "#00FF66")

                    raw_sender = item.get("sender", "Desconocido")
                    if not raw_sender or not str(raw_sender).strip():
                        raw_sender = "Desconocido"
                    
                    clean_sender = str(raw_sender).replace("\n", " ").replace("\r", "").strip()
                    display_sender = clean_sender[:30] + "..." if len(clean_sender) > 30 else clean_sender

                    ctk.CTkLabel(row, text=f"[{item.get('status')}]", width=90, anchor="w", font=("Trebuchet MS", 12)).pack(side="left", padx=5)
                    ctk.CTkLabel(row, text=item.get("source"), width=80, anchor="w", text_color="#C77DFF", font=("Trebuchet MS", 12, "bold")).pack(side="left")
                    ctk.CTkLabel(row, text=display_sender, width=220, anchor="w", font=("Trebuchet MS", 12)).pack(side="left")
                    ctk.CTkLabel(row, text=riesgo, width=150, anchor="w", text_color=color_riesgo, font=("Trebuchet MS", 12, "bold")).pack(side="left")
        except Exception:
            ctk.CTkLabel(self.scroll_history, text="Error: Servidor ChainMail desconectado.", font=("Trebuchet MS", 13)).pack(pady=20)

    def purge_history(self):
        if messagebox.askyesno("Confirmar Purga", "¿Deseas eliminar los registros antiguos y conservar solo los 10 más recientes?"):
            try:
                response = requests.post(self.clear_history_url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    deleted = data.get("deleted", 0)
                    messagebox.showinfo("Éxito", f"Se han depurado {deleted} registros antiguos de la base de datos.")
                    self.load_history()
                else:
                    messagebox.showerror("Error", "No se pudo completar la purga.")
            except Exception as e:
                messagebox.showerror("Error", f"Fallo de conexión: {str(e)}")

    def analyze_email(self):
        email_content = self.txt_email.get("1.0", ctk.END).strip()
        if not email_content:
            messagebox.showwarning("Advertencia", "El campo de texto está vacío.")
            return

        self.btn_analyze.configure(state="disabled", text="Analizando...")
        self.btn_export.configure(state="disabled")
        self.root.update()

        try:
            payload = {"email_content": email_content, "source": "Manual"}
            response = requests.post(self.api_url, json=payload, timeout=15)
            
            if response.status_code == 200:
                self.last_scan_data = response.json()
                self.display_results(self.last_scan_data)
                self.btn_export.configure(state="normal") 
            else:
                messagebox.showerror("Error API", f"Código {response.status_code}")
                
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo conectar al motor: {str(e)}")
        finally:
            self.btn_analyze.configure(state="normal", text="Escanear Amenazas")

    def display_results(self, data):
        score = data.get("score", 0)
        risk = data.get("risk_level", "DESCONOCIDO")
        details = data.get("details", [])

        self.lbl_score.configure(text=f"Puntaje de Riesgo: {score}")
        self.lbl_risk.configure(text=f"Nivel de Amenaza: {risk}")

        if risk == "CRÍTICO (Posible Phishing)":
            self.lbl_risk.configure(text_color="#FF0055")
        elif risk == "SOSPECHOSO":
            self.lbl_risk.configure(text_color="#FFAA00")
        else:
            self.lbl_risk.configure(text_color="#00FF66")

        self.txt_details.configure(state="normal")
        self.txt_details.delete("1.0", ctk.END)
        if not details:
            self.txt_details.insert(ctk.END, "✓ No se detectaron anomalías heurísticas ni reportes en OSINT.\n")
        else:
            for idx, det in enumerate(details, 1):
                self.txt_details.insert(ctk.END, f"[{idx}] {det}\n")
        self.txt_details.configure(state="disabled")

    def export_to_pdf(self):
        if not self.last_scan_data:
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("Documentos PDF", "*.pdf")],
            title="Guardar Reporte ChainMail",
            initialfile=f"Reporte_ChainMail_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        
        if not file_path:
            return 

        try:
            pdf = FPDF()
            pdf.add_page()
            
            pdf.set_font("helvetica", "B", 22)
            pdf.set_text_color(157, 78, 221) # Morado oscuro para el PDF
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
            messagebox.showinfo("Exportación Exitosa", f"El reporte ha sido guardado y formateado correctamente en:\n\n{file_path}")

        except Exception as e:
            messagebox.showerror("Error Crítico", f"No se pudo generar el documento PDF:\n{str(e)}")

    def clear_fields(self):
        self.txt_email.delete("1.0", ctk.END)
        self.lbl_score.configure(text="Puntaje de Riesgo: -")
        self.lbl_risk.configure(text="Nivel de Amenaza: -", text_color=["gray10", "gray90"])
        self.txt_details.configure(state="normal")
        self.txt_details.delete("1.0", ctk.END)
        self.txt_details.configure(state="disabled")
        self.btn_export.configure(state="disabled")
        self.last_scan_data = None

    def on_closing(self):
        try:
            requests.post(self.shutdown_url, timeout=1)
        except:
            pass
        finally:
            self.root.destroy()

if __name__ == "__main__":
    root = ctk.CTk()
    app = PhishingAnalyzerGUI(root)
    root.mainloop()