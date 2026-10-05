import customtkinter as ctk
from tkinter import messagebox
import requests

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PhishingAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ChainMail - Centro de Operaciones")
        self.root.geometry("750x720")
        
        self.api_url = "http://127.0.0.1:5000/api/v1/analyze"
        self.shutdown_url = "http://127.0.0.1:5000/api/v1/shutdown"
        self.history_url = "http://127.0.0.1:5000/api/v1/history"
        self.clear_history_url = "http://127.0.0.1:5000/api/v1/history/clear"

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.create_widgets()

    def create_widgets(self):
        self.lbl_title = ctk.CTkLabel(self.root, text="ChainMail: Phishing Engine", font=ctk.CTkFont(size=24, weight="bold"))
        self.lbl_title.pack(pady=(20, 10))

        self.tabview = ctk.CTkTabview(self.root, width=700, height=570)
        self.tabview.pack(padx=20, pady=10, fill="both", expand=True)

        self.tab_scan = self.tabview.add("Escáner Manual")
        self.tab_history = self.tabview.add("Centro de Monitoreo")

        self.build_scan_tab()
        self.build_history_tab()

        self.lbl_dev = ctk.CTkLabel(self.root, text="@Camus_Dav", font=ctk.CTkFont(size=10, slant="italic"), text_color="gray")
        self.lbl_dev.pack(side="bottom", pady=10)

    def build_scan_tab(self):
        self.lbl_inst = ctk.CTkLabel(self.tab_scan, text="Código fuente (.eml) o texto plano del correo:")
        self.lbl_inst.pack(anchor="w", padx=20, pady=(10, 0))

        self.txt_email = ctk.CTkTextbox(self.tab_scan, height=180, font=ctk.CTkFont(family="Consolas", size=12))
        self.txt_email.pack(pady=10, padx=20, fill="x")

        self.frame_buttons = ctk.CTkFrame(self.tab_scan, fg_color="transparent")
        self.frame_buttons.pack(pady=5)
        
        self.btn_analyze = ctk.CTkButton(self.frame_buttons, text="Escanear Amenazas", command=self.analyze_email, fg_color="#E63946", hover_color="#B32B36")
        self.btn_analyze.pack(side="left", padx=10)
        
        self.btn_clear = ctk.CTkButton(self.frame_buttons, text="Limpiar", command=self.clear_fields, fg_color="#457B9D", hover_color="#1D3557")
        self.btn_clear.pack(side="left", padx=10)

        self.frame_results = ctk.CTkFrame(self.tab_scan)
        self.frame_results.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.lbl_score = ctk.CTkLabel(self.frame_results, text="Puntaje de Riesgo: -", font=ctk.CTkFont(size=16))
        self.lbl_score.pack(anchor="w", padx=15, pady=(10, 5))
        
        self.lbl_risk = ctk.CTkLabel(self.frame_results, text="Nivel de Amenaza: -", font=ctk.CTkFont(size=18, weight="bold"))
        self.lbl_risk.pack(anchor="w", padx=15, pady=0)
        
        self.txt_details = ctk.CTkTextbox(self.frame_results, height=100, font=ctk.CTkFont(family="Consolas", size=12))
        self.txt_details.pack(pady=10, padx=15, fill="x")
        self.txt_details.configure(state="disabled")

    def build_history_tab(self):
        # Contenedor superior para los botones de control de historial
        frame_hist_buttons = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        frame_hist_buttons.pack(pady=10)

        self.btn_refresh = ctk.CTkButton(frame_hist_buttons, text="Actualizar Datos", command=self.load_history, fg_color="#457B9D", hover_color="#1D3557")
        self.btn_refresh.pack(side="left", padx=5)

        self.btn_purge = ctk.CTkButton(frame_hist_buttons, text="Purgar Historial Antiguo", command=self.purge_history, fg_color="#E63946", hover_color="#B32B36")
        self.btn_purge.pack(side="left", padx=5)
        
        headers_frame = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        headers_frame.pack(fill="x", padx=20, pady=(0, 5))
        ctk.CTkLabel(headers_frame, text="Estado", width=90, anchor="w", font=ctk.CTkFont(weight="bold")).pack(side="left")
        ctk.CTkLabel(headers_frame, text="Origen", width=80, anchor="w", font=ctk.CTkFont(weight="bold")).pack(side="left")
        ctk.CTkLabel(headers_frame, text="Remitente", width=220, anchor="w", font=ctk.CTkFont(weight="bold")).pack(side="left")
        ctk.CTkLabel(headers_frame, text="Veredicto", width=150, anchor="w", font=ctk.CTkFont(weight="bold")).pack(side="left")

        self.scroll_history = ctk.CTkScrollableFrame(self.tab_history)
        self.scroll_history.pack(fill="both", expand=True, padx=20, pady=5)
        
        # Cargar datos al iniciar la pestaña
        self.load_history()

    def load_history(self):
        for widget in self.scroll_history.winfo_children():
            widget.destroy()
        
        try:
            response = requests.get(self.history_url, timeout=5)
            if response.status_code == 200:
                historial = response.json()
                if not historial:
                    ctk.CTkLabel(self.scroll_history, text="No hay registros en la base de datos.").pack(pady=20)
                    return

                for item in historial:
                    row = ctk.CTkFrame(self.scroll_history, fg_color="transparent")
                    row.pack(fill="x", pady=2)
                    
                    riesgo = item.get("risk_level", "Desconocido")
                    color_riesgo = "#FF4C4C" if "CRÍTICO" in riesgo else ("#FFA500" if "SOSPECHOSO" in riesgo else "#00FF00")

                    raw_sender = item.get("sender", "Desconocido")
                    if not raw_sender or not str(raw_sender).strip():
                        raw_sender = "Desconocido"
                    
                    clean_sender = str(raw_sender).replace("\n", " ").replace("\r", "").strip()
                    display_sender = clean_sender[:30] + "..." if len(clean_sender) > 30 else clean_sender

                    ctk.CTkLabel(row, text=f"[{item.get('status')}]", width=90, anchor="w").pack(side="left")
                    ctk.CTkLabel(row, text=item.get("source"), width=80, anchor="w", text_color="#457B9D").pack(side="left")
                    ctk.CTkLabel(row, text=display_sender, width=220, anchor="w").pack(side="left")
                    ctk.CTkLabel(row, text=riesgo, width=150, anchor="w", text_color=color_riesgo).pack(side="left")
        except Exception:
            ctk.CTkLabel(self.scroll_history, text="Error: Servidor ChainMail desconectado.").pack(pady=20)

    def purge_history(self):
        """Envía la orden al servidor para limpiar registros viejos y optimizar Atlas."""
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
        self.root.update()

        try:
            payload = {"email_content": email_content, "source": "Manual"}
            response = requests.post(self.api_url, json=payload, timeout=15)
            
            if response.status_code == 200:
                self.display_results(response.json())
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
            self.lbl_risk.configure(text_color="#FF4C4C")
        elif risk == "SOSPECHOSO":
            self.lbl_risk.configure(text_color="#FFA500")
        else:
            self.lbl_risk.configure(text_color="#00FF00")

        self.txt_details.configure(state="normal")
        self.txt_details.delete("1.0", ctk.END)
        if not details:
            self.txt_details.insert(ctk.END, "✓ No se detectaron anomalías heurísticas ni reportes en OSINT.\n")
        else:
            for idx, det in enumerate(details, 1):
                self.txt_details.insert(ctk.END, f"[{idx}] {det}\n")
        self.txt_details.configure(state="disabled")

    def clear_fields(self):
        self.txt_email.delete("1.0", ctk.END)
        self.lbl_score.configure(text="Puntaje de Riesgo: -")
        self.lbl_risk.configure(text="Nivel de Amenaza: -", text_color=["gray10", "gray90"])
        self.txt_details.configure(state="normal")
        self.txt_details.delete("1.0", ctk.END)
        self.txt_details.configure(state="disabled")

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