import os
import sys
import threading
import multiprocessing
from flask import Flask, request, jsonify
from engine import AnalyzerEngine
from mongo_client import DatabaseManager

# Importamos los submódulos directamente en lugar de usar subprocess
from gui import PhishingAnalyzerGUI
import customtkinter as ctk
from imap_scanner import MultiIMAPMonitor

app = Flask(__name__)
db = DatabaseManager()

@app.route('/api/v1/analyze', methods=['POST'])
def analyze_email():
    data = request.json
    if not data or 'email_content' not in data:
        return jsonify({"error": "Falta el campo 'email_content'"}), 400

    origen = data.get('source', 'Manual')
    temp_file = "temp_email.eml"
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(data['email_content'])

    try:
        engine = AnalyzerEngine(temp_file)
        result = engine.run_analysis()
        _, raw_html = engine.parser.get_body()
        
        headers = engine.parser.get_headers()
        raw_sender = headers.get("From") or headers.get("from") or headers.get("FROM") or "Desconocido"
        clean_sender = str(raw_sender).replace("\n", " ").replace("\r", "").strip()
        
        scan_id = db.save_analysis(
            sender=clean_sender,
            score=result['score'],
            risk_level=result['risk_level'],
            details=result['details'],
            raw_text=raw_html,
            source=origen
        )
        
        result['scan_id'] = str(scan_id)
        return jsonify(result), 200
        
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)

@app.route('/api/v1/history', methods=['GET'])
def get_history():
    historial = db.get_recent_scans(limit=30)
    return jsonify(historial), 200

@app.route('/api/v1/history/clear', methods=['POST'])
def clear_history():
    deleted_count = db.clear_old_history(keep_latest=10)
    if deleted_count >= 0:
        return jsonify({"status": "success", "deleted": deleted_count}), 200
    return jsonify({"status": "error"}), 500

@app.route('/api/v1/shutdown', methods=['POST'])
def shutdown():
    print("Señal de apagado recibida. Cerrando ChainMail...")
    os._exit(0)
    return jsonify({"status": "apagando"}), 200

# --- FUNCIONES PARA LOS HILOS SECUNDARIOS ---

def start_flask():
    """Ejecuta la API Backend silenciosamente."""
    app.run(port=5000, use_reloader=False)

def start_scanner():
    """Ejecuta el escudo IMAP silenciosamente."""
    monitor = MultiIMAPMonitor()
    monitor.start_all(interval=30)

if __name__ == '__main__':
    # Previene creación de procesos fantasma al compilar con PyInstaller
    multiprocessing.freeze_support()
    
    print("Iniciando ChainMail Master Node (Arquitectura Unificada)...")
    
    # 1. Lanzar el servidor Flask en un hilo secundario (Daemon)
    hilo_flask = threading.Thread(target=start_flask, daemon=True)
    hilo_flask.start()
    
    # 2. Lanzar el Escudo IMAP en un hilo secundario (Daemon)
    hilo_scanner = threading.Thread(target=start_scanner, daemon=True)
    hilo_scanner.start()
    
    # 3. Lanzar la Interfaz Gráfica (Obligatoriamente en el hilo principal)
    root = ctk.CTk()
    app_gui = PhishingAnalyzerGUI(root)
    root.mainloop()