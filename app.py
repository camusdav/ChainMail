import os
import sys
import threading
import multiprocessing
from flask import Flask, request, jsonify
from engine import AnalyzerEngine
from mongo_client import DatabaseManager
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
        
        # Le damos prioridad al remitente extraído por el escáner IMAP
        raw_sender = data.get('sender') or headers.get("From") or headers.get("from") or headers.get("FROM") or "Desconocido"
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

def start_flask():
    app.run(port=5000, use_reloader=False)

def start_scanner():
    monitor = MultiIMAPMonitor()
    monitor.start_all(interval=30)

if __name__ == '__main__':
    multiprocessing.freeze_support()
    print("Iniciando ChainMail Master Node (Arquitectura Unificada con PyQt6)...")
    
    hilo_flask = threading.Thread(target=start_flask, daemon=True)
    hilo_flask.start()
    
    hilo_scanner = threading.Thread(target=start_scanner, daemon=True)
    hilo_scanner.start()
    
    from gui import run_gui
    run_gui()