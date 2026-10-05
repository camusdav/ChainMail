import os
import sys
import subprocess
from flask import Flask, request, jsonify
from engine import AnalyzerEngine
from mongo_client import DatabaseManager

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
        
        # Extracción segura y saneada del remitente
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
    """Endpoint para limpiar registros antiguos y optimizar espacio."""
    deleted_count = db.clear_old_history(keep_latest=10)
    if deleted_count >= 0:
        return jsonify({"status": "success", "deleted": deleted_count}), 200
    return jsonify({"status": "error"}), 500

@app.route('/api/v1/shutdown', methods=['POST'])
def shutdown():
    print("Señal de apagado recibida. Cerrando ChainMail...")
    os._exit(0)
    return jsonify({"status": "apagando"}), 200

if __name__ == '__main__':
    print("Iniciando ChainMail Master Node...")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    gui_path = os.path.join(current_dir, "gui.py")
    scanner_path = os.path.join(current_dir, "imap_scanner.py")
    
    subprocess.Popen([sys.executable, gui_path])
    subprocess.Popen([sys.executable, scanner_path])
    app.run(debug=True, port=5000, use_reloader=False)