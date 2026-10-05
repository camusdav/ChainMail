import os
import hashlib
import certifi
from datetime import datetime, timezone
from pymongo import MongoClient
from dotenv import load_dotenv
from crypto import QuarantineCrypto

load_dotenv()

class DatabaseManager:
    def __init__(self, connection_string=None):
        if not connection_string:
            connection_string = os.getenv("MONGO_URI")
            
        if not connection_string:
            raise ValueError("Falta el string de conexión (MONGO_URI). Verifica tu archivo .env")

        self.client = MongoClient(connection_string, tlsCAFile=certifi.where())
        self.db = self.client["phishing_analyzer"]
        self.scans = self.db["scans"]
        self.quarantine = self.db["quarantine"]
        self.crypto = QuarantineCrypto()

    def _generate_hash(self, text):
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def save_analysis(self, sender, score, risk_level, details, raw_text, source="Manual"):
        scan_record = {
            "timestamp": datetime.now(timezone.utc),
            "sender": sender,
            "score": score,
            "risk_level": risk_level,
            "details": details,
            "source": source
        }
        
        result = self.scans.insert_one(scan_record)
        scan_id = result.inserted_id

        if risk_level == "CRÍTICO (Posible Phishing)":
            encrypted_body = self.crypto.encrypt(raw_text)
            email_hash = self._generate_hash(raw_text)
            
            quarantine_record = {
                "scan_id": scan_id,
                "timestamp": datetime.now(timezone.utc),
                "email_hash": email_hash,
                "encrypted_content": encrypted_body
            }
            self.quarantine.insert_one(quarantine_record)
            print(f"[\u2713] ALERTA: Correo crítico enviado a bóveda de cuarentena cifrada en MongoDB Atlas.")

        return scan_id

    def get_recent_scans(self, limit=30):
        try:
            scans = self.scans.find().sort("timestamp", -1).limit(limit)
            history = []
            for scan in scans:
                history.append({
                    "id": str(scan["_id"]),
                    "sender": scan.get("sender", "Desconocido"),
                    "risk_level": scan.get("risk_level", "DESCONOCIDO"),
                    "source": scan.get("source", "Manual"),
                    "status": "Analizado"
                })
            return history
        except Exception as e:
            return []

    def clear_old_history(self, keep_latest=10):
        """Elimina los registros antiguos de 'scans', conservando solo los N más recientes."""
        try:
            # Obtener todos los IDs ordenados del más nuevo al más viejo
            all_scans = list(self.scans.find({}, {"_id": 1}).sort("timestamp", -1))
            
            if len(all_scans) > keep_latest:
                # Extraer los IDs que exceden el límite para borrarlos
                ids_to_delete = [doc["_id"] for doc in all_scans[keep_latest:]]
                result = self.scans.delete_many({"_id": {"$in": ids_to_delete}})
                return result.deleted_count
            return 0
        except Exception as e:
            print(f"Error al limpiar base de datos: {e}")
            return -1