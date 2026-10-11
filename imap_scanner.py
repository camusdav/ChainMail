import os
import time
import requests
import threading
import base64
import email
from plyer import notification
from security import CredentialManager
from googleapiclient.discovery import build

class MultiIMAPMonitor:
    def __init__(self):
        self.api_url = "http://127.0.0.1:5000/api/v1/analyze"
        self.vault = CredentialManager()

    def monitor_account(self, creds, interval=30):
        print("[*] Iniciando hilo de vigilancia con Gmail API...")
        try:
            service = build('gmail', 'v1', credentials=creds)
            profile = service.users().getProfile(userId='me').execute()
            email_address = profile.get('emailAddress')
            print(f"[+] Conectado exitosamente con OAuth 2.0 como: {email_address}")
        except Exception as e:
            print(f"[-] Error al conectar con Gmail API: {e}")
            return

        queries = [
            {'q': 'is:unread in:inbox', 'folder_name': 'Inbox'},
            {'q': 'is:unread in:spam', 'folder_name': 'Spam'}
        ]
        
        while True:
            for query_info in queries:
                q = query_info['q']
                folder = query_info['folder_name']
                try:
                    results = service.users().messages().list(userId='me', q=q).execute()
                    messages = results.get('messages', [])
                    
                    if messages:
                        print(f"\n[*] [Gmail API - {folder}] ¡Nuevos correos detectados: {len(messages)}!")
                        
                        for msg in messages:
                            msg_id = msg['id']
                            
                            msg_data = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
                            raw_email_bytes = base64.urlsafe_b64decode(msg_data['raw'].encode('ASCII'))
                            
                            # Extracción nativa del remitente usando la librería email
                            parsed_email = email.message_from_bytes(raw_email_bytes)
                            sender = parsed_email.get("From", "Desconocido")
                            
                            raw_email = raw_email_bytes.decode('utf-8', errors='ignore')
                            origen_detallado = f"Gmail ({folder}) | ID: {msg_id}"
                            
                            payload = {
                                "email_content": raw_email,
                                "source": origen_detallado,
                                "sender": sender,
                                "status": "Analizado"
                            }
                            
                            try:
                                response = requests.post(self.api_url, json=payload, timeout=15)
                                if response.status_code == 200:
                                    res = response.json()
                                    risk = res.get('risk_level')
                                    print(f" -> [{email_address}] ID {msg_id}: Riesgo -> {risk}")
                                    
                                    if risk == "CRÍTICO (Posible Phishing)" and folder == 'Inbox':
                                        self.move_to_spam(service, msg_id, email_address)
                                        
                                    service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
                                    
                            except Exception as api_err:
                                print(f"[-] Error comunicando con la API ChainMail: {api_err}")
                except Exception as e:
                    print(f"[-] Error leyendo la bandeja {folder}: {e}")
            
            time.sleep(interval)

    def move_to_spam(self, service, msg_id, acc_name):
        try:
            service.users().messages().modify(userId='me', id=msg_id, body={'addLabelIds': ['SPAM'], 'removeLabelIds': ['INBOX']}).execute()
            print(f" [!] [{acc_name}] ACCIÓN DEFENSIVA: Correo crítico neutralizado y movido a SPAM.")
            notification.notify(
                title="ChainMail: Amenaza Interceptada",
                message=f"Se detectó un ataque de phishing. El correo ha sido movido a la cuarentena.",
                app_name="ChainMail Phishing Engine",
                timeout=8
            )
        except Exception as e:
            print(f" [-] [{acc_name}] No se pudo mover el correo a Spam: {e}")

    def start_all(self, interval=30):
        print("[*] Escudo en espera del Token OAuth 2.0...")
        while not self.vault.has_valid_token():
            time.sleep(2)
        print("\n[+] Token autorizado detectado. Levantando escudos de Gmail API...")
        creds = self.vault.authenticate_via_browser()
        t = threading.Thread(target=self.monitor_account, args=(creds, interval), daemon=True)
        t.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Desactivando escudos...")

if __name__ == "__main__":
    multi_monitor = MultiIMAPMonitor()
    multi_monitor.start_all(interval=30)