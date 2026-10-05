import os
import imaplib
import time
import requests
from dotenv import load_dotenv

load_dotenv()

class IMAPMonitor:
    def __init__(self):
        self.email_user = os.getenv("EMAIL_USER")
        self.email_pass = os.getenv("EMAIL_PASS")
        self.imap_server = os.getenv("IMAP_SERVER", "imap.gmail.com")
        self.api_url = "http://127.0.0.1:5000/api/v1/analyze"
        self.mail = None

    def connect(self):
        try:
            self.mail = imaplib.IMAP4_SSL(self.imap_server)
            self.mail.login(self.email_user, self.email_pass)
            print(f"[+] Conectado exitosamente a {self.email_user} en {self.imap_server}")
        except Exception as e:
            print(f"[-] Error de conexión IMAP. Verifica tus credenciales: {e}")
            exit()

    def scan_unseen(self):
        self.mail.select('inbox')
        status, messages = self.mail.search(None, 'UNSEEN')
        
        if status != 'OK':
            return

        mail_ids = messages[0].split()
        if not mail_ids:
            return 

        print(f"\n[*] Detectados {len(mail_ids)} correos nuevos. Iniciando análisis...")

        for num in mail_ids:
            typ, data = self.mail.fetch(num, '(RFC822)')
            raw_email = data[0][1].decode('utf-8', errors='ignore')
            
            try:
                origen = "Gmail" if "gmail" in self.imap_server.lower() else "Outlook"
                
                payload = {
                    "email_content": raw_email,
                    "source": origen,
                    "status": "Analizado"
                }
                
                response = requests.post(self.api_url, json=payload, timeout=15)
                
                if response.status_code == 200:
                    result = response.json()
                    risk = result.get('risk_level')
                    score = result.get('score')
                    print(f" -> Correo ID {num.decode()}: Riesgo {risk} (Puntaje: {score})")
                    
                    if risk == "CRÍTICO (Posible Phishing)":
                        self.move_to_spam(num)
                else:
                    print(f"[-] Error en la API: {response.status_code}")
            except Exception as e:
                print(f"[-] Error conectando a ChainMail API: {e}")

    def move_to_spam(self, email_id):
        spam_folder = '"[Gmail]/Spam"' if "gmail" in self.imap_server else '"Junk Email"'
        try:
            self.mail.copy(email_id, spam_folder)
            self.mail.store(email_id, '+FLAGS', '\\Deleted')
            self.mail.expunge()
            print(f" [!] ACCIÓN DEFENSIVA: Correo neutralizado y movido a {spam_folder}.")
        except Exception as e:
            print(f" [-] No se pudo mover a Spam: {e}")

    def start_listening(self, interval=30):
        self.connect()
        print(f"[*] Escudo ChainMail activado. Escaneando cada {interval} segundos...")
        try:
            while True:
                self.scan_unseen()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] Escudo desactivado. Cerrando conexión...")
            self.mail.logout()

if __name__ == "__main__":
    monitor = IMAPMonitor()
    monitor.start_listening(interval=30)