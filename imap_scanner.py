import os
import imaplib
import time
import requests
import threading
from dotenv import load_dotenv

load_dotenv()

class MultiIMAPMonitor:
    def __init__(self):
        self.api_url = "http://127.0.0.1:5000/api/v1/analyze"
        self.accounts = []
        
        # Configurar Gmail si existe en el .env
        gmail_user = os.getenv("GMAIL_USER")
        gmail_pass = os.getenv("GMAIL_PASS")
        if gmail_user and gmail_pass and "tu_clave" not in gmail_pass:
            self.accounts.append({
                "name": "Gmail",
                "user": gmail_user,
                "pass": gmail_pass,
                "server": "imap.gmail.com",
                "spam_folder": '"[Gmail]/Spam"'
            })

        # Configurar Outlook si existe en el .env
        outlook_user = os.getenv("OUTLOOK_USER")
        outlook_pass = os.getenv("OUTLOOK_PASS")
        if outlook_user and outlook_pass and "tu_clave" not in outlook_pass:
            self.accounts.append({
                "name": "Outlook",
                "user": outlook_user,
                "pass": outlook_pass,
                "server": "outlook.office365.com",
                "spam_folder": '"Junk Email"'
            })

    def monitor_account(self, acc, interval=30):
        """Bucle de monitoreo independiente para cada proveedor de correo."""
        print(f"[*] Iniciando hilo de vigilancia para {acc['name']} ({acc['user']})...")
        while True:
            try:
                mail = imaplib.IMAP4_SSL(acc['server'])
                mail.login(acc['user'], acc['pass'])
                print(f"[+] Conexión establecida con éxito en {acc['name']}.")
                
                while True:
                    mail.select('inbox')
                    status, messages = mail.search(None, 'UNSEEN')
                    
                    if status == 'OK':
                        mail_ids = messages[0].split()
                        if mail_ids:
                            print(f"\n[*] [{acc['name']}] ¡Nuevos correos detectados: {len(mail_ids)}!")
                            for num in mail_ids:
                                typ, data = mail.fetch(num, '(RFC822)')
                                raw_email = data[0][1].decode('utf-8', errors='ignore')
                                
                                payload = {
                                    "email_content": raw_email,
                                    "source": acc['name'],
                                    "status": "Analizado"
                                }
                                try:
                                    response = requests.post(self.api_url, json=payload, timeout=15)
                                    if response.status_code == 200:
                                        res = response.json()
                                        risk = res.get('risk_level')
                                        print(f" -> [{acc['name']}] ID {num.decode()}: Riesgo -> {risk}")
                                        
                                        if risk == "CRÍTICO (Posible Phishing)":
                                            self.move_to_spam(mail, num, acc['spam_folder'], acc['name'])
                                except Exception as api_err:
                                    print(f"[-] [{acc['name']}] Error comunicando con la API ChainMail: {api_err}")
                    
                    time.sleep(interval)
            except Exception as e:
                print(f"[-] Error de conexión IMAP en {acc['name']}: {e}. Reintentando en 30 segundos...")
                time.sleep(30)

    def move_to_spam(self, mail_conn, email_id, spam_folder, acc_name):
        try:
            mail_conn.copy(email_id, spam_folder)
            mail_conn.store(email_id, '+FLAGS', '\\Deleted')
            mail_conn.expunge()
            print(f" [!] [{acc_name}] ACCIÓN DEFENSIVA: Correo crítico neutralizado y movido a {spam_folder}.")
        except Exception as e:
            print(f" [-] [{acc_name}] No se pudo mover el correo a Spam: {e}")

    def start_all(self, interval=30):
        if not self.accounts:
            print("[-] ADVERTENCIA: No hay cuentas configuradas correctamente en el archivo .env.")
            return
        
        # Lanzar un hilo independiente por cada cuenta configurada
        threads = []
        for acc in self.accounts:
            t = threading.Thread(target=self.monitor_account, args=(acc, interval), daemon=True)
            t.start()
            threads.append(t)
        
        print(f"[*] Escudo Multi-Cuenta ChainMail operando de forma concurrente para {len(self.accounts)} cuenta(s).")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Desactivando escudos IMAP...")

if __name__ == "__main__":
    multi_monitor = MultiIMAPMonitor()
    multi_monitor.start_all(interval=30)