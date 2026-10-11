import os
import json
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

class CredentialManager:
    def __init__(self):
        self.SCOPES = ['https://mail.google.com/']
        
        # Obtenemos la ruta absoluta de la carpeta donde está guardado ESTE script
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Anclamos los archivos a esa ruta absoluta para que nunca se pierdan
        self.token_file = os.path.join(base_dir, 'token.json')
        self.credentials_file = os.path.join(base_dir, 'credentials.json')

    def has_valid_token(self):
        """Verifica si el usuario ya inició sesión previamente y el token sirve."""
        if os.path.exists(self.token_file):
            creds = Credentials.from_authorized_user_file(self.token_file, self.SCOPES)
            if creds and creds.valid:
                return True
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    with open(self.token_file, 'w') as token:
                        token.write(creds.to_json())
                    return True
                except Exception:
                    pass
        return False

    def authenticate_via_browser(self):
        """Abre el navegador para que el usuario inicie sesión con Google."""
        creds = None
        
        if os.path.exists(self.token_file):
            creds = Credentials.from_authorized_user_file(self.token_file, self.SCOPES)
            
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(self.credentials_file):
                    raise FileNotFoundError(f"No se encontró '{self.credentials_file}'. Asegúrate de descargarlo.")
                
                flow = InstalledAppFlow.from_client_secrets_file(self.credentials_file, self.SCOPES)
                creds = flow.run_local_server(port=0)
                
            with open(self.token_file, 'w') as token:
                token.write(creds.to_json())
                
        return creds

    def get_access_token(self):
        """Devuelve el token puro necesario para que el escáner se conecte."""
        if self.has_valid_token():
            creds = Credentials.from_authorized_user_file(self.token_file, self.SCOPES)
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
                with open(self.token_file, 'w') as token:
                    token.write(creds.to_json())
            return creds.token
        return None

    def logout(self):
        """Destruye el token de sesión actual."""
        if os.path.exists(self.token_file):
            os.remove(self.token_file)