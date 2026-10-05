import email
from email import policy

class EmailParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.parsed_email = self._load_email()

    def _load_email(self):
        with open(self.file_path, 'rb') as f:
            # Usamos policy.default para decodificar correctamente los strings
            return email.message_from_binary_file(f, policy=policy.default)

    def get_headers(self):
        """Extrae cabeceras clave para análisis de suplantación."""
        return {
            "From": self.parsed_email.get("From", ""),
            "Reply-To": self.parsed_email.get("Reply-To", ""),
            "Return-Path": self.parsed_email.get("Return-Path", ""),
            "Subject": self.parsed_email.get("Subject", "")
        }

    def get_body(self):
        """Extrae el cuerpo del correo, priorizando HTML para analizar enlaces."""
        body_text = ""
        body_html = ""
        
        if self.parsed_email.is_multipart():
            for part in self.parsed_email.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        body_text += str(part.get_content() or "")
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        body_html += str(part.get_content() or "")
                    except Exception:
                        pass
        else:
            try:
                body_text = str(self.parsed_email.get_content() or "")
            except Exception:
                pass
            
        return body_text, body_html