import os
import requests
import base64

class OSINTAnalyzer:
    def __init__(self):
        # Toma la clave automáticamente del entorno
        self.api_key = os.getenv("VT_API_KEY")
        self.headers = {
            "x-apikey": self.api_key
        }

    def check_url_virustotal(self, url):
        """
        Consulta la base de datos de VirusTotal para ver si la URL ya está reportada.
        """
        if not self.api_key:
            return {"error": "VT_API_KEY no configurada en el archivo .env"}
        
        # VirusTotal v3 requiere codificar la URL en Base64 URL-safe sin el relleno (=)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        try:
            response = requests.get(api_url, headers=self.headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                # Sumamos detecciones de malware y phishing
                malicious_count = stats.get('malicious', 0) + stats.get('suspicious', 0)
                return {"malicious": malicious_count, "total": sum(stats.values())}
                
            elif response.status_code == 404:
                # Significa que la URL es tan nueva que VT no la ha analizado nunca
                return {"malicious": 0, "status": "URL no encontrada en la base de datos global"}
                
            else:
                return {"error": f"Error de API: {response.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}