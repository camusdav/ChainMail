import requests
import json

# URL de tu servidor Flask local
url = "http://127.0.0.1:5000/api/v1/analyze"

# Simulamos el texto en crudo de un correo de phishing muy agresivo
correo_malicioso = """From: admin@paypal.com
Reply-To: estafador_pro@evil.net
Subject: URGENTE: Accion requerida en tu cuenta
Content-Type: text/html; charset="utf-8"

<html>
    <body>
        <h1>Alerta de Seguridad</h1>
        <p>Hemos detectado actividad inusual. Es urgente que verifiques tu identidad o tu cuenta sera suspendida de inmediato.</p>
        <p>Haz clic en el siguiente enlace seguro para continuar:</p>
        <a href="http://pagos-falsos-update.xyz/auth">https://www.paypal.com/auth/seguro</a>
    </body>
</html>
"""

# Armamos el payload en formato JSON
payload = {
    "email_content": correo_malicioso
}

print("Enviando petición POST a la API...")
respuesta = requests.post(url, json=payload)

# Imprimimos el resultado formateado
if respuesta.status_code == 200:
    print("\n--- RESPUESTA DE LA API (JSON) ---")
    print(json.dumps(respuesta.json(), indent=4, ensure_ascii=False))
else:
    print(f"Error {respuesta.status_code}: {respuesta.text}")