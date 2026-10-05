import os
from engine import AnalyzerEngine
from mongo_client import DatabaseManager

def create_mock_email(filename, sender, reply_to, subject, body_html):
    email_content = f"""From: {sender}
Reply-To: {reply_to}
Subject: {subject}
Content-Type: text/html; charset="utf-8"

{body_html}
"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(email_content)
    return filename

def run_tests():
    # Instanciamos la conexión a la base de datos
    db = DatabaseManager()
    
    print("--- INICIANDO PRUEBAS DEL MOTOR DE PHISHING CON MONGODB ---\n")

    # CASO 2 (El malicioso)
    phishing_eml = create_mock_email(
        filename="phishing_test.eml",
        sender="soporte@paypal.com",
        reply_to="hacker_ruso@evil-domain.net",
        subject="URGENTE: Cuenta suspendida",
        body_html="""
        <html>
            <body>
                <h2>Atención: Acción Requerida</h2>
                <p>Tu cuenta ha sido bloqueada por seguridad. Es urgente que actualices tus datos.</p>
                <p>Por favor, ingresa aquí para verificar cuenta: 
                   <a href="http://pagos-seguros-update.com/login">www.paypal.com/login</a>
                </p>
            </body>
        </html>
        """
    )
    
    print("Analizando y guardando Caso Phishing Crítico...")
    engine_phish = AnalyzerEngine(phishing_eml)
    resultado_phish = engine_phish.run_analysis()
    
    # Extraemos el contenido original para la base de datos
    _, raw_html = engine_phish.parser.get_body()
    
    # Guardamos en la base de datos
    db.save_analysis(
        sender="soporte@paypal.com",
        score=resultado_phish['score'],
        risk_level=resultado_phish['risk_level'],
        details=resultado_phish['details'],
        raw_text=raw_html
    )
    
    print(f"Puntaje: {resultado_phish['score']} | Nivel: {resultado_phish['risk_level']}")
    print("Revisa tu base de datos MongoDB para ver los registros insertados.")
    print("-" * 50)

    os.remove(phishing_eml)

if __name__ == "__main__":
    run_tests()