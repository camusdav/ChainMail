from parser import EmailParser
from rules import PhishingRules
from osint import OSINTAnalyzer

class AnalyzerEngine:
    def __init__(self, file_path):
        self.parser = EmailParser(file_path)
        self.rules = PhishingRules()
        self.osint = OSINTAnalyzer()  # Inicializamos el módulo OSINT
        self.score = 0
        self.report = []

    def run_analysis(self):
        headers = self.parser.get_headers()
        body_text, body_html = self.parser.get_body()
        
        # Concatenación segura de texto
        safe_body_text = str(body_text) if body_text else ""
        safe_body_html = str(body_html) if body_html else ""
        combined_body = safe_body_text + " " + safe_body_html
        
        # 1. Análisis de Cabeceras (+30 puntos)
        header_flags = self.rules.analyze_headers(headers)
        if header_flags:
            self.score += 30
            self.report.extend(header_flags)
            
        # 2. Análisis de URLs Mismatched y OSINT (+40 puntos RegEx / +50 puntos VT)
        if safe_body_html:
            mismatched_urls = self.rules.analyze_urls(safe_body_html)
            if mismatched_urls:
                self.score += 40
                for m in mismatched_urls:
                    self.report.append(f"URL ofuscada detectada: '{m['visible_text']}' dirige a '{m['href']}'")
                    
                    # [NUEVO] Análisis OSINT en tiempo real
                    vt_result = self.osint.check_url_virustotal(m['href'])
                    
                    if "malicious" in vt_result and vt_result["malicious"] > 0:
                        self.score += 50
                        self.report.append(f"🚨 [OSINT CRÍTICO] VirusTotal alerta: {vt_result['malicious']} motores detectaron el enlace como amenaza.")
                    elif "error" in vt_result:
                        self.report.append(f"⚠️ [OSINT] No verificado: {vt_result['error']}")

        # 3. Sentido de urgencia (+15 puntos por patrón)
        urgency_hits = self.rules.detect_urgency(combined_body)
        if urgency_hits > 0:
            self.score += (15 * urgency_hits)
            self.report.append(f"Se detectaron {urgency_hits} patrones de urgencia/amenaza.")

        # Veredicto final
        risk_level = "SEGURO"
        if self.score > 70:
            risk_level = "CRÍTICO (Posible Phishing)"
        elif self.score > 30:
            risk_level = "SOSPECHOSO"

        return {
            "score": self.score,
            "risk_level": risk_level,
            "details": self.report
        }

if __name__ == "__main__":
    pass