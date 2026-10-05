import re

class PhishingRules:
    def __init__(self):
        # Detecta enlaces donde el texto visible difiere del href
        # Ej: <a href="http://malicia.com">www.paypal.com</a>
        self.url_regex = re.compile(r'<a\s+(?:[^>]*?\s+)?href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE)
        
        # Detecta espacios inusuales usados para evadir filtros (ej: c u e n t a)
        self.spaced_words_regex = re.compile(r'\b(?:[a-zA-Z]\s){4,}[a-zA-Z]\b')
        
        # Diccionario de urgencia (se puede ampliar)
        self.urgency_keywords = [
            r"\b(urgente|inmediato|suspendid[oa]|bloquead[oa]|verificar cuenta)\b",
            r"\b(accion requerida|cierre de cuenta|factura adjunta)\b"
        ]

    def analyze_urls(self, html_body):
        mismatches = []
        matches = self.url_regex.findall(html_body)
        
        for href, visible_text in matches:
            # Limpiamos tags HTML dentro del texto visible si los hay
            clean_text = re.sub(r'<[^>]+>', '', visible_text).strip()
            
            # Si el texto visible parece un dominio pero no coincide con el href
            if '.' in clean_text and clean_text.lower() not in href.lower():
                mismatches.append({"href": href, "visible_text": clean_text})
                
        return mismatches

    def detect_urgency(self, text):
        found_patterns = []
        for pattern in self.urgency_keywords:
            if re.search(pattern, text, re.IGNORECASE):
                found_patterns.append(pattern)
        return len(found_patterns)
    
    def analyze_headers(self, headers):
        flags = []
        # Conversión forzada a string para evitar AttributeErrors con objetos email.header
        sender = str(headers.get("From", "")).lower()
        reply_to = str(headers.get("Reply-To", "")).lower()
        
        # Extraer dominios con regex básico
        domain_regex = r'@([\w.-]+)'
        
        sender_domain_match = re.search(domain_regex, sender)
        reply_domain_match = re.search(domain_regex, reply_to)
        
        if sender_domain_match and reply_domain_match:
            if sender_domain_match.group(1) != reply_domain_match.group(1):
                flags.append(f"Discrepancia en dominios: From ({sender_domain_match.group(1)}) vs Reply-To ({reply_domain_match.group(1)})")
                
        return flags