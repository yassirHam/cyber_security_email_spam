import re
import email
from email import policy
import math

class SecurityFeatureExtractor:
    def __init__(self):
        # Behavioral IoCs : Vocabulaire d'ingénierie sociale
        self.urgency_words = ['urgent', 'immediate', 'suspend', 'action required', 'warning', 'alert', 'important']
        self.credential_words = ['login', 'password', 'verify', 'account', 'auth', 'credential', 'update']
        
        # Metadata IoCs : Extensions de payload dangereuses
        self.suspicious_extensions = ['.exe', '.vbs', '.scr', '.js', '.bat', '.cmd', '.ps1']
        
        # Domain IoCs : TLDs souvent utilisés pour héberger du phishing ou malware
        self.suspicious_tlds = ['.xyz', '.top', '.click', '.club', '.online', '.vip']

    def extract_iocs(self, raw_email_content):
        """
        Agit comme un filtre de première ligne : parse l'email et extrait 
        les Indicateurs de Compromission (IoCs) comportementaux et structurels.
        """
        msg = email.message_from_string(raw_email_content, policy=policy.default)
        body = self._get_body(msg)
        body_lower = body.lower()
        
        features = {}
        
        # ==========================================
        # 1. Header & Authentication IoCs
        # ==========================================
        sender = str(msg.get('From', '')).lower()
        reply_to = str(msg.get('Reply-To', '')).lower()
        
        features['reply_to_mismatch'] = 1 if reply_to and sender not in reply_to and reply_to not in sender else 0
        
        # Simulation d'évaluation d'authentification (DMARC/SPF/DKIM)
        auth_results = str(msg.get('Authentication-Results', '')).lower()
        features['spf_dkim_failure'] = 1 if 'fail' in auth_results or 'softfail' in auth_results else 0

        # ==========================================
        # 2. URL & Domain IoCs
        # ==========================================
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
        features['url_count'] = len(urls)
        
        # Bypass DNS : Adresses IP nues
        features['ip_based_urls'] = sum(1 for url in urls if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))
        
        # TLDs suspects et génériques
        features['suspicious_tld_count'] = sum(1 for url in urls if any(tld in url for tld in self.suspicious_tlds))

        # ==========================================
        # 3. Behavioral & Psychological IoCs
        # ==========================================
        word_count = max(len(body.split()), 1)
        urgency_count = sum(1 for word in self.urgency_words if word in body_lower)
        cred_count = sum(1 for word in self.credential_words if word in body_lower)
        
        # Utilisation de densités pour éviter le biais des longs emails
        features['urgency_density'] = urgency_count / word_count
        features['credential_request_density'] = cred_count / word_count

        # ==========================================
        # 4. Content & Obfuscation IoCs
        # ==========================================
        alpha_chars = [c for c in body if c.isalpha()]
        features['uppercase_ratio'] = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars) if alpha_chars else 0.0

        # Obfuscation pour tromper les filtres lexicaux
        features['zero_width_chars'] = sum(1 for c in body if c in ['\u200b', '\u200c', '\u200d', '\ufeff'])
        features['leetspeak_anomalies'] = len(re.findall(r'[a-zA-Z]0[a-zA-Z]|[a-zA-Z]@[a-zA-Z]', body))
        
        html_tags = len(re.findall(r'<[^>]+>', body))
        features['html_tag_count'] = html_tags

        # Entropie du texte (détection de génération DGA ou obfuscation massive)
        features['text_entropy'] = self._calculate_entropy(body)

        # ==========================================
        # 5. Metadata IoCs
        # ==========================================
        suspicious_attachments = 0
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                if any(filename.lower().endswith(ext) for ext in self.suspicious_extensions):
                    suspicious_attachments += 1
        features['suspicious_attachments_count'] = suspicious_attachments

        return features

    def _get_body(self, msg):
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    return part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            return msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        return ""
        
    def _calculate_entropy(self, text):
        if not text: return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy
