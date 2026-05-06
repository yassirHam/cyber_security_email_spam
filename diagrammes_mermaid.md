# Diagrammes d'Architecture Cybersécurité (Mermaid)

Voici les codes sources des diagrammes pour ton rapport. Tu peux les compiler sur [Mermaid Live Editor](https://mermaid.live/) et les inclure dans ton document LaTeX sous forme d'images.

### 1. Classification des Menaces (Threat Tree)
```mermaid
graph TD
    A[Menaces Messagerie] --> B[Spam]
    A --> C[Phishing / Spear Phishing]
    B --> B1[Impact : Disponibilité]
    B --> B2[Cible : Infrastructures & Temps]
    C --> C1[Impact : Confidentialité & Intégrité]
    C --> C2[Cible : Identifiants & Déploiement Malware]
    C2 --> D[Ingénierie Sociale]
    C2 --> E[Contournement de Filtres]
```

### 2. Architecture de Filtrage Multi-Couches (Pipeline)
```mermaid
flowchart LR
    E[Email Brut] --> F1[Couche 1 : Header IoCs\nSPF/DKIM/Spoofing]
    F1 --> F2[Couche 2 : Domain IoCs\nIP-URLs/TLD/Entropie]
    F2 --> F3[Couche 3 : Content & Obfuscation\nZero-width/Leetspeak]
    F3 --> F4[Couche 4 : Behavioral IoCs\nUrgence/Credentials]
    F4 --> F5[Couche 5 : Metadata IoCs\nExtensions .exe/.vbs]
    F5 --> M[Vecteur de Caractéristiques Structuré]
    M --> AI[Détection ML]
```

### 3. Mapping Attaque -> IoC
```mermaid
graph LR
    A1[Usurpation d'Identité] -->|Spoofing| I1(Reply-To Mismatch)
    A2[Bypass DNS] -->|IP Nues| I2(IP-based URLs)
    A3[Masquage Lexical] -->|Caractères Invisibles| I3(Zero-width chars)
    A4[Manipulation Psychologique] -->|Urgence| I4(Urgency Density)
    A5[Livraison Payload] -->|Dropper| I5(Suspicious Extension)
    
    I1 --> D[Système de Détection]
    I2 --> D
    I3 --> D
    I4 --> D
    I5 --> D
```
