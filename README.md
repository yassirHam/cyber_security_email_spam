# 🛡️ Système de Détection de Spam et Phishing (Cybersecurity-Oriented)

Ce dépôt contient le travail de la **Personne A** (Analyse des Menaces et Ingénierie des Caractéristiques) pour le projet de cybersécurité supervisé par le Pr. Sara Ouald Chaib.

L'objectif de cette phase est de transformer les vecteurs d'attaque par email en **Indicateurs de Compromission (IoCs)** structurés pour alimenter les modèles de détection.

---

## 📂 Structure du Projet

- **`src/`** : Scripts Python
  - `feature_extractor.py` : Le moteur d'extraction des IoCs (Headers, URLs, Contenu, Obfuscation).
  - `dataset_pipeline.py` : Pipeline automatisé pour transformer des mails bruts en dataset structuré.
- **`data/processed/`** : Contient le dataset final `security_features_dataset.csv`.
- **`report_person_A.tex`** : Rapport détaillé sur l'analyse des menaces et la logique des IoCs.
- **`main.pdf`** & **`explanation.pdf`** : Rapports compilés.
- **`Dockerfile`** : Environnement de compilation LaTeX reproductible.
- **`diagrammes_mermaid.md`** : Source des diagrammes d'architecture.

---

## 🧠 Guide pour la Personne B (Modèles de Détection)

### 📊 Le Dataset
Le fichier `data/processed/security_features_dataset.csv` contient les caractéristiques suivantes (IoCs) :
- **Headers** : `reply_to_mismatch`, `spf_dkim_failure`.
- **URLs** : `ip_based_urls`, `suspicious_tld_count`.
- **Comportement (Social Engineering)** : `urgency_density`, `credential_request_density`.
- **Obfuscation** : `zero_width_chars`, `leetspeak_anomalies`, `text_entropy`.
- **Métadonnées** : `suspicious_attachments_count`.

**Cible** : La colonne `is_malicious` (1 = Malveillant, 0 = Ham).

### 🛠️ Utilisation de l'Extracteur
Pour tester tes modèles sur de nouveaux mails, utilise la classe `SecurityFeatureExtractor` dans `src/feature_extractor.py`. Elle te retournera exactement le même format de dictionnaire que celui utilisé pour l'entraînement.

### 📝 Recommandations
- Les densités sont déjà normalisées par la longueur du mail.
- Un modèle de type **Random Forest** ou **XGBoost** devrait être très performant sur ces features structurées.
- N'hésite pas à consulter `explanation.pdf` pour comprendre le mapping "Attaque -> IoC" et justifier tes résultats dans la partie "Sécurité".

---
*Projet réalisé dans le cadre du module Cybersécurité - 2026*
