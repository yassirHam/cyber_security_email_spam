import os
import tarfile
import urllib.request
import pandas as pd
from feature_extractor import SecurityFeatureExtractor
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DatasetPipeline:
    def __init__(self, data_dir="./data"):
        self.data_dir = data_dir
        self.raw_dir = os.path.join(data_dir, "raw")
        self.processed_dir = os.path.join(data_dir, "processed")
        
        # S'assurer que l'architecture des dossiers existe
        os.makedirs(self.raw_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)
        
        self.extractor = SecurityFeatureExtractor()

    def download_spamassassin_dataset(self):
        """
        Télécharge le dataset public SpamAssassin.
        Cette approche automatisée démontre une bonne ingénierie et garantit 
        la reproductibilité de notre pipeline de données.
        """
        urls = {
            "easy_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
            "spam": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2"
        }
        
        for label, url in urls.items():
            filename = url.split('/')[-1]
            filepath = os.path.join(self.raw_dir, filename)
            
            if not os.path.exists(filepath):
                logging.info(f"Téléchargement de {label} depuis {url}...")
                urllib.request.urlretrieve(url, filepath)
            
            # Extraction des archives
            extract_path = os.path.join(self.raw_dir, label)
            if not os.path.exists(extract_path):
                logging.info(f"Extraction de {filename}...")
                with tarfile.open(filepath, "r:bz2") as tar:
                    tar.extractall(path=self.raw_dir)
                    
        logging.info("Acquisition des données brutes terminée.")

    def process_emails(self):
        """
        Passe chaque email brut dans notre firewall applicatif (extracteur de features)
        pour générer notre dataset d'Indicateurs de Compromission (IoC).
        """
        dataset = []
        
        directories = {
            "easy_ham": 0, # Mail légitime (Ham) = 0
            "spam": 1      # Email malveillant/Spam = 1
        }
        
        for dir_name, label in directories.items():
            folder_path = os.path.join(self.raw_dir, dir_name)
            if not os.path.exists(folder_path):
                continue
                
            logging.info(f"Analyse en cours du dossier {dir_name}...")
            
            for filename in os.listdir(folder_path):
                filepath = os.path.join(folder_path, filename)
                if os.path.isfile(filepath):
                    try:
                        with open(filepath, 'r', encoding='latin-1') as f:
                            raw_content = f.read()
                            
                        # Extraction des IoCs structurels et comportementaux
                        features = self.extractor.extract_iocs(raw_content)
                        features['is_malicious'] = label # Target variable
                        
                        dataset.append(features)
                    except Exception as e:
                        logging.warning(f"Erreur de lecture sur le fichier {filename}: {e}")
                        
        df = pd.DataFrame(dataset)
        output_path = os.path.join(self.processed_dir, "security_features_dataset.csv")
        df.to_csv(output_path, index=False)
        
        logging.info(f"Pipeline terminé avec succès. Dataset sauvegardé: {output_path} ({len(df)} emails traités)")
        return df

if __name__ == "__main__":
    # Point d'entrée de notre pipeline
    pipeline = DatasetPipeline()
    pipeline.download_spamassassin_dataset()
    pipeline.process_emails()
