import pandas as pd
import numpy as np
import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report
import warnings
warnings.filterwarnings('ignore')

# 1. DATA LOADING & VALIDATION
print("=== 1. DATA LOADING & VALIDATION ===")
data_path = '../data/processed/security_features_dataset.csv'
if not os.path.exists(data_path):
    data_path = 'data/processed/security_features_dataset.csv'

df = pd.read_csv(data_path)
print(f"Dataset Shape: {df.shape}")
print("Class Distribution (0 = Ham, 1 = Malicious):")
print(df['is_malicious'].value_counts(normalize=True) * 100)

X = df.drop('is_malicious', axis=1)
y = df['is_malicious']

# 2. TRAINING STRATEGY
print("\n=== 2. TRAINING STRATEGY ===")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"Training Set: {X_train.shape[0]} samples")
print(f"Testing Set: {X_test.shape[0]} samples")

# 3. MODEL DEVELOPMENT & RATIONALE
# Why these models for IoC-based detection?
# - Naive Bayes: Good baseline for independent features (assumes IoCs are independent).
# - Logistic Regression: Excellent baseline for linear separability; provides feature importance weights (interpretable).
# - Random Forest: Captures non-linear combinations of IoCs (e.g., urgency + suspicious TLD) and resists overfitting. Highly robust.
# - SVM: Effective in high-dimensional spaces; finds the optimal hyperplane separating ham/spam.
# - Gradient Boosting: Iteratively corrects errors of weak learners; exceptional at finding complex adversarial patterns.
models = {
    "Naive Bayes": GaussianNB(),
    "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
    "Random Forest": RandomForestClassifier(random_state=42),
    "SVM": SVC(probability=True, random_state=42),
    "Gradient Boosting": GradientBoostingClassifier(random_state=42)
}

print("\n=== 3.1 CROSS-VALIDATION & HYPERPARAMETER TUNING ===")
# Performing Grid Search for Random Forest as part of the training strategy
rf_params = {
    'n_estimators': [50, 100],
    'max_depth': [None, 10, 20],
    'min_samples_split': [2, 5]
}
print("Running GridSearchCV for Random Forest to optimize hyperparameters...")
grid_search = GridSearchCV(RandomForestClassifier(random_state=42), rf_params, cv=3, scoring='f1', n_jobs=-1)
grid_search.fit(X_train, y_train)
best_rf = grid_search.best_estimator_
print(f"Best Random Forest parameters found: {grid_search.best_params_}")
print(f"Cross-Validation F1-Score (Training): {grid_search.best_score_:.4f}")

# Update the models dictionary with the tuned model
models["Random Forest (Tuned)"] = best_rf
del models["Random Forest"]

print("\n=== 3.2 SECURITY-ORIENTED EVALUATION & COMPARISON ===")
results = []
trained_models = {}

for name, model in models.items():
    print(f"\nTraining {name}...")
    model.fit(X_train, y_train)
    trained_models[name] = model
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else [0]*len(y_test)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob) if hasattr(model, "predict_proba") else 0
    cm = confusion_matrix(y_test, y_pred)
    
    results.append({
        "Model": name,
        "Accuracy": acc,
        "Precision (Alert Quality)": prec,
        "Detection Rate (Recall)": rec,
        "F1-Score": f1,
        "ROC-AUC": roc_auc,
        "False Positives (Friction)": cm[0, 1],
        "False Negatives (Breaches)": cm[1, 0]
    })
    
    print(f"Results for {name}:")
    print(f"Accuracy: {acc:.4f}, Precision (Correct Alerts): {prec:.4f}, Detection Rate (Recall): {rec:.4f}, F1: {f1:.4f}, ROC-AUC: {roc_auc:.4f}")
    print(f"Confusion Matrix (Security Context):")
    print(f"  [True Negatives (Allowed Legitimate): {cm[0, 0]} | False Positives (Blocked Legitimate - Usability Issue): {cm[0, 1]}]")
    print(f"  [False Negatives (Missed Attacks - CRITICAL): {cm[1, 0]} | True Positives (Blocked Malicious): {cm[1, 1]}]\n")

results_df = pd.DataFrame(results)
print("\n=== MODEL COMPARISON TABLE ===")
print(results_df.to_string(index=False))

# Optional Visualization: Save ROC curves or Confusion Matrices
plt.figure(figsize=(10, 6))
sns.barplot(x='Model', y='Detection Rate (Recall)', data=results_df)
plt.title('Detection Rate (Recall) by Model - Security Perspective')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('detection_rate_comparison.png')
print("\nVisualization saved to 'detection_rate_comparison.png'.")

# 4. ADVERSARIAL & EVASION ANALYSIS
print("\n=== 4. ADVERSARIAL & EVASION ANALYSIS ===")
# Let's simulate an evasion attack on the best model (e.g., Random Forest or Gradient Boosting)
best_model_name = "Gradient Boosting"
best_model = trained_models[best_model_name]

# Simulating an evasion technique:
# The attacker creates a phishing email but carefully minimizes IoCs:
# No suspicious TLD, no ip-based urls, lower urgency words, lower text entropy, but maybe a credential request is hidden.
evasion_sample_1 = {
    'reply_to_mismatch': 0, 'spf_dkim_failure': 0, 'url_count': 1, 'ip_based_urls': 0, 
    'suspicious_tld_count': 0, 'urgency_density': 0.0, 'credential_request_density': 0.01, 
    'uppercase_ratio': 0.03, 'zero_width_chars': 2, 'leetspeak_anomalies': 0, 
    'html_tag_count': 1, 'text_entropy': 4.5, 'suspicious_attachments_count': 0
}

# The attacker obfuscates the word "password" as "p@ssw0rd" -> increases leetspeak but lowers credential density
evasion_sample_2 = {
    'reply_to_mismatch': 0, 'spf_dkim_failure': 0, 'url_count': 1, 'ip_based_urls': 0, 
    'suspicious_tld_count': 0, 'urgency_density': 0.0, 'credential_request_density': 0.0, 
    'uppercase_ratio': 0.04, 'zero_width_chars': 0, 'leetspeak_anomalies': 2, 
    'html_tag_count': 0, 'text_entropy': 4.6, 'suspicious_attachments_count': 0
}

evasion_df = pd.DataFrame([evasion_sample_1, evasion_sample_2])
preds = best_model.predict(evasion_df)
probs = best_model.predict_proba(evasion_df)[:, 1]

print(f"Testing evasion samples with {best_model_name}:")
for i, (pred, prob) in enumerate(zip(preds, probs)):
    result = "MALICIOUS (Detected)" if pred == 1 else "LEGITIMATE (Bypassed)"
    print(f"Evasion Sample {i+1} prediction: {result} (Probability of being malicious: {prob:.4f})")

# 5. MODEL SERIALIZATION & EXPLAINABILITY (FEATURE IMPORTANCE)
print("\n=== 5. MODEL SERIALIZATION & FEATURE IMPORTANCE ===")

# Sauvegarde du modèle pour la Personne C (Déploiement)
model_dir = '../models' if os.path.basename(os.getcwd()) == 'src' else 'models'
os.makedirs(model_dir, exist_ok=True)
model_path = os.path.join(model_dir, 'phishing_detector.joblib')
joblib.dump(best_model, model_path)
print(f"Model successfully saved to {model_path} for deployment pipeline.")

# Génération du graphique d'importance des features (Explicabilité)
if hasattr(best_model, 'feature_importances_'):
    importances = best_model.feature_importances_
    features = X.columns
    indices = np.argsort(importances)[::-1]
    
    plt.figure(figsize=(10, 6))
    sns.barplot(x=importances[indices], y=features[indices], palette="viridis")
    plt.title('IoC Feature Importance (Cybersecurity Relevance)')
    plt.xlabel('Relative Importance (Tree Splits)')
    plt.ylabel('Indicators of Compromise (IoC)')
    plt.tight_layout()
    
    plot_path = '../feature_importance.png' if os.path.basename(os.getcwd()) == 'src' else 'feature_importance.png'
    plt.savefig(plot_path)
    print(f"Feature importance visualization saved to '{plot_path}'.")
