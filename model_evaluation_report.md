# AI-Based Email Spam & Phishing Detection System: Security & Evaluation Analysis

This report details the implementation, evaluation, and security analysis of the detection layer utilizing Indicators of Compromise (IoCs).

## 1. Data Validation & Threat Landscape

The dataset `security_features_dataset.csv` contains pre-processed emails parsed into distinct IoC vectors.
* **Total Emails**: 3004
* **Distribution**: ~83.3% Legitimate (Ham), ~16.7% Malicious (Spam/Phishing)

This is an imbalanced dataset, typical in real-world environments where the volume of legitimate traffic drastically outnumbers malicious anomalies. The features provided are not purely statistical text vectors (like TF-IDF); rather, they represent concrete **Indicator of Compromise (IoC) categories**:
- Header/Auth Anomalies
- URL Vectors
- Content Tactics (urgency, credential harvesting)
- Obfuscation Techniques (leetspeak, zero-width characters)

## 2. Security-Oriented Model Evaluation

We trained and compared several machine learning models to act as the detection engine. In a cybersecurity firewall or email filtering system, metrics must be mapped to operational reality:
* **False Positives (FP)**: Legitimate emails incorrectly flagged and quarantined. High FP rates lead to "alert fatigue" and business friction, causing users to ignore warnings or disable filters.
* **False Negatives (FN)**: Malicious emails that evade detection and reach the user's inbox. This is a **CRITICAL security failure**, potentially resulting in compromised credentials or ransomware execution. 

Therefore, while Accuracy is helpful, our primary focus is the trade-off between **Recall (Detection Rate)** and Precision.

### Rationale: Why These Models?
IoC-based features are heavily categorical and continuous representations of attacker tactics. The chosen models are highly relevant for these specific features:
* **Naive Bayes**: Excellent baseline that assumes independence between features. Perfect for testing if individual IoCs are distinct signals.
* **Logistic Regression**: Linear model that provides direct weights for features, making it highly interpretable to reverse-engineer which IoCs are driving decisions.
* **Random Forest**: Captures non-linear intersections of IoCs (e.g., an email with 1 URL + suspicious urgency + mismatch domain). Resistant to overfitting on noisy text features.
* **SVM**: Maps complex interactions in high-dimensional spaces, ideal when the boundary between a clever phishing email and a legitimate one is thin.
* **Gradient Boosting**: Iteratively improves on hard-to-classify samples. Highly effective against adversarial emails designed to sit right on the decision boundary.

### Model Comparison Results

| Model | Accuracy | Precision | Recall (Detection Rate) | F1-Score | ROC-AUC | FPs | FNs |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Naive Bayes** | 0.9101 | 0.9423 | 0.4900 | 0.6447 | 0.7990 | 3 | 51 |
| **Logistic Regression** | 0.9084 | 0.9787 | 0.4600 | 0.6258 | 0.8197 | 1 | 54 |
| **Random Forest** | 0.9450 | 0.8941 | **0.7600** | **0.8216** | **0.9709** | 9 | **24** |
| **SVM** | 0.8818 | 1.0000 | 0.2900 | 0.4496 | 0.7640 | 0 | 71 |
| **Gradient Boosting** | 0.9284 | 0.9384 | 0.6100 | 0.7393 | 0.9024 | 4 | 39 |

### Cybersecurity Interpretation

* **Baseline Models (LR, SVM, NB)**: While they achieved exceptional Precision (very few FPs), their Recall was dangerously low (detecting less than 50% of the threats). In a production deployment, allowing over 50% of attacks to pass through as False Negatives is completely unacceptable for an availability/confidentiality defense layer.
* **Random Forest**: This model provided the most robust detection capability. It achieved a 76% Detection Rate (Recall) with an excellent ROC-AUC of 0.97. While it produced slightly more False Positives (9), the significant reduction in False Negatives (down to 24) makes it the most viable candidate for a high-security environment where missing a threat is costlier than delaying a legitimate email.

### Real-World Deployment Trade-Offs
Beyond basic metrics, deploying these models as a real-time gateway requires evaluating secondary characteristics:
* **Interpretability**: Logistic Regression and Random Forest offer explicit feature importance. When an email is blocked, an analyst can easily see if it was due to `suspicious_tld_count` or `urgency_density`. SVM and Gradient Boosting act more as "black boxes," making incident response harder.
* **Computational Cost**: Filtering thousands of emails per second requires extreme efficiency. Naive Bayes and Logistic Regression are computationally cheap (O(N)). Random Forest requires more memory and compute time per evaluation but remains parallelizable. Gradient Boosting and complex SVMs can introduce unacceptable latency for real-time delivery unless properly optimized.
* **Robustness**: Single decision boundary models (LR, NB) are easily gamed. Ensemble methods (RF, GB) are intrinsically more robust against minor feature perturbations, making them superior for cybersecurity applications.

## 3. Adversarial & Evasion Analysis

To simulate adversarial behavior, we tested our detection engine against targeted evasion techniques. Attackers are aware of automated filtering and actively mutate their payloads to bypass detection logic.

We passed two handcrafted evasion samples against our Gradient Boosting model:

1. **IoC Minimization (Bypass via Subtlety)**:
   * **Vector**: An email containing only 1 URL, zero suspicious TLDs, and avoiding aggressive urgency keywords, but subtly requesting a login validation.
   * **Result**: `LEGITIMATE (Bypassed)` with a mere 3.39% probability of being flagged malicious. The model failed to detect the implicit threat because the volume of IoCs was beneath its learned threshold.

2. **Obfuscation (Bypass via Symbol Substitution)**:
   * **Vector**: An email where the word "password" is replaced with "p@ssw0rd". This drops the `credential_request_density` to 0.0 but increases the `leetspeak_anomalies` slightly.
   * **Result**: `LEGITIMATE (Bypassed)` with a 5.52% probability of being flagged malicious. The simple feature mapping failed to catch the obfuscated credential request.

### Conclusion and Vulnerability Assessment

The evasion simulation proves that our current system, while mathematically accurate against the static dataset, is highly susceptible to **Adversarial Drift**. 

**Limitations of Detection:**
Relying solely on static IoCs allows attackers to mathematically "game" the system by distributing their malicious payloads across multiple benign-looking vectors. For instance, if the model heavily weights `urgency_density`, the adversary simply rewrites the phishing lure to sound casual.

**Proposed Mitigation:**
To build a truly resilient system, this ML classifier must act as merely *one layer* in a "defense-in-depth" architecture. Future iterations must include:
* Deep NLP models (like Transformers) to understand semantic context rather than just keyword density.
* Dynamic Link Analysis (following the URL in a sandbox environment) rather than relying on static URL character limits or known-bad TLDs.
