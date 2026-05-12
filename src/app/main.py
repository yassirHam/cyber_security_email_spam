import logging
import joblib
import pandas as pd
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from schemas import Email, Response
from utils.feature_extractor import SecurityFeatureExtractor

# --- SIEM-READY LOGGING ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("GatewayAppliance")

audit_logger = logging.getLogger("SECURITY_AUDIT")
audit_handler = logging.FileHandler("security_audit.log")
audit_handler.setFormatter(logging.Formatter("%(asctime)s | VERDICT:%(verdict)s | RISK:%(risk)s | IP:%(client_ip)s"))
audit_logger.addHandler(audit_handler)
audit_logger.propagate = False

# --- RATE LIMITING ---
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="ESG-1000", version="1.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- RESOURCE LOADING ---
try:
    PHISHING_MODEL = joblib.load("phishing_detector.joblib")
    EXTRACTOR = SecurityFeatureExtractor()
    logger.info("Defense Engines online.")
except Exception as e:
    logger.critical(f"Engine Failure: {e}")
    PHISHING_MODEL = None

@app.post("/analyser", response_model=Response)
@limiter.limit("20/minute") 
async def analyser_email(request: Request, email: Email):
    if not PHISHING_MODEL:
        raise HTTPException(status_code=503, detail="Engine Offline")

    # 1. Feature Extraction
    features = EXTRACTOR.extract_iocs(email.raw_content)
    df = pd.DataFrame([features])
    
    # 2. ML Probability
    prob = PHISHING_MODEL.predict_proba(df)[0][1]
    
    # 3. Hybrid Logic: Heuristic Override
    # Even if ML says < 0.5, we flag if specific dangerous IoCs are high
    is_policy_violation = (
        features.get('url_count', 0) > 0 and 
        features.get('credential_request_density', 0) > 0.05
    )

    if is_policy_violation or prob > 0.5:
        prediction = 1
        verdict_text = "Phishing Detected (Policy Override)" if is_policy_violation and prob <= 0.5 else "Phishing Detected"
        risk = "High" if prob > 0.8 or is_policy_violation else "Medium"
    else:
        prediction = 0
        verdict_text = "Clean"
        risk = "Low"

    # 4. Audit Trail
    audit_logger.info("Scan Result", extra={
        "verdict": verdict_text,
        "risk": risk,
        "client_ip": request.client.host
    })

    return Response(
        status="spam" if prediction == 1 else "ham",
        verdict=verdict_text,
        risk_level=risk,
        confidence_score=prob,
        analysed_at=datetime.utcnow().isoformat()
    )