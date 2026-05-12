from pydantic import BaseModel, Field, field_validator
from datetime import datetime

class Email(BaseModel):
    raw_content: str = Field(
        
        min_length=10, 
        max_length=1048576, 
        description="Raw email data for IoC extraction"
    )

    @field_validator('raw_content')
    @classmethod
    def validate_rfc_headers(cls, v: str) -> str:
        """
        Operational Check: Ensure the input looks like a real email 
        header structure to prevent processing garbage data.
        """
        required_headers = ["From:", "Subject:"]
        if not all(header in v for header in required_headers):
            # We raise a ValueError which FastAPI converts to a 422 Unprocessable Entity
            raise ValueError("Input lacks standard RFC 5322 headers (From/Subject).")
        return v

class Response(BaseModel):
    status: str = Field(pattern="^(spam|ham)$") # Regex constraint
    verdict: str
    risk_level: str = Field(pattern="^(Low|Medium|High|Critical)$")
    confidence_score: float = Field(ge=0.0, le=1.0)
    analysed_at: str = Field(default_factory=lambda: datetime.isoformat())

    @field_validator('confidence_score')
    @classmethod
    def validate_score(cls, v: float) -> float:
        return round(v, 4)