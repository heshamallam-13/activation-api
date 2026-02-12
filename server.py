from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import os
import re
from dotenv import load_dotenv
from auth import generate_license

load_dotenv()

app = FastAPI()

API_SECRET = os.getenv("API_SECRET")

# -----------------------
# Request Model
# -----------------------

class ActivationRequest(BaseModel):
    hardware_id: str
    duration: int

# -----------------------
# HWID Validation Function
# -----------------------

def validate_hwid(hwid: str):
    # تنظيف المسافات وتحويل للحروف الكبيرة
    hwid = hwid.strip().upper()
    
    # التحقق من الصيغة: 32 حرف، A-F0-9 فقط
    pattern = r"^[A-F0-9]{32}$"
    if not re.fullmatch(pattern, hwid):
        raise HTTPException(
            status_code=400,
            detail="Invalid Hardware ID format. Must be 32 characters HEX (0-9, A-F)"
        )
    
    return hwid  # نرجع الـ HWID بعد التنظيف

# -----------------------
# Endpoint
# -----------------------

@app.post("/activate")
def activate_license(data: ActivationRequest, x_api_key: str = Header(None)):

    # 🔐 حماية الـ API
    if x_api_key != API_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")

    # ✅ التحقق من صيغة HWID
    validated_hwid = validate_hwid(data.hardware_id)

    # ✅ تمرير الـ HWID النظيف للـ generate_license
    license_key, expiration = generate_license(
        data.duration,
        validated_hwid
    )

    return {
        "license_key": license_key,
        "expires": expiration
    }