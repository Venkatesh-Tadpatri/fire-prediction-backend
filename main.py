from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
import os
import random
import pytz
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi import HTTPException
from models import UPSData

from fastapi import BackgroundTasks

# ✅ Absolute imports
from database import SessionLocal, engine
import models, schemas
from schemas import SensorData as SensorDataSchema
from models import User

from passlib.context import CryptContext

# -------------------- Password Hashing --------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# Load env variables
load_dotenv()

# Create DB tables
models.Base.metadata.create_all(bind=engine)

# ✅ FastAPI app
app = FastAPI()

# ✅ Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Dependency for DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -------------------- Email Config --------------------
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=int(os.getenv("MAIL_PORT")),
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_STARTTLS=os.getenv("MAIL_STARTTLS") == "True",
    MAIL_SSL_TLS=os.getenv("MAIL_SSL_TLS") == "True",
    USE_CREDENTIALS=True,
)


# -------------------- API Endpoints ----------------------------------------------
@app.post("/sensor-data")
def create_sensor_data(data: schemas.SensorDataCreate, db: Session = Depends(get_db)):
    new_entry = models.SensorData(
        temperature=data.temperature,
        humidity=data.humidity,
        smoke_level=data.smoke_level,
        voltage=data.voltage,
        air_velocity=data.air_velocity,
        pressure=data.pressure,
        timestamp=data.timestamp,
    )
    db.add(new_entry)
    db.commit()
    db.refresh(new_entry)
    return {"message": "Sensor data saved", "id": new_entry.id}


# Used to fetch data by ID (given in body)
class SensorIdRequest(BaseModel):
    id: int

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    confirm_password: str    

class LoginRequest(BaseModel):
    email: EmailStr
    password: str    

class VerifyOTPRequest(BaseModel):
    email: str
    otp: str 

class ResetPasswordRequest(BaseModel):
    email: str
    password: str
    confirm_password: str    

class ResendOTPRequest(BaseModel):
    email: EmailStr 

class PanelNameRequest(BaseModel):
    panel_name: str      

class PanelNameRequest(BaseModel):
    panel_name: str  

# Request schema to pass ups_id or ups_name
class UPSIdRequest(BaseModel):
    ups_id: str = None
    ups_name: str = None          


@app.post("/get-sensor-data-by-id", response_model=schemas.SensorData)
def get_sensor_data_by_id_body(request: SensorIdRequest, db: Session = Depends(get_db)):
    data = db.query(models.SensorData).filter(models.SensorData.id == request.id).first()
    if data is None:
        raise HTTPException(status_code=404, detail="Sensor data not found")
    return data


# -------------------- User Registration --------------------
@app.post("/register", response_model=schemas.UserResponse)
async def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Check if email already exists
    existing_user = db.query(models.User).filter(models.User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Check if contact number already exists
    existing_contact = db.query(models.User).filter(models.User.contact_number == user.contact_number).first()
    if existing_contact:
        raise HTTPException(status_code=400, detail="Contact number already registered")

    # Check password match
    if user.password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # ✅ Hash the password before saving
    hashed_password = get_password_hash(user.password)
    hashed_confirm_password = get_password_hash(user.confirm_password)

    # ✅ Define timezone first
    india = pytz.timezone("Asia/Kolkata")

    # ✅ Generate unique 6-digit OTP
    otp = str(random.randint(100000, 999999))
    otp_expiry = datetime.now(india) + timedelta(minutes=10)


    # ✅ Create user 
    new_user = models.User(
        name=user.name,
        last_name=user.last_name,
        email=user.email,
        contact_number=user.contact_number,
        password=hashed_password,
        confirm_password=hashed_confirm_password,
        otp=otp,  
        otp_expiry=otp_expiry  
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # ✅ Send confirmation email
    message = MessageSchema(
        subject="Your OTP for Registration",
        recipients=[user.email],
        body=f"Hello {user.name},\n\nYour OTP for completing registration is: {otp}\n\nThis OTP is valid for 10 minutes.\n\nBest regards,\nMepstra IT Solutions",
        subtype="plain",
    )
    fm = FastMail(conf)
    await fm.send_message(message)

    return {"message": "Registration successful"}








# -------------------- Test Email --------------------
@app.get("/test-email")
async def test_email():
    message = MessageSchema(
        subject="Test Email",
        recipients=[os.getenv("MAIL_USERNAME")],
        body="This is a test email from Fire Prediction App 🚀",
        subtype="plain",
    )
    fm = FastMail(conf)
    await fm.send_message(message)
    return {"message": "Test email sent successfully!"}


@app.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    # find user by email
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # verify password
    if not pwd_context.verify(request.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # check OTP verification status
    if not user.otp_status:
        raise HTTPException(
            status_code=403,
            detail="Please verify your OTP before logging in"
        )

    return {"message": "Login successful"}


@app.post("/verify-otp")
async def verify_otp(request: VerifyOTPRequest, db: Session = Depends(get_db)):
    email = request.email
    otp = request.otp

    # 1️⃣ Find user by email
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 2️⃣ Check if OTP matches
    if user.otp != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # 3️⃣ Check if OTP expired (IST)
    if not user.otp_expiry:
        raise HTTPException(status_code=400, detail="OTP not generated")

    india = pytz.timezone("Asia/Kolkata")
    
    now_ist = datetime.now(india).replace(tzinfo=None)

    if now_ist > user.otp_expiry:
        raise HTTPException(status_code=400, detail="OTP expired")

    # 4️⃣ Mark OTP as verified
    user.otp_status = True
    db.commit()
    db.refresh(user)

    return {"message": "OTP verified successfully"}



# -------------------- Resend OTP --------------------
@app.post("/resend-otp")
async def resend_otp(request: ResendOTPRequest, db: Session = Depends(get_db)):
    email = request.email

    # 1️⃣ Find user
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 2️⃣ Generate new OTP
    otp = str(random.randint(100000, 999999))
    india = pytz.timezone("Asia/Kolkata")
    otp_expiry = datetime.now(india) + timedelta(minutes=10)

    # 3️⃣ Update user
    user.otp = otp
    user.otp_expiry = otp_expiry
    user.otp_status = False
    db.commit()
    db.refresh(user)

    # 4️⃣ Send OTP email
    message = MessageSchema(
        subject="Your New OTP for Verification",
        recipients=[user.email],
        body=f"Hello {user.name},\n\nYour new OTP is: {otp}\n\nThis OTP is valid for 10 minutes.\n\nBest regards,\nMepstra IT Solutions",
        subtype="plain",
    )
    fm = FastMail(conf)
    await fm.send_message(message)

    return {"message": "New OTP sent successfully"}





@app.post("/forgot-password")
async def forgot_password(email: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate OTP
    otp = str(random.randint(100000, 999999))

    # Set OTP expiry (10 mins from now IST)
    india = pytz.timezone("Asia/Kolkata")
    otp_expiry = datetime.now(india).replace(tzinfo=None) + timedelta(minutes=10)

    user.otp = otp
    user.otp_expiry = otp_expiry
    user.otp_status = False
    db.commit()
    db.refresh(user)

    # Send OTP via email
    message = MessageSchema(
        subject="Password Reset OTP",
        recipients=[email],
        body=f"Hello {user.name},\n\nYour OTP for password reset is: {otp}\nIt is valid for 10 minutes.\n\nBest regards,\nMepstra IT Solutions",
        subtype="plain"
    )
    fm = FastMail(conf)
    await fm.send_message(message)

    return {"message": "OTP sent to your email"} 



@app.post("/verify-forgot-otp")
def verify_forgot_otp(request: VerifyOTPRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    india = pytz.timezone("Asia/Kolkata")
    now_ist = datetime.now(india).replace(tzinfo=None)

    if user.otp != request.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    if not user.otp_expiry or now_ist > user.otp_expiry:
        raise HTTPException(status_code=400, detail="OTP expired")

    # Mark OTP verified
    user.otp_status = True
    db.commit()
    db.refresh(user)

    return {"message": "OTP verified successfully"}   



@app.post("/reset-password")
def reset_password(
    request: ResetPasswordRequest, 
    db: Session = Depends(get_db), 
    background_tasks: BackgroundTasks = None
):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.otp_status:
        raise HTTPException(status_code=403, detail="Please verify OTP first")

    if request.password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # Hash new password
    hashed_password = pwd_context.hash(request.password)
    user.password = hashed_password

    # Reset OTP fields
    user.otp_status = False
    user.otp = None
    user.otp_expiry = None

    db.commit()
    db.refresh(user)

    # Prepare email
    message = MessageSchema(
        subject="Password Reset Successful",
        recipients=[user.email],
        body=(
            f"Hello {user.name},\n\n"
            "Your password has been changed successfully.\n"
            "If you did not perform this action, please contact support immediately.\n\n"
            "Best regards,\nMepstra IT Solutions."
        ),
        subtype="plain"
    )

    # Send email in background (optional)
    if background_tasks:
        try:
            background_tasks.add_task(FastMail(conf).send_message, message)
        except Exception as e:
            # Log instead of failing the API
            print(f"[Warning] Failed to send email: {e}")

    return {"message": "Password reset successfully. Email notification (if possible) sent."}



@app.post("/get-user-profile", response_model=schemas.UserProfileResponse)
def get_user_profile(request: schemas.EmailRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "name": user.name,
        "last_name": user.last_name,
        "contact_number": user.contact_number,
        "email": user.email
    }



@app.put("/update-user-profile", response_model=schemas.UserProfileResponse)
def update_user_profile(request: schemas.UpdateUserRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update only provided fields
    if request.name is not None:
        user.name = request.name
    if request.last_name is not None:
        user.last_name = request.last_name
    if request.contact_number is not None:
        user.contact_number = request.contact_number

    db.commit()
    db.refresh(user)

    return {
        "name": user.name,
        "last_name": user.last_name,
        "contact_number": user.contact_number,
        "email": user.email
    }






def calculate_risk(data):
    # Prevent division by zero
    I_abn = 0 if data.rated_current == 0 else abs(data.I_phaseA - data.rated_current) / data.rated_current

    # Risk sub-scores
    CRS = 0.5 * data.R_contact_norm + 0.3 * data.T_contact_norm + 0.2 * I_abn             #CRS - Contact Risk Score
    PDS = 0.6 * data.HF_I_env_norm + 0.4 * data.US_sig_norm                               #PDS - Power Distribution Score 
    ATS = 0.5 * data.transient_peak_norm + 0.3 * data.pulse_rate_norm + 0.2 * data.HF_energy_norm  #ATS – Arc/Transient Score
    TRS = 0.5 * data.T_contact_norm + 0.3 * data.thermal_gradient_norm + 0.2 * data.T_bus_norm     #TRS – Thermal/Temperature Risk Score
    IDS = 0.6 * (1 - data.IR_norm) + 0.4 * data.PD_trend_norm                                      #IDS – Insulation/Dielectric Score
    LFS = 0.7 * data.I_leak_norm + 0.3 * data.neutral_imbalance                                    #LFS – Leakage/Load Flow Score  

    PRS = 0.2 * CRS + 0.15 * PDS + 0.25 * ATS + 0.2 * TRS + 0.1 * IDS + 0.1 * LFS

    # Determine risk level
    if PRS < 0.5:
        risk_level = "Normal"
    elif PRS < 0.7:
        risk_level = "Warning"
    elif PRS < 0.85:
        risk_level = "High"
    else:
        risk_level = "Critical"

    return PRS, risk_level


@app.post("/calculate_risk", response_model=schemas.RiskResponse)
def create_panel_risk(request: PanelNameRequest, db: Session = Depends(get_db)):
    panel = db.query(models.PanelRiskData).filter(models.PanelRiskData.panel_name == request.panel_name).first()
    
    if not panel:
        raise HTTPException(status_code=404, detail="Panel not found")
    
    PRS, risk_level = calculate_risk(panel)
    panel.risk_score = PRS
    panel.risk_level = risk_level
    db.commit()
    db.refresh(panel)

    return schemas.RiskResponse(
        risk_score=panel.risk_score,
        risk_level=panel.risk_level,
        created_at=panel.created_at.isoformat()
    )


# Risk calculation function
def real_values_calculate_risk(panel):
    # Prevent division by zero
    I_abn = abs(panel.I_phaseA - panel.rated_current) / panel.rated_current if panel.rated_current else 0

    # Risk sub-scores
    CRS = 0.5 * panel.R_contact_norm + 0.3 * panel.T_contact_norm + 0.2 * I_abn  #CRS - Contact Risk Score
    PDS = 0.6 * panel.HF_I_env_norm + 0.4 * panel.US_sig_norm                    #PDS - Power Distribution Score 
    ATS = 0.5 * panel.transient_peak_norm + 0.3 * panel.pulse_rate_norm + 0.2 * panel.HF_energy_norm  #ATS – Arc/Transient Score
    TRS = 0.5 * panel.T_contact_norm + 0.3 * panel.thermal_gradient_norm + 0.2 * panel.T_bus_norm    #TRS – Thermal/Temperature Risk Score
    IDS = 0.6 * (1 - panel.IR_norm) + 0.4 * panel.PD_trend_norm                                    #IDS – Insulation/Dielectric Score
    LFS = 0.7 * panel.I_leak_norm + 0.3 * panel.neutral_imbalance                                    #LFS – Leakage/Load Flow Score  

    PRS = 0.2 * CRS + 0.15 * PDS + 0.25 * ATS + 0.2 * TRS + 0.1 * IDS + 0.1 * LFS

    # Determine risk level
    if PRS < 0.5:
        risk_level = "Normal"
    elif PRS < 0.7:
        risk_level = "Warning"
    elif PRS < 0.85:
        risk_level = "High"
    else:
        risk_level = "Critical"

    return PRS, risk_level

# Request schema to only pass panel_name
class PanelNameRequest(schemas.BaseModel):
    panel_name: str

@app.post("/real_value_update_panel_risk", response_model=schemas.RiskResponse)
def update_panel_risk(request: PanelNameRequest, db: Session = Depends(get_db)):
    # Fetch the panel from DB
    panel = db.query(models.PanelRiskData).filter(models.PanelRiskData.panel_name == request.panel_name).first()
    if not panel:
        raise HTTPException(status_code=404, detail="Panel not found")

    # Calculate updated risk
    PRS, risk_level = real_values_calculate_risk(panel)

    # Update only risk_score and risk_level
    panel.risk_score = PRS
    panel.risk_level = risk_level
    db.commit()
    db.refresh(panel)

    # Return response
    return schemas.RiskResponse(
        risk_score=panel.risk_score,
        risk_level=panel.risk_level,
        created_at=panel.created_at.isoformat()
    )




# -----------------------------------------------------------example of calculation------------------------------


# # Example real-time data for Panel_D
# panel_real_time_data = {
#     "I_phaseA": 600.0,
#     "rated_current": 400.0,
#     "R_contact_norm": 0.9,
#     "T_contact_norm": 0.98,
#     "HF_I_env_norm": 0.8,
#     "US_sig_norm": 0.75,
#     "transient_peak_norm": 0.9,
#     "pulse_rate_norm": 0.8,
#     "HF_energy_norm": 0.7,
#     "T_bus_norm": 0.8,
#     "IR_norm": 0.3,
#     "PD_trend_norm": 0.8,
#     "I_leak_norm": 0.5,
#     "neutral_imbalance": 0.6,
#     "thermal_gradient_norm": 0.7
# }

# def calculate_risk(panel):
#     I_abn = abs(panel.I_phaseA - panel.rated_current) / panel.rated_current if panel.rated_current else 0

#     CRS = 0.5 * panel.R_contact_norm + 0.3 * panel.T_contact_norm + 0.2 * I_abn  
#     PDS = 0.6 * panel.HF_I_env_norm + 0.4 * panel.US_sig_norm
#     ATS = 0.5 * panel.transient_peak_norm + 0.3 * panel.pulse_rate_norm + 0.2 * panel.HF_energy_norm
#     TRS = 0.5 * panel.T_contact_norm + 0.3 * panel.thermal_gradient_norm + 0.2 * panel.T_bus_norm
#     IDS = 0.6 * (1 - panel.IR_norm) + 0.4 * panel.PD_trend_norm
#     LFS = 0.7 * panel.I_leak_norm + 0.3 * panel.neutral_imbalance

#     PRS = 0.2 * CRS + 0.15 * PDS + 0.25 * ATS + 0.2 * TRS + 0.1 * IDS + 0.1 * LFS

#     if PRS < 0.5:
#         risk_level = "Normal"
#     elif PRS < 0.7:
#         risk_level = "Warning"
#     elif PRS < 0.85:
#         risk_level = "High"
#     else:
#         risk_level = "Critical"

#     print(f"[DEBUG] PRS: {PRS}, Risk Level: {risk_level}")
#     return PRS, risk_level

# @app.post("/update_panel_d_risk", response_model=schemas.RiskResponse)
# def update_panel_d_risk(db: Session = Depends(get_db)):
#     # Fetch Panel_D from DB
#     panel = db.query(models.PanelRiskData).filter(models.PanelRiskData.panel_name == "Panel_D").first()
#     if not panel:
#         raise HTTPException(status_code=404, detail="Panel_D not found")

#     # Update panel fields with real-time data (optional, if only risk_score/risk_level change, skip these)
#     for key, value in panel_real_time_data.items():
#         setattr(panel, key, value)

#     # Calculate updated risk
#     PRS, risk_level = calculate_risk(panel)

#     # Update only risk_score and risk_level
#     panel.risk_score = PRS
#     panel.risk_level = risk_level
#     db.commit()
#     db.refresh(panel)

#     return schemas.RiskResponse(
#         risk_score=panel.risk_score,
#         risk_level=panel.risk_level,
#         created_at=panel.created_at.isoformat()
#     )


#---------------------------------------------------------------------------------------------------------------


# # Risk calculation function using real UPS values
# def real_values_calculate_ups_risk(ups: UPSData):
#     # Prevent division by zero
#     I_score = ups.I / ups.I if ups.I else 0
#     T_score = (ups.TUPS - 0) / ups.TUPS if ups.TUPS else 0  # Assuming min 0
#     IL_score = ups.IL / ups.IL if ups.IL else 0
#     THD_score = ups.THD / ups.THD if ups.THD else 0
#     PF_score = 1 - ups.PF if ups.PF else 0
#     V_score = 0  # Not considered

#     # TRS calculation with weights
#     WEIGHTS = {"I": 0.2, "V": 0.1, "PF": 0.1, "T": 0.3, "IL": 0.2, "THD": 0.1}
#     TRS = (
#         WEIGHTS["I"] * I_score +
#         WEIGHTS["V"] * V_score +
#         WEIGHTS["PF"] * PF_score +
#         WEIGHTS["T"] * T_score +
#         WEIGHTS["IL"] * IL_score +
#         WEIGHTS["THD"] * THD_score
#     )

#     # Determine risk level
#     if TRS < 0.3:
#         risk_level = "Normal"
#     elif TRS < 0.6:
#         risk_level = "Medium"
#     else:
#         risk_level = "High"

#     return TRS, risk_level

# # UPS risk calculation endpoint
# @app.post("/calculate_ups_risk", response_model=schemas.RiskResponse)
# def calculate_ups_risk(request: UPSIdRequest, db: Session = Depends(get_db)):
#     if not request.ups_id and not request.ups_name:
#         raise HTTPException(status_code=400, detail="Provide either ups_id or ups_name")

#     # Fetch UPS data
#     if request.ups_id:
#         ups = db.query(UPSData).filter(UPSData.ups_id == request.ups_id).first()
#     else:
#         ups = db.query(UPSData).filter(UPSData.ups_name == request.ups_name).first()

#     if not ups:
#         raise HTTPException(status_code=404, detail="UPS not found")

#     # Calculate risk using live UPS values
#     trs, risk_level = real_values_calculate_ups_risk(ups)

#     # Update UPS data in DB
#     ups.risk_score = round(trs, 3)
#     ups.risk_level = risk_level
#     ups.risk_created_at = datetime.utcnow()
#     db.commit()
#     db.refresh(ups)

#     # Return response
#     return schemas.RiskResponse(
#         risk_score=ups.risk_score,
#         risk_level=ups.risk_level,
#         created_at=ups.risk_created_at.isoformat()
#     )





# Request body model
class UPSIDRequest(BaseModel):
    ups_id: str

# TRS calculation
def calculate_trs(ups: UPSData):

    # Safe max values for normalization
    MAX_VALUES = {
        "I": 100.0,
        "TUPS": 80.0,
        "IL": 30.0,
        "THD": 15.0
    }

    # Weight factors
    WEIGHTS = {
        "I": 0.2,
        "V": 0.0,  # Not used
        "PF": 0.1,
        "T": 0.3,
        "IL": 0.2,
        "THD": 0.1
    }
    I_score = ups.I / MAX_VALUES["I"]
    T_score = ups.TUPS / MAX_VALUES["TUPS"]
    IL_score = ups.IL / MAX_VALUES["IL"]
    THD_score = ups.THD / MAX_VALUES["THD"]
    PF_score = 1 - ups.PF

    TRS = (
        WEIGHTS["I"] * I_score +
        WEIGHTS["V"] * 0 +
        WEIGHTS["PF"] * PF_score +
        WEIGHTS["T"] * T_score +
        WEIGHTS["IL"] * IL_score +
        WEIGHTS["THD"] * THD_score
    )

    if TRS < 0.3:
        risk_level = "Normal"
    elif TRS < 0.6:
        risk_level = "Medium"
    else:
        risk_level = "High"

    return TRS, risk_level

@app.post("/calculate_ups_risk", response_model=schemas.RiskResponse)
def calculate_ups_risk(request: UPSIDRequest, db: Session = Depends(get_db)):
    # Fetch UPS live data
    ups = db.query(UPSData).filter(UPSData.ups_id == request.ups_id).first()
    if not ups:
        raise HTTPException(status_code=404, detail="UPS_id not found")

    # Calculate TRS and risk
    trs, risk_level = calculate_trs(ups)

    # Update DB
    ups.risk_score = round(trs, 3)
    ups.risk_level = risk_level
    ups.risk_created_at = datetime.utcnow()
    db.commit()
    db.refresh(ups)

    # Return response
    return schemas.RiskResponse(
        risk_score=ups.risk_score,
        risk_level=ups.risk_level,
        created_at=ups.risk_created_at.isoformat()
    )