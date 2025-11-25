from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
import os
import random
import pytz
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi import HTTPException
from typing import Optional

from fastapi.responses import JSONResponse
from fastapi import BackgroundTasks

from models import PanelRiskData 
from models import UPSData
from models import ACData
from models import BatteryLiveData
from models import SwitchboardLiveData
from models import WiringEquipmentData

from schemas import ACRiskResponse

import socket  
from typing import List
import math
from math import exp


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


# -------------------- Email Configuration for sending an email --------------------
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




# Used to fetch data by ID (given in body)
class SensorIdRequest(BaseModel):
    id: int

class UserCreate(BaseModel):
    name: str
    last_name: str    
    email: EmailStr
    password: str
    confirm_password: str    

class MessageResponse(BaseModel):
    message: str    

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


# -------------------- API Endpoints for sensor data (dummy just for checking remove after development) ----------------------------------------------
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
   
         
# -------------------- API Endpoints for fetching the sensor data using ID (dummy just for checking remove after development) ----------------------------------------------
@app.post("/get-sensor-data-by-id", response_model=schemas.SensorData)
def get_sensor_data_by_id_body(request: SensorIdRequest, db: Session = Depends(get_db)):
    data = db.query(models.SensorData).filter(models.SensorData.id == request.id).first()
    if data is None:
        raise HTTPException(status_code=404, detail="Sensor data not found")
    return data


# -------------------- User Registration --------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    errors = [f"{err['loc'][-1]}: {err['msg']}" for err in exc.errors()]
    return JSONResponse(status_code=400, content={"message": ", ".join(errors)})


# -----------------------------------------------------------------------------------------------------
# Endpoint to register a new user.
# Accepts user details, validates them, and stores in the database.
@app.post("/register", response_model=schemas.MessageResponse)
async def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):

    # Check if email already exists
    if db.query(models.User).filter(models.User.email == user.email).first():
        return JSONResponse(status_code=400, content={"message": "Email already registered"})

    # Check if contact number already exists
    if db.query(models.User).filter(models.User.contact_number == user.contact_number).first():
        return JSONResponse(status_code=400, content={"message": "Contact number already registered"})

    # Hash the password
    hashed_password = get_password_hash(user.password)
    hashed_confirm_password = get_password_hash(user.confirm_password)

    # Timezone
    india = pytz.timezone("Asia/Kolkata")

    # Generate OTP
    otp = str(random.randint(100000, 999999))
    otp_expiry = datetime.now(india) + timedelta(minutes=10)

    # Create user
    new_user = models.User(
        name=user.name,
        last_name=user.last_name,
        email=user.email,
        contact_number=user.contact_number,
        password=hashed_password,
        confirm_password=hashed_confirm_password,
        otp=otp,
        otp_expiry=otp_expiry,
        otp_status=0
    )

    # Save to DB
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Send confirmation email
    message = MessageSchema(
        subject="Your OTP for Registration",
        recipients=[user.email],
        body=f"Hello {user.name},\n\nYour OTP for completing registration is: {otp}\n\nThis OTP is valid for 10 minutes.\n\nBest regards,\nMepstra IT Solutions",
        subtype="plain",
    )
    fm = FastMail(conf)
    await fm.send_message(message)

    return {"message": "Registration successful"}


# -----------------------------------------------------------------------------------------------------
# Endpoint to verify the otp entered by user.
# Verifies the entered otp with the database otp if matches then gives message OTP verified successfully.
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



# -----------------------------------------------------------------------------------------------------
# Endpoint to resend the otp for user verification.
# Sends an new otp and stored in database for verification.
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


# ---------------------------------Duplicate Api remove after development--------------------------------------------------------------------
# Endpoint to resend the otp for user verification.
# @app.post("/resend-otp")
# async def resend_otp(request: ResendOTPRequest, db: Session = Depends(get_db)):
#     email = request.email

#     # 1️⃣ Find user
#     user = db.query(models.User).filter(models.User.email == email).first()
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found")

#     # 2️⃣ Generate new OTP
#     otp = str(random.randint(100000, 999999))
#     india = pytz.timezone("Asia/Kolkata")
#     otp_expiry = datetime.now(india) + timedelta(minutes=10)

#     # 3️⃣ Update user
#     user.otp = otp
#     user.otp_expiry = otp_expiry
#     user.otp_status = False
#     db.commit()
#     db.refresh(user)

#     # 4️⃣ Send OTP email
#     message = MessageSchema(
#         subject="Your New OTP for Verification",
#         recipients=[user.email],
#         body=f"Hello {user.name},\n\nYour new OTP is: {otp}\n\nThis OTP is valid for 10 minutes.\n\nBest regards,\nMepstra IT Solutions",
#         subtype="plain",
#     )
#     fm = FastMail(conf)
#     await fm.send_message(message)

#     return {"message": "New OTP sent successfully"}




# --------------------------Sample Testing sending Email(Dummy just for checking remove after development)---------------------------------
@app.get("/test-email")
async def test_email():
    message = MessageSchema(
        subject="Test Email",
        recipients=[os.getenv("MAIL_USERNAME")],
        body="This is a test email from Fire Prediction App",
        subtype="plain",
    )
    fm = FastMail(conf)
    await fm.send_message(message)
    return {"message": "Test email sent successfully!"}


# -----------------------------------------------------------------------------------------------------
# Endpoint to Login theuser.
# Verifies user details, validates them, allows only if the entered user name and password matches from database.
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



# -----------------------------------------------------------------------------------------------------
# Endpoint to forgot-password for the user.
# If user forgots password then he can do forgot-password and reset the new password after successful verification of user.
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


# -----------------------------------------------------------------------------------------------------
# Endpoint to verify-forgot-otp for the user.
# If user clicks forgots password then he must verify with otp if entered otp matches then only he will allow to change the password.
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



# -----------------------------------------------------------------------------------------------------
# Endpoint to reset-password(change password) for the user.
# If user wants to change his password he can enter the email with new password and after verification with otp the new password will be updated.
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



# -----------------------------------------------------------------------------------------------------
# Endpoint to get user details to display all details in profile.
# With the user id fetching the details from database and sending in response.
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




# -----------------------------------------------------------------------------------------------------
# Endpoint to update-user-profile details.
# User can update his details from profile click update and saved in database.
@app.post("/update-user-profile", response_model=schemas.UserProfileResponse)
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



# Function to calculate_risk is to calculate the panel risk using the data from database.
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


# -----------------------------------------------------------------------------------------------------
# Endpoint to calculate_risk of panels.
# We are fetching the data from the panel_risk_data and Using them in algorithm and formula and predicting the risk level.
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




    



# Request model
class ACIDRequest(BaseModel):
    ac_id: int

# FARI calculation function
def calculate_fari(ac_data: ACData):
    # Constants
    α1, α2 = 0.7, 0.3
    β1, β2 = 0.6, 0.4
    W = [2.0, 1.5, 1.2, 1.0, 1.3]  # weights

    # Derived indices
    EAI = α1 * abs(ac_data.I_measured - ac_data.Irated)/ac_data.Irated + α2 * (ac_data.THD / ac_data.THDmax)
    TSI = (ac_data.Tc - ac_data.Tsafe) / ac_data.Tsafe
    CHI = β1 * (ac_data.ESR / ac_data.ESRlimit) + β2 * ac_data.C_drop
    MSI = ac_data.RHpcb / ac_data.RHthreshold
    CIRI = (ac_data.Ires / ac_data.Ilimit) + (1 / ac_data.IR)

    # Weighted FARI
    FARIraw = W[0]*EAI + W[1]*TSI + W[2]*CHI + W[3]*MSI + W[4]*CIRI
    FARInorm = FARIraw / sum(W)

    # Risk classification
    if FARInorm < 0.5:
        risk_level = "Low"
    elif 0.5 <= FARInorm < 1.0:
        risk_level = "Medium"
    elif 1.0 <= FARInorm < 1.5:
        risk_level = "High"
    else:
        risk_level = "Critical"

    return FARInorm, risk_level

# API endpoint
@app.post("/calculate_ac_risk", response_model=ACRiskResponse)
def calculate_ac_risk(request: ACIDRequest, db: Session = Depends(get_db)):
    # Fetch AC data
    ac_data = db.query(ACData).filter(ACData.ac_id == request.ac_id).first()
    if not ac_data:
        raise HTTPException(status_code=404, detail="AC data not found")

    # Calculate FARI and risk
    fari_score, risk_level = calculate_fari(ac_data)

    # Update DB
    ac_data.risk_score = round(fari_score, 3)
    ac_data.risk_level = risk_level
    ac_data.risk_created_at = datetime.utcnow()
    db.commit()
    db.refresh(ac_data)

    # Return response
    return ACRiskResponse(
        risk_score=ac_data.risk_score,
        risk_level=ac_data.risk_level,
        created_at=ac_data.risk_created_at.isoformat()
    )



# Request model
class BatteryIDRequest(BaseModel):
    battery_id: str

# Response model
class BatteryRiskResponse(BaseModel):
    risk_score: float
    risk_level: str
    created_at: str

# Calculation function (simple example)
def calculate_battery_risk(data: BatteryLiveData):
    """
    Example risk calculation based on live battery parameters.
    Replace with your actual model/formula later.
    """

    # Normalize values for scoring
    I_factor = abs(data.I_meas) / 100.0
    V_factor = abs(data.V_meas - 48) / 48.0      # assume 48V nominal
    T_factor = data.T_meas / 100.0
    SOC_factor = (100 - data.SOC_pred) / 100.0
    Cycle_factor = data.Cycle_pred / 1000.0
    IR_factor = data.IR_pred / 0.05              # assume 0.05Ω limit

    # Weighted risk score
    raw_score = (0.2 * I_factor +
                 0.2 * V_factor +
                 0.2 * T_factor +
                 0.2 * SOC_factor +
                 0.1 * Cycle_factor +
                 0.1 * IR_factor)

    risk_score = round(raw_score, 3)

    if risk_score < 0.3:
        risk_level = "Normal"
    elif 0.3 <= risk_score < 0.6:
        risk_level = "Medium"
    elif 0.6 <= risk_score < 0.8:
        risk_level = "High"
    else:  # risk_score >= 0.8
        risk_level = "Critical"    

    return risk_score, risk_level

# API endpoint
@app.post("/calculate_battery_risk", response_model=BatteryRiskResponse)
def calculate_battery_risk_api(request: BatteryIDRequest, db: Session = Depends(get_db)):
    # Fetch battery record
    battery_data = db.query(BatteryLiveData).filter(BatteryLiveData.battery_id == request.battery_id).first()
    if not battery_data:
        raise HTTPException(status_code=404, detail="Battery data not found")

    # Run risk calculation
    risk_score, risk_level = calculate_battery_risk(battery_data)

    #Update DB
    battery_data.risk_score = risk_score
    battery_data.risk_level = risk_level
    battery_data.risk_created_at = datetime.utcnow()
    db.commit()
    db.refresh(battery_data)

    # Return response
    return BatteryRiskResponse(
        risk_score=battery_data.risk_score,
        risk_level=battery_data.risk_level,
        created_at=battery_data.risk_created_at.isoformat()
    )


class SwitchboardIDRequest(BaseModel):
    switchboard_id: str

class SwitchboardRiskResponse(BaseModel):
    risk_score: float
    risk_level: str
    created_at: str

# ------------------ Calculation Function ------------------ #
def calculate_switchboard_risk(data: SwitchboardLiveData):
    I_RATED = 400.0
    V_NOM = 500.0
    T_SAFE = 80.0
    I_LEAK_MAX = 10.0
    R_REF = 0.05
    E_SAFE = 150.0
    DELTA_T_SAFE = 50.0

    w1, w2, w3, w4, w5, w6, w7, w8 = 0.1, 0.1, 0.1, 0.05, 0.1, 0.05, 0.15, 0.2

    X = (
        w1 * (data.I_load / I_RATED) +
        w2 * (data.V_meas / V_NOM) +
        w3 * (data.T_meas / T_SAFE) +
        w4 * (data.I_leak / I_LEAK_MAX) +
        w5 * (data.R_contact / R_REF) +
        w6 * (data.R_surface / R_REF) +
        w7 * (data.E_arc / E_SAFE) +
        w8 * (data.deltaT_pred / DELTA_T_SAFE)
    )

    # Sigmoid function
    risk_score = 1 / (1 + exp(-X))
    risk_score = round(risk_score, 3)

    if risk_score < 0.3:
        risk_level = "Normal"
    elif 0.3 >= risk_score < 0.6:
        risk_level = "Medium"
    else:
        risk_level = "High"

    return risk_score, risk_level

# ------------------ API Endpoint ------------------ #
@app.post("/calculate_switchboard_risk", response_model=SwitchboardRiskResponse)
def calculate_switchboard_risk_api(request: SwitchboardIDRequest, db: Session = Depends(get_db)):
    # Fetch the switchboard data
    sb_data = db.query(SwitchboardLiveData).filter(
        SwitchboardLiveData.switchboard_id == request.switchboard_id
    ).first()  # <-- MUST use .first() to get a single row

    if not sb_data:
        raise HTTPException(status_code=404, detail="Switchboard data not found")

    # Run calculation
    risk_score, risk_level = calculate_switchboard_risk(sb_data)

    # Update DB
    sb_data.risk_score = risk_score
    sb_data.risk_level = risk_level
    sb_data.risk_created_at = datetime.utcnow()
    db.commit()
    db.refresh(sb_data)

    return SwitchboardRiskResponse(
        risk_score=sb_data.risk_score,
        risk_level=sb_data.risk_level,
        created_at=sb_data.risk_created_at.isoformat()
    )

@app.get("/get_system_ip")
def get_system_ip():
    try:
        # Get local system IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return {"ip_address": local_ip}
    except Exception as e:
        return {"error": str(e)}
    

# --------------------------------------------------------------------------------------------------

# @app.post("/save_components", response_model=schemas.MessageResponse)
# async def save_components(request: schemas.ComponentCreateRequest, db: Session = Depends(get_db)):
#     user_name = request.user_name
#     components = request.components

#     # ✅ Check if user exists
#     user_exists = db.query(models.User).filter(models.User.email == user_name).first()
#     if not user_exists:
#         raise HTTPException(status_code=404, detail="User not found")

#     # ✅ Get all existing components for the user
#     existing_components = db.query(models.ComponentLayout).filter(
#         models.ComponentLayout.user_name == user_name
#     ).all()

#     existing_instance_ids = {comp.instance_id for comp in existing_components}
#     new_instance_ids = {comp.instance_id for comp in components}

#     # ✅ 1. DELETE components not present in new request
#     for comp in existing_components:
#         if comp.instance_id not in new_instance_ids:
#             db.delete(comp)

#     # ✅ 2. INSERT or UPDATE existing components
#     for comp in components:
#         existing_component = db.query(models.ComponentLayout).filter(
#             models.ComponentLayout.user_name == user_name,
#             models.ComponentLayout.instance_id == comp.instance_id
#         ).first()

#         if existing_component:
#             existing_component.position_x = comp.position_x
#             existing_component.position_y = comp.position_y
#             existing_component.component_name = comp.component_name
#             existing_component.floor_name = comp.floor_name
#         else:
#             new_component = models.ComponentLayout(
#                 user_name=user_name,
#                 floor_name=comp.floor_name,
#                 component_name=comp.component_name,
#                 instance_id=comp.instance_id,
#                 position_x=comp.position_x,
#                 position_y=comp.position_y
#             )
#             db.add(new_component)

#     db.commit()
#     return {"message": "Components saved, updated, and deleted successfully"}


# @app.post("/save_components", response_model=schemas.MessageResponse)
# async def save_components(request: schemas.ComponentCreateRequest, db: Session = Depends(get_db)):
#     user_name = request.user_name
#     components = request.components

#     # ✅ Check if user exists
#     user_exists = db.query(models.User).filter(models.User.email == user_name).first()
#     if not user_exists:
#         raise HTTPException(status_code=404, detail="User not found")

#     # ✅ Get all existing components for the user
#     existing_components = db.query(models.ComponentLayout).filter(
#         models.ComponentLayout.user_name == user_name
#     ).all()

#     existing_instance_ids = {comp.instance_id for comp in existing_components}
#     new_instance_ids = {comp.instance_id for comp in components}

#     # ✅ 1. DELETE components not present in new request
#     for comp in existing_components:
#         if comp.instance_id not in new_instance_ids:
#             db.delete(comp)

#     # ✅ 2. INSERT or UPDATE components
#     for comp in components:
#         existing_component = db.query(models.ComponentLayout).filter(
#             models.ComponentLayout.user_name == user_name,
#             models.ComponentLayout.instance_id == comp.instance_id,
#             models.ComponentLayout.floor_name == comp.floor_name  # 🔹 include floor name in lookup
#         ).first()

#         if existing_component:
#             # Update existing record (only if same floor)
#             existing_component.position_x = comp.position_x
#             existing_component.position_y = comp.position_y
#             existing_component.component_name = comp.component_name
#         else:
#             # If floor changed or component not found → create new record
#             new_component = models.ComponentLayout(
#                 user_name=user_name,
#                 floor_name=comp.floor_name,
#                 component_name=comp.component_name,
#                 instance_id=comp.instance_id,
#                 position_x=comp.position_x,
#                 position_y=comp.position_y
#             )
#             db.add(new_component)

#     db.commit()
#     return {"message": "Components saved, updated, and deleted successfully"}


# @app.post("/save_components", response_model=schemas.MessageResponse)
# async def save_components(request: schemas.ComponentCreateRequest, db: Session = Depends(get_db)):
#     user_name = request.user_name
#     components = request.components

#     # ✅ Ensure user exists
#     user_exists = db.query(models.User).filter(models.User.email == user_name).first()
#     if not user_exists:
#         raise HTTPException(status_code=404, detail="User not found")

#     if not components:
#         raise HTTPException(status_code=400, detail="No components provided")

#     # 🔹 Identify the floor(s) involved in this save
#     floor_names = {comp.floor_name for comp in components}

#     for floor_name in floor_names:
#         # ✅ Get all existing components for this user and floor
#         existing_components = db.query(models.ComponentLayout).filter(
#             models.ComponentLayout.user_name == user_name,
#             models.ComponentLayout.floor_name == floor_name
#         ).all()

#         # ✅ Build unique (floor_name, instance_id) pairs for comparison
#         existing_keys = {(comp.floor_name, comp.instance_id) for comp in existing_components}
#         new_keys = {(comp.floor_name, comp.instance_id) for comp in components if comp.floor_name == floor_name}

#         # ✅ DELETE only components on this floor that are missing in the new request
#         for comp in existing_components:
#             if (comp.floor_name, comp.instance_id) not in new_keys:
#                 db.delete(comp)

#         # ✅ INSERT or UPDATE components for this floor
#         for comp in components:
#             if comp.floor_name != floor_name:
#                 continue  # skip components from other floors

#             existing_component = db.query(models.ComponentLayout).filter(
#                 models.ComponentLayout.user_name == user_name,
#                 models.ComponentLayout.floor_name == comp.floor_name,
#                 models.ComponentLayout.instance_id == comp.instance_id
#             ).first()

#             if existing_component:
#                 # Update existing component
#                 existing_component.position_x = comp.position_x
#                 existing_component.position_y = comp.position_y
#                 existing_component.component_name = comp.component_name
#             else:
#                 # Insert new component
#                 new_component = models.ComponentLayout(
#                     user_name=user_name,
#                     floor_name=comp.floor_name,
#                     component_name=comp.component_name,
#                     instance_id=comp.instance_id,
#                     position_x=comp.position_x,
#                     position_y=comp.position_y
#                 )
#                 db.add(new_component)

#     db.commit()
#     return {"message": "Components saved, updated, and deleted successfully (per floor)"}

# **********************************************************************************************

# @app.post("/save_components", response_model=schemas.MessageResponse)
# async def save_components(request: schemas.ComponentCreateRequest, db: Session = Depends(get_db)):
#     user_name = request.user_name
#     components = request.components

#     # ✅ Ensure user exists
#     user_exists = db.query(models.User).filter(models.User.email == user_name).first()
#     if not user_exists:
#         raise HTTPException(status_code=404, detail="User not found")

#     if not components:
#         raise HTTPException(status_code=400, detail="No components provided")

#     # 🔹 Identify floors involved
#     floor_names = {comp.floor_name for comp in components}

#     for floor_name in floor_names:
#         # ✅ Existing components for this user and floor
#         existing_components = db.query(models.ComponentLayout).filter(
#             models.ComponentLayout.user_name == user_name,
#             models.ComponentLayout.floor_name == floor_name
#         ).all()

#         # ✅ Build key sets for comparison
#         existing_keys = {(comp.floor_name, comp.instance_id) for comp in existing_components}
#         new_keys = {(comp.floor_name, comp.instance_id) for comp in components if comp.floor_name == floor_name}

#         # ✅ DELETE missing components (from both tables)
#         for comp in existing_components:
#             if (comp.floor_name, comp.instance_id) not in new_keys:
#                 db.delete(comp)

#                 # Delete from wiring_equipment_data using email instead of user_name
#                 wiring_item = db.query(models.WiringEquipmentData).filter(
#                     models.WiringEquipmentData.email == user_name,
#                     models.WiringEquipmentData.floor_name == comp.floor_name,
#                     models.WiringEquipmentData.instance_id == comp.instance_id
#                 ).first()
#                 if wiring_item:
#                     db.delete(wiring_item)

#         # ✅ INSERT or UPDATE per floor
#         for comp in components:
#             if comp.floor_name != floor_name:
#                 continue

#             # Update or insert ComponentLayout
#             existing_component = db.query(models.ComponentLayout).filter(
#                 models.ComponentLayout.user_name == user_name,
#                 models.ComponentLayout.floor_name == comp.floor_name,
#                 models.ComponentLayout.instance_id == comp.instance_id
#             ).first()

#             if existing_component:
#                 existing_component.position_x = comp.position_x
#                 existing_component.position_y = comp.position_y
#                 existing_component.component_name = comp.component_name
#             else:
#                 new_component = models.ComponentLayout(
#                     user_name=user_name,
#                     floor_name=comp.floor_name,
#                     component_name=comp.component_name,
#                     instance_id=comp.instance_id,
#                     position_x=comp.position_x,
#                     position_y=comp.position_y
#                 )
#                 db.add(new_component)

#             # ✅ Sync WiringEquipmentData using email field
#             existing_wiring = db.query(models.WiringEquipmentData).filter(
#                 models.WiringEquipmentData.email == user_name,
#                 models.WiringEquipmentData.floor_name == comp.floor_name,
#                 models.WiringEquipmentData.instance_id == comp.instance_id
#             ).first()

#             if existing_wiring:
#                 # Update if needed
#                 existing_wiring.floor_name = comp.floor_name
#                 existing_wiring.instance_id = comp.instance_id
#             else:
#                 # Insert new record
#                 new_wiring = models.WiringEquipmentData(
#                     email=user_name,
#                     floor_name=comp.floor_name,
#                     instance_id=comp.instance_id
#                 )
#                 db.add(new_wiring)

#     db.commit()
#     return {"message": "Components and wiring data saved, updated, and deleted successfully (per floor)"}


# @app.post("/save_components", response_model=schemas.MessageResponse)
# async def save_components(request: schemas.ComponentCreateRequest, db: Session = Depends(get_db)):
#     user_name = request.user_name
#     components = request.components

#     # ✅ Ensure user exists
#     user_exists = db.query(models.User).filter(models.User.email == user_name).first()
#     if not user_exists:
#         raise HTTPException(status_code=404, detail="User not found")

#     if not components:
#         raise HTTPException(status_code=400, detail="No components provided")

#     # 🔹 Identify floors involved
#     floor_names = {comp.floor_name for comp in components}

#     for floor_name in floor_names:
#         # ✅ Existing components for this user and floor
#         existing_components = db.query(models.ComponentLayout).filter(
#             models.ComponentLayout.user_name == user_name,
#             models.ComponentLayout.floor_name == floor_name
#         ).all()

#         # ✅ Build key sets for comparison
#         existing_keys = {(comp.floor_name, comp.instance_id) for comp in existing_components}
#         new_keys = {(comp.floor_name, comp.instance_id) for comp in components if comp.floor_name == floor_name}

#         # ✅ DELETE missing components (from all related tables)
#         for comp in existing_components:
#             if (comp.floor_name, comp.instance_id) not in new_keys:
#                 # Delete from ComponentLayout
#                 db.delete(comp)

#                 # Delete from WiringEquipmentData
#                 wiring_item = db.query(models.WiringEquipmentData).filter(
#                     models.WiringEquipmentData.email == user_name,
#                     models.WiringEquipmentData.floor_name == comp.floor_name,
#                     models.WiringEquipmentData.instance_id == comp.instance_id
#                 ).first()
#                 if wiring_item:
#                     db.delete(wiring_item)

#                 # Delete from PanelRiskData
#                 panel_item = db.query(models.PanelRiskData).filter(
#                     models.PanelRiskData.email == user_name,
#                     models.PanelRiskData.floor_name == comp.floor_name,
#                     models.PanelRiskData.instance_id == comp.instance_id
#                 ).first()
#                 if panel_item:
#                     db.delete(panel_item)

#         # ✅ INSERT or UPDATE per floor
#         for comp in components:
#             if comp.floor_name != floor_name:
#                 continue

#             # ---- ComponentLayout ----
#             existing_component = db.query(models.ComponentLayout).filter(
#                 models.ComponentLayout.user_name == user_name,
#                 models.ComponentLayout.floor_name == comp.floor_name,
#                 models.ComponentLayout.instance_id == comp.instance_id
#             ).first()

#             if existing_component:
#                 existing_component.position_x = comp.position_x
#                 existing_component.position_y = comp.position_y
#                 existing_component.component_name = comp.component_name
#             else:
#                 new_component = models.ComponentLayout(
#                     user_name=user_name,
#                     floor_name=comp.floor_name,
#                     component_name=comp.component_name,
#                     instance_id=comp.instance_id,
#                     position_x=comp.position_x,
#                     position_y=comp.position_y
#                 )
#                 db.add(new_component)

#             # ---- Conditional Syncs ----
#             # ✅ For wiring components
#             if comp.component_name.lower() == "wiring":
#                 existing_wiring = db.query(models.WiringEquipmentData).filter(
#                     models.WiringEquipmentData.email == user_name,
#                     models.WiringEquipmentData.floor_name == comp.floor_name,
#                     models.WiringEquipmentData.instance_id == comp.instance_id
#                 ).first()

#                 if existing_wiring:
#                     existing_wiring.floor_name = comp.floor_name
#                     existing_wiring.instance_id = comp.instance_id
#                 else:
#                     new_wiring = models.WiringEquipmentData(
#                         email=user_name,
#                         floor_name=comp.floor_name,
#                         instance_id=comp.instance_id
#                     )
#                     db.add(new_wiring)

#             # ✅ For panel components
#             elif comp.component_name.lower() == "panel":
#                 existing_panel = db.query(models.PanelRiskData).filter(
#                     models.PanelRiskData.email == user_name,
#                     models.PanelRiskData.floor_name == comp.floor_name,
#                     models.PanelRiskData.instance_id == comp.instance_id
#                 ).first()

#                 if existing_panel:
#                     existing_panel.floor_name = comp.floor_name
#                     existing_panel.instance_id = comp.instance_id
                   
#                 else:
#                     new_panel = models.PanelRiskData(
#                         email=user_name,
#                         floor_name=comp.floor_name,
#                         instance_id=comp.instance_id,
                      
#                     )
#                     db.add(new_panel)

#     db.commit()
#     return {"message": "Components synced successfully across related tables (per floor)"}

# ✅ Schema for inserting multiple components

# @app.post("/save_components", response_model=schemas.MessageResponse)
# async def save_components(request: schemas.ComponentCreateRequest, db: Session = Depends(get_db)):
#     user_name = request.user_name
#     components = request.components

#     # ✅ Ensure user exists
#     user_exists = db.query(models.User).filter(models.User.email == user_name).first()
#     if not user_exists:
#         raise HTTPException(status_code=404, detail="User not found")

#     if not components:
#         raise HTTPException(status_code=400, detail="No components provided")

#     # 🔹 Identify floors involved
#     floor_names = {comp.floor_name for comp in components}

#     for floor_name in floor_names:
#         # ✅ Existing components for this user and floor
#         existing_components = db.query(models.ComponentLayout).filter(
#             models.ComponentLayout.user_name == user_name,
#             models.ComponentLayout.floor_name == floor_name
#         ).all()

#         # ✅ Build key sets for comparison
#         existing_keys = {(comp.floor_name, comp.instance_id) for comp in existing_components}
#         new_keys = {(comp.floor_name, comp.instance_id) for comp in components if comp.floor_name == floor_name}

#         # ✅ DELETE missing components (from appropriate tables)
#         for comp in existing_components:
#             if (comp.floor_name, comp.instance_id) not in new_keys:
#                 component_type = comp.component_name.lower()

#                 # Delete from ComponentLayout
#                 db.delete(comp)

#                 if component_type == "wiring":
#                     wiring_item = db.query(models.WiringEquipmentData).filter(
#                         models.WiringEquipmentData.email == user_name,
#                         models.WiringEquipmentData.floor_name == comp.floor_name,
#                         models.WiringEquipmentData.instance_id == comp.instance_id
#                     ).first()
#                     if wiring_item:
#                         db.delete(wiring_item)

#                 elif component_type == "panel":
#                     panel_item = db.query(models.PanelRiskData).filter(
#                         models.PanelRiskData.email == user_name,
#                         models.PanelRiskData.floor_name == comp.floor_name,
#                         models.PanelRiskData.instance_id == comp.instance_id
#                     ).first()
#                     if panel_item:
#                         db.delete(panel_item)

#         # ✅ INSERT or UPDATE per floor
#         for comp in components:
#             if comp.floor_name != floor_name:
#                 continue

#             # ---- ComponentLayout ----
#             existing_component = db.query(models.ComponentLayout).filter(
#                 models.ComponentLayout.user_name == user_name,
#                 models.ComponentLayout.floor_name == comp.floor_name,
#                 models.ComponentLayout.instance_id == comp.instance_id
#             ).first()

#             if existing_component:
#                 existing_component.position_x = comp.position_x
#                 existing_component.position_y = comp.position_y
#                 existing_component.component_name = comp.component_name
#             else:
#                 new_component = models.ComponentLayout(
#                     user_name=user_name,
#                     floor_name=comp.floor_name,
#                     component_name=comp.component_name,
#                     instance_id=comp.instance_id,
#                     position_x=comp.position_x,
#                     position_y=comp.position_y
#                 )
#                 db.add(new_component)

#             # ---- Conditional Syncs ----
#             component_type = comp.component_name.lower()

#             if component_type == "wiring":
#                 existing_wiring = db.query(models.WiringEquipmentData).filter(
#                     models.WiringEquipmentData.email == user_name,
#                     models.WiringEquipmentData.floor_name == comp.floor_name,
#                     models.WiringEquipmentData.instance_id == comp.instance_id
#                 ).first()

#                 if existing_wiring:
#                     existing_wiring.floor_name = comp.floor_name
#                     existing_wiring.instance_id = comp.instance_id
#                 else:
#                     new_wiring = models.WiringEquipmentData(
#                         email=user_name,
#                         floor_name=comp.floor_name,
#                         instance_id=comp.instance_id
#                     )
#                     db.add(new_wiring)

#             elif component_type == "panel":
#                 existing_panel = db.query(models.PanelRiskData).filter(
#                     models.PanelRiskData.email == user_name,
#                     models.PanelRiskData.floor_name == comp.floor_name,
#                     models.PanelRiskData.instance_id == comp.instance_id
#                 ).first()

#                 if existing_panel:
#                     existing_panel.floor_name = comp.floor_name
#                     existing_panel.instance_id = comp.instance_id
                   
#                 else:
#                     new_panel = models.PanelRiskData(
#                         email=user_name,
#                         floor_name=comp.floor_name,
#                         instance_id=comp.instance_id,
                        
#                     )
#                     db.add(new_panel)

#     db.commit()
#     return {"message": "Components and related data updated and deleted correctly (per floor)"}

class LayoutSaveRequest(BaseModel):
    components: List[schemas.ComponentBase]

# @app.post("/save_components", response_model=schemas.MessageResponse)
# async def save_components(request: schemas.ComponentCreateRequest, db: Session = Depends(get_db)):
#     user_name = request.user_name
#     components = request.components

#     # ✅ Ensure user exists
#     user_exists = db.query(models.User).filter(models.User.email == user_name).first()
#     if not user_exists:
#         raise HTTPException(status_code=404, detail="User not found")

#     if not components:
#         raise HTTPException(status_code=400, detail="No components provided")

#     # 🔹 Identify floors involved
#     floor_names = {comp.floor_name for comp in components}

#     for floor_name in floor_names:
#         # ✅ Existing components for this user and floor
#         existing_components = db.query(models.ComponentLayout).filter(
#             models.ComponentLayout.user_name == user_name,
#             models.ComponentLayout.floor_name == floor_name
#         ).all()

#         # ✅ Build key sets for comparison
#         existing_keys = {(comp.floor_name, comp.instance_id) for comp in existing_components}
#         new_keys = {(comp.floor_name, comp.instance_id) for comp in components if comp.floor_name == floor_name}

#         # ✅ DELETE missing components (from respective tables)
#         for comp in existing_components:
#             if (comp.floor_name, comp.instance_id) not in new_keys:
#                 component_type = comp.component_name.lower()

#                 # Delete from ComponentLayout
#                 db.delete(comp)

#                 if component_type == "wiring":
#                     wiring_item = db.query(models.WiringEquipmentData).filter(
#                         models.WiringEquipmentData.email == user_name,
#                         models.WiringEquipmentData.floor_name == comp.floor_name,
#                         models.WiringEquipmentData.instance_id == comp.instance_id
#                     ).first()
#                     if wiring_item:
#                         db.delete(wiring_item)

#                 elif component_type == "panel":
#                     panel_item = db.query(models.PanelRiskData).filter(
#                         models.PanelRiskData.email == user_name,
#                         models.PanelRiskData.floor_name == comp.floor_name,
#                         models.PanelRiskData.instance_id == comp.instance_id
#                     ).first()
#                     if panel_item:
#                         db.delete(panel_item)

#                 elif component_type == "ac":
#                     ac_item = db.query(models.ACData).filter(
#                         models.ACData.email == user_name,
#                         models.ACData.floor_name == comp.floor_name,
#                         models.ACData.instance_id == comp.instance_id
#                     ).first()
#                     if ac_item:
#                         db.delete(ac_item)

#         # ✅ INSERT or UPDATE per floor
#         for comp in components:
#             if comp.floor_name != floor_name:
#                 continue

#             # ---- ComponentLayout ----
#             existing_component = db.query(models.ComponentLayout).filter(
#                 models.ComponentLayout.user_name == user_name,
#                 models.ComponentLayout.floor_name == comp.floor_name,
#                 models.ComponentLayout.instance_id == comp.instance_id
#             ).first()

#             if existing_component:
#                 existing_component.position_x = comp.position_x
#                 existing_component.position_y = comp.position_y
#                 existing_component.component_name = comp.component_name
#             else:
#                 new_component = models.ComponentLayout(
#                     user_name=user_name,
#                     floor_name=comp.floor_name,
#                     component_name=comp.component_name,
#                     instance_id=comp.instance_id,
#                     position_x=comp.position_x,
#                     position_y=comp.position_y
#                 )
#                 db.add(new_component)

#             # ---- Conditional Syncs ----
#             component_type = comp.component_name.lower()

#             if component_type == "wiring":
#                 existing_wiring = db.query(models.WiringEquipmentData).filter(
#                     models.WiringEquipmentData.email == user_name,
#                     models.WiringEquipmentData.floor_name == comp.floor_name,
#                     models.WiringEquipmentData.instance_id == comp.instance_id
#                 ).first()

#                 if existing_wiring:
#                     existing_wiring.floor_name = comp.floor_name
#                     existing_wiring.instance_id = comp.instance_id
#                 else:
#                     new_wiring = models.WiringEquipmentData(
#                         email=user_name,
#                         floor_name=comp.floor_name,
#                         instance_id=comp.instance_id
#                     )
#                     db.add(new_wiring)

#             elif component_type == "panel":
#                 existing_panel = db.query(models.PanelRiskData).filter(
#                     models.PanelRiskData.email == user_name,
#                     models.PanelRiskData.floor_name == comp.floor_name,
#                     models.PanelRiskData.instance_id == comp.instance_id
#                 ).first()

#                 if existing_panel:
#                     existing_panel.floor_name = comp.floor_name
#                     existing_panel.instance_id = comp.instance_id
#                 else:
#                     new_panel = models.PanelRiskData(
#                         email=user_name,
#                         floor_name=comp.floor_name,
#                         instance_id=comp.instance_id
#                     )
#                     db.add(new_panel)

#             elif component_type == "ac":
#                 existing_ac = db.query(models.ACData).filter(
#                     models.ACData.email == user_name,
#                     models.ACData.floor_name == comp.floor_name,
#                     models.ACData.instance_id == comp.instance_id
#                 ).first()

#                 if existing_ac:
#                     existing_ac.floor_name = comp.floor_name
#                     existing_ac.instance_id = comp.instance_id
#                 else:
#                     new_ac = models.ACData(
#                         email=user_name,
#                         floor_name=comp.floor_name,
#                         instance_id=comp.instance_id
#                     )
#                     db.add(new_ac)

#     db.commit()
#     return {"message": "Components and related equipment data synced successfully (per floor)"}



# @app.post("/save_components", response_model=schemas.MessageResponse)
# async def save_components(request: schemas.ComponentCreateRequest, db: Session = Depends(get_db)):
#     user_name = request.user_name
#     components = request.components

#     # ✅ Ensure user exists
#     user_exists = db.query(models.User).filter(models.User.email == user_name).first()
#     if not user_exists:
#         raise HTTPException(status_code=404, detail="User not found")

#     if not components:
#         raise HTTPException(status_code=400, detail="No components provided")

#     # 🔹 Identify unique floors
#     floor_names = {comp.floor_name for comp in components}

#     for floor_name in floor_names:
#         # ✅ Fetch existing components for this user and floor
#         existing_components = db.query(models.ComponentLayout).filter(
#             models.ComponentLayout.user_name == user_name,
#             models.ComponentLayout.floor_name == floor_name
#         ).all()

#         # ✅ Build key sets for comparison
#         existing_keys = {(comp.floor_name, comp.instance_id) for comp in existing_components}
#         new_keys = {(comp.floor_name, comp.instance_id) for comp in components if comp.floor_name == floor_name}

#         # ✅ DELETE missing components from relevant tables
#         for comp in existing_components:
#             if (comp.floor_name, comp.instance_id) not in new_keys:
#                 component_type = comp.component_name.lower()

#                 # Delete from ComponentLayout
#                 db.delete(comp)

#                 if component_type == "wiring":
#                     wiring_item = db.query(models.WiringEquipmentData).filter(
#                         models.WiringEquipmentData.email == user_name,
#                         models.WiringEquipmentData.floor_name == comp.floor_name,
#                         models.WiringEquipmentData.instance_id == comp.instance_id
#                     ).first()
#                     if wiring_item:
#                         db.delete(wiring_item)

#                 elif component_type == "panel":
#                     panel_item = db.query(models.PanelRiskData).filter(
#                         models.PanelRiskData.email == user_name,
#                         models.PanelRiskData.floor_name == comp.floor_name,
#                         models.PanelRiskData.instance_id == comp.instance_id
#                     ).first()
#                     if panel_item:
#                         db.delete(panel_item)

#                 elif component_type == "ac":
#                     ac_item = db.query(models.ACData).filter(
#                         models.ACData.email == user_name,
#                         models.ACData.floor_name == comp.floor_name,
#                         models.ACData.instance_id == comp.instance_id
#                     ).first()
#                     if ac_item:
#                         db.delete(ac_item)

#                 elif component_type == "battery":
#                     battery_item = db.query(models.BatteryLiveData).filter(
#                         models.BatteryLiveData.email == user_name,
#                         models.BatteryLiveData.floor_name == comp.floor_name,
#                         models.BatteryLiveData.instance_id == comp.instance_id
#                     ).first()
#                     if battery_item:
#                         db.delete(battery_item)

                        

#         # ✅ INSERT or UPDATE per floor
#         for comp in components:
#             if comp.floor_name != floor_name:
#                 continue

#             # ---- ComponentLayout ----
#             existing_component = db.query(models.ComponentLayout).filter(
#                 models.ComponentLayout.user_name == user_name,
#                 models.ComponentLayout.floor_name == comp.floor_name,
#                 models.ComponentLayout.instance_id == comp.instance_id
#             ).first()

#             if existing_component:
#                 existing_component.position_x = comp.position_x
#                 existing_component.position_y = comp.position_y
#                 existing_component.component_name = comp.component_name
#             else:
#                 new_component = models.ComponentLayout(
#                     user_name=user_name,
#                     floor_name=comp.floor_name,
#                     component_name=comp.component_name,
#                     instance_id=comp.instance_id,
#                     position_x=comp.position_x,
#                     position_y=comp.position_y
#                 )
#                 db.add(new_component)

#             # ---- Conditional Equipment Sync ----
#             component_type = comp.component_name.lower()

#             if component_type == "wiring":
#                 existing_wiring = db.query(models.WiringEquipmentData).filter(
#                     models.WiringEquipmentData.email == user_name,
#                     models.WiringEquipmentData.floor_name == comp.floor_name,
#                     models.WiringEquipmentData.instance_id == comp.instance_id
#                 ).first()

#                 if not existing_wiring:
#                     new_wiring = models.WiringEquipmentData(
#                         email=user_name,
#                         floor_name=comp.floor_name,
#                         instance_id=comp.instance_id
#                     )
#                     db.add(new_wiring)

#             elif component_type == "panel":
#                 existing_panel = db.query(models.PanelRiskData).filter(
#                     models.PanelRiskData.email == user_name,
#                     models.PanelRiskData.floor_name == comp.floor_name,
#                     models.PanelRiskData.instance_id == comp.instance_id
#                 ).first()

#                 if not existing_panel:
#                     new_panel = models.PanelRiskData(
#                         email=user_name,
#                         floor_name=comp.floor_name,
#                         instance_id=comp.instance_id
#                     )
#                     db.add(new_panel)

#             elif component_type == "ac":
#                 existing_ac = db.query(models.ACData).filter(
#                     models.ACData.email == user_name,
#                     models.ACData.floor_name == comp.floor_name,
#                     models.ACData.instance_id == comp.instance_id
#                 ).first()

#                 if not existing_ac:
#                     new_ac = models.ACData(
#                         email=user_name,
#                         floor_name=comp.floor_name,
#                         instance_id=comp.instance_id
#                     )
#                     db.add(new_ac)

#             elif component_type == "battery":
#                 existing_battery = db.query(models.BatteryLiveData).filter(
#                     models.BatteryLiveData.email == user_name,
#                     models.BatteryLiveData.floor_name == comp.floor_name,
#                     models.BatteryLiveData.instance_id == comp.instance_id
#                 ).first()

#                 if not existing_battery:
#                     new_battery = models.BatteryLiveData(
#                         email=user_name,
#                         floor_name=comp.floor_name,
#                         instance_id=comp.instance_id
#                     )
#                     db.add(new_battery)

#     db.commit()
#     return {"message": "Components and all related equipment data synced successfully (wiring/panel/ac/battery per floor)"}


# @app.post("/save_components", response_model=schemas.MessageResponse)
# async def save_components(request: schemas.ComponentCreateRequest, db: Session = Depends(get_db)):
#     user_name = request.user_name
#     components = request.components

#     # ✅ Ensure user exists
#     user_exists = db.query(models.User).filter(models.User.email == user_name).first()
#     if not user_exists:
#         raise HTTPException(status_code=404, detail="User not found")

#     if not components:
#         raise HTTPException(status_code=400, detail="No components provided")

#     # 🔹 Identify unique floors
#     floor_names = {comp.floor_name for comp in components}

#     for floor_name in floor_names:
#         # ✅ Fetch existing components for this user and floor
#         existing_components = db.query(models.ComponentLayout).filter(
#             models.ComponentLayout.user_name == user_name,
#             models.ComponentLayout.floor_name == floor_name
#         ).all()

#         # ✅ Build key sets for comparison
#         existing_keys = {(comp.floor_name, comp.instance_id) for comp in existing_components}
#         new_keys = {(comp.floor_name, comp.instance_id) for comp in components if comp.floor_name == floor_name}

#         # ✅ DELETE missing components from relevant tables
#         for comp in existing_components:
#             if (comp.floor_name, comp.instance_id) not in new_keys:
#                 component_type = comp.component_name.lower()

#                 # Delete from ComponentLayout
#                 db.delete(comp)

#                 if component_type == "wiring":
#                     item = db.query(models.WiringEquipmentData).filter(
#                         models.WiringEquipmentData.email == user_name,
#                         models.WiringEquipmentData.floor_name == comp.floor_name,
#                         models.WiringEquipmentData.instance_id == comp.instance_id
#                     ).first()
#                     if item:
#                         db.delete(item)

#                 elif component_type == "panel":
#                     item = db.query(models.PanelRiskData).filter(
#                         models.PanelRiskData.email == user_name,
#                         models.PanelRiskData.floor_name == comp.floor_name,
#                         models.PanelRiskData.instance_id == comp.instance_id
#                     ).first()
#                     if item:
#                         db.delete(item)

#                 elif component_type == "ac":
#                     item = db.query(models.ACData).filter(
#                         models.ACData.email == user_name,
#                         models.ACData.floor_name == comp.floor_name,
#                         models.ACData.instance_id == comp.instance_id
#                     ).first()
#                     if item:
#                         db.delete(item)

#                 elif component_type == "battery":
#                     item = db.query(models.BatteryLiveData).filter(
#                         models.BatteryLiveData.email == user_name,
#                         models.BatteryLiveData.floor_name == comp.floor_name,
#                         models.BatteryLiveData.instance_id == comp.instance_id
#                     ).first()
#                     if item:
#                         db.delete(item)

#                 elif component_type == "ups":
#                     item = db.query(models.UPSData).filter(
#                         models.UPSData.email == user_name,
#                         models.UPSData.floor_name == comp.floor_name,
#                         models.UPSData.instance_id == comp.instance_id
#                     ).first()
#                     if item:
#                         db.delete(item)

#         # ✅ INSERT or UPDATE per floor
#         for comp in components:
#             if comp.floor_name != floor_name:
#                 continue

#             # ---- ComponentLayout ----
#             existing_component = db.query(models.ComponentLayout).filter(
#                 models.ComponentLayout.user_name == user_name,
#                 models.ComponentLayout.floor_name == comp.floor_name,
#                 models.ComponentLayout.instance_id == comp.instance_id
#             ).first()

#             if existing_component:
#                 existing_component.position_x = comp.position_x
#                 existing_component.position_y = comp.position_y
#                 existing_component.component_name = comp.component_name
#             else:
#                 new_component = models.ComponentLayout(
#                     user_name=user_name,
#                     floor_name=comp.floor_name,
#                     component_name=comp.component_name,
#                     instance_id=comp.instance_id,
#                     position_x=comp.position_x,
#                     position_y=comp.position_y
#                 )
#                 db.add(new_component)

#             # ---- Conditional Equipment Sync ----
#             component_type = comp.component_name.lower()

#             if component_type == "wiring":
#                 existing = db.query(models.WiringEquipmentData).filter(
#                     models.WiringEquipmentData.email == user_name,
#                     models.WiringEquipmentData.floor_name == comp.floor_name,
#                     models.WiringEquipmentData.instance_id == comp.instance_id
#                 ).first()
#                 if not existing:
#                     db.add(models.WiringEquipmentData(
#                         email=user_name, floor_name=comp.floor_name, instance_id=comp.instance_id
#                     ))

#             elif component_type == "panel":
#                 existing = db.query(models.PanelRiskData).filter(
#                     models.PanelRiskData.email == user_name,
#                     models.PanelRiskData.floor_name == comp.floor_name,
#                     models.PanelRiskData.instance_id == comp.instance_id
#                 ).first()
#                 if not existing:
#                     db.add(models.PanelRiskData(
#                         email=user_name, floor_name=comp.floor_name, instance_id=comp.instance_id
#                     ))

#             elif component_type == "ac":
#                 existing = db.query(models.ACData).filter(
#                     models.ACData.email == user_name,
#                     models.ACData.floor_name == comp.floor_name,
#                     models.ACData.instance_id == comp.instance_id
#                 ).first()
#                 if not existing:
#                     db.add(models.ACData(
#                         email=user_name, floor_name=comp.floor_name, instance_id=comp.instance_id
#                     ))

#             elif component_type == "battery":
#                 existing = db.query(models.BatteryLiveData).filter(
#                     models.BatteryLiveData.email == user_name,
#                     models.BatteryLiveData.floor_name == comp.floor_name,
#                     models.BatteryLiveData.instance_id == comp.instance_id
#                 ).first()
#                 if not existing:
#                     db.add(models.BatteryLiveData(
#                         email=user_name, floor_name=comp.floor_name, instance_id=comp.instance_id
#                     ))

#             elif component_type == "ups":
#                 existing = db.query(models.UPSData).filter(
#                     models.UPSData.email == user_name,
#                     models.UPSData.floor_name == comp.floor_name,
#                     models.UPSData.instance_id == comp.instance_id
#                 ).first()
#                 if not existing:
#                     db.add(models.UPSData(
#                         email=user_name, floor_name=comp.floor_name, instance_id=comp.instance_id
#                     ))

#     db.commit()
#     return {"message": "Components and all related equipment data synced successfully (wiring/panel/ac/battery/ups per floor)"}

@app.post("/save_components", response_model=schemas.MessageResponse)
async def save_components(request: schemas.ComponentCreateRequest, db: Session = Depends(get_db)):
    user_name = request.user_name
    components = request.components

    # ✅ Ensure user exists
    user_exists = db.query(models.User).filter(models.User.email == user_name).first()
    if not user_exists:
        raise HTTPException(status_code=404, detail="User not found")

    if not components:
        raise HTTPException(status_code=400, detail="No components provided")

    # 🔹 Identify unique floors
    floor_names = {comp.floor_name for comp in components}

    for floor_name in floor_names:
        # ✅ Fetch existing components for this user and floor
        existing_components = db.query(models.ComponentLayout).filter(
            models.ComponentLayout.user_name == user_name,
            models.ComponentLayout.floor_name == floor_name
        ).all()

        # ✅ Build key sets for comparison
        existing_keys = {(comp.floor_name, comp.instance_id) for comp in existing_components}
        new_keys = {(comp.floor_name, comp.instance_id) for comp in components if comp.floor_name == floor_name}

        # ✅ DELETE missing components from relevant tables
        for comp in existing_components:
            if (comp.floor_name, comp.instance_id) not in new_keys:
                component_type = comp.component_name.lower()

                # Delete from ComponentLayout
                db.delete(comp)

                if component_type == "wiring":
                    item = db.query(models.WiringEquipmentData).filter(
                        models.WiringEquipmentData.email == user_name,
                        models.WiringEquipmentData.floor_name == comp.floor_name,
                        models.WiringEquipmentData.instance_id == comp.instance_id
                    ).first()
                    if item:
                        db.delete(item)

                elif component_type == "panel":
                    item = db.query(models.PanelRiskData).filter(
                        models.PanelRiskData.email == user_name,
                        models.PanelRiskData.floor_name == comp.floor_name,
                        models.PanelRiskData.instance_id == comp.instance_id
                    ).first()
                    if item:
                        db.delete(item)

                elif component_type == "ac":
                    item = db.query(models.ACData).filter(
                        models.ACData.email == user_name,
                        models.ACData.floor_name == comp.floor_name,
                        models.ACData.instance_id == comp.instance_id
                    ).first()
                    if item:
                        db.delete(item)

                elif component_type == "battery":
                    item = db.query(models.BatteryLiveData).filter(
                        models.BatteryLiveData.email == user_name,
                        models.BatteryLiveData.floor_name == comp.floor_name,
                        models.BatteryLiveData.instance_id == comp.instance_id
                    ).first()
                    if item:
                        db.delete(item)

                elif component_type == "ups":
                    item = db.query(models.UPSData).filter(
                        models.UPSData.email == user_name,
                        models.UPSData.floor_name == comp.floor_name,
                        models.UPSData.instance_id == comp.instance_id
                    ).first()
                    if item:
                        db.delete(item)

                elif component_type == "switchboard":
                    item = db.query(models.SwitchboardLiveData).filter(
                        models.SwitchboardLiveData.email == user_name,
                        models.SwitchboardLiveData.floor_name == comp.floor_name,
                        models.SwitchboardLiveData.instance_id == comp.instance_id
                    ).first()
                    if item:
                        db.delete(item)

        # ✅ INSERT or UPDATE per floor
        for comp in components:
            if comp.floor_name != floor_name:
                continue

            # ---- ComponentLayout ----
            existing_component = db.query(models.ComponentLayout).filter(
                models.ComponentLayout.user_name == user_name,
                models.ComponentLayout.floor_name == comp.floor_name,
                models.ComponentLayout.instance_id == comp.instance_id
            ).first()

            if existing_component:
                existing_component.position_x = comp.position_x
                existing_component.position_y = comp.position_y
                existing_component.component_name = comp.component_name
            else:
                new_component = models.ComponentLayout(
                    user_name=user_name,
                    floor_name=comp.floor_name,
                    component_name=comp.component_name,
                    instance_id=comp.instance_id,
                    position_x=comp.position_x,
                    position_y=comp.position_y
                )
                db.add(new_component)

            # ---- Conditional Equipment Sync ----
            component_type = comp.component_name.lower()

            if component_type == "wiring":
                existing = db.query(models.WiringEquipmentData).filter(
                    models.WiringEquipmentData.email == user_name,
                    models.WiringEquipmentData.floor_name == comp.floor_name,
                    models.WiringEquipmentData.instance_id == comp.instance_id
                ).first()
                if not existing:
                    db.add(models.WiringEquipmentData(
                        email=user_name, floor_name=comp.floor_name, instance_id=comp.instance_id
                    ))

            elif component_type == "panel":
                existing = db.query(models.PanelRiskData).filter(
                    models.PanelRiskData.email == user_name,
                    models.PanelRiskData.floor_name == comp.floor_name,
                    models.PanelRiskData.instance_id == comp.instance_id
                ).first()
                if not existing:
                    db.add(models.PanelRiskData(
                        email=user_name, floor_name=comp.floor_name, instance_id=comp.instance_id
                    ))

            elif component_type == "ac":
                existing = db.query(models.ACData).filter(
                    models.ACData.email == user_name,
                    models.ACData.floor_name == comp.floor_name,
                    models.ACData.instance_id == comp.instance_id
                ).first()
                if not existing:
                    db.add(models.ACData(
                        email=user_name, floor_name=comp.floor_name, instance_id=comp.instance_id
                    ))

            elif component_type == "battery":
                existing = db.query(models.BatteryLiveData).filter(
                    models.BatteryLiveData.email == user_name,
                    models.BatteryLiveData.floor_name == comp.floor_name,
                    models.BatteryLiveData.instance_id == comp.instance_id
                ).first()
                if not existing:
                    db.add(models.BatteryLiveData(
                        email=user_name, floor_name=comp.floor_name, instance_id=comp.instance_id
                    ))

            elif component_type == "ups":
                existing = db.query(models.UPSData).filter(
                    models.UPSData.email == user_name,
                    models.UPSData.floor_name == comp.floor_name,
                    models.UPSData.instance_id == comp.instance_id
                ).first()
                if not existing:
                    db.add(models.UPSData(
                        email=user_name, floor_name=comp.floor_name, instance_id=comp.instance_id
                    ))

            elif component_type == "switchboard":
                existing = db.query(models.SwitchboardLiveData).filter(
                    models.SwitchboardLiveData.email == user_name,
                    models.SwitchboardLiveData.floor_name == comp.floor_name,
                    models.SwitchboardLiveData.instance_id == comp.instance_id
                ).first()
                if not existing:
                    db.add(models.SwitchboardLiveData(
                        email=user_name, floor_name=comp.floor_name, instance_id=comp.instance_id
                    ))

    db.commit()
    return {"message": "Components and all related equipment data synced successfully (wiring/panel/ac/battery/ups/switchboard per floor)"}


# --------------------------------------------------------------------------------------------
class GetComponentsRequest(BaseModel):
    user_name: str

@app.post("/get_components")
async def get_components(request: GetComponentsRequest, db: Session = Depends(get_db)):
    user_name = request.user_name

    # ✅ Check if user exists
    user_exists = db.query(models.User).filter(models.User.email == user_name).first()
    if not user_exists:
        raise HTTPException(status_code=404, detail=f"User '{user_name}' not found")

    # ✅ Fetch all components for this user
    components = db.query(models.ComponentLayout).filter(models.ComponentLayout.user_name == user_name).all()

    if not components:
        raise HTTPException(status_code=404, detail="No components found for this user")

    return components



# # ✅ API to fetch from 4 tables: panel, ups, ac, battery
# @app.post("/user_panel_details", response_model=UserPanelUPSResponse)
# def get_user_panel_details(request: UserEmailRequest, db: Session = Depends(get_db)):
#     # --- Fetch from panel_risk_data ---
#     panel_records = (
#         db.query(
#             PanelRiskData.panel_name,
#             PanelRiskData.risk_score,
#             PanelRiskData.risk_level,
#             PanelRiskData.created_at
#         )
#         .filter(PanelRiskData.email == request.email)
#         .all()
#     )

#     # --- Fetch from ups_data ---
#     ups_records = (
#         db.query(
#             UPSData.ups_id,
#             UPSData.risk_score,
#             UPSData.risk_level,
#             UPSData.risk_created_at
#         )
#         .filter(UPSData.email == request.email)
#         .all()
#     )

#     # --- Fetch from ac_data ---
#     ac_records = (
#         db.query(
#             ACData.ac_name,
#             ACData.risk_score,
#             ACData.risk_level
#         )
#         .filter(ACData.email == request.email)
#         .all()
#     )

#     # --- Fetch from battery_live_data ---
#     battery_records = (
#         db.query(
#             BatteryLiveData.battery_id,
#             BatteryLiveData.risk_score,
#             BatteryLiveData.risk_level
#         )
#         .filter(BatteryLiveData.email == request.email)
#         .all()
#     )

#     # --- If no records found in all four tables ---
#     if not panel_records and not ups_records and not ac_records and not battery_records:
#         raise HTTPException(status_code=404, detail="No records found for this email")

#     return UserPanelUPSResponse(
#         panels=[
#             PanelDetails(
#                 panel_name=r.panel_name,
#                 risk_score=r.risk_score,
#                 risk_level=r.risk_level,
#                 created_at=str(r.created_at)
#             )
#             for r in panel_records
#         ],
#         ups_data=[
#             UPSDetails(
#                 ups_id=r.ups_id,
#                 risk_score=r.risk_score,
#                 risk_level=r.risk_level,
#                 risk_created_at=str(r.risk_created_at)
#             )
#             for r in ups_records
#         ],
#         ac_data=[
#             ACDetails(
#                 ac_name=r.ac_name,
#                 risk_score=r.risk_score,
#                 risk_level=r.risk_level
#             )
#             for r in ac_records
#         ],
#         battery_data=[
#             BatteryDetails(
#                 battery_id=r.battery_id,
#                 risk_score=r.risk_score,
#                 risk_level=r.risk_level
#             )
#             for r in battery_records
#         ]
#     )



# ✅ Request schema
class UserEmailRequest(BaseModel):
    email: EmailStr

# ✅ Panel response
class PanelDetails(BaseModel):
    instance_id: str
    # risk_score: float
    # risk_level: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    floor_name: str

# ✅ UPS response
class UPSDetails(BaseModel):
    instance_id: str
    # risk_score: float
    # risk_level: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    floor_name: str
    risk_created_at: str
   

class ACDetails(BaseModel):
    instance_id: str
    # risk_score: float
    # risk_level: str
    floor_name: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None

class BatteryDetails(BaseModel):
    instance_id: str
    # risk_score: float
    # risk_level: str  
    floor_name: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None

class SwitchboardDetails(BaseModel):
    instance_id: str
    # risk_score: float
    # risk_level: str
    floor_name: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None

class WiringEquipmentDetails(BaseModel):
    instance_id: str
    floor_name: str
    risk_score: float
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    # risk_level: str    

# ✅ Combined response
class UserPanelUPSResponse(BaseModel):
    panels: List[PanelDetails] = []
    ups_data: List[UPSDetails] = []
    ac_data: List[ACDetails] = []
    battery_data: List[BatteryDetails] = []
    switchboard_data: List[SwitchboardDetails]  
    wiring_equipment_data: List[WiringEquipmentDetails] = []  

#API to fetch from 5 tables: panel, ups, ac, battery, switchboard
@app.post("/user_panel_details", response_model=UserPanelUPSResponse)
def get_user_panel_details(request: UserEmailRequest, db: Session = Depends(get_db)):
    # --- Fetch from panel_risk_data ---
    panel_records = (
        db.query(
            PanelRiskData.instance_id,
            PanelRiskData.risk_score,
            PanelRiskData.risk_level,
            PanelRiskData.floor_name
        )
        .filter(PanelRiskData.email == request.email)
        .all()
    )

    # --- Fetch from ups_data ---
    ups_records = (
        db.query(
            UPSData.instance_id,
            UPSData.risk_score,
            UPSData.risk_level,
            UPSData.risk_created_at,
            UPSData.floor_name
        )
        .filter(UPSData.email == request.email)
        .all()
    )

    # --- Fetch from ac_data ---
    ac_records = (
        db.query(
            ACData.instance_id,
            ACData.risk_score,
            ACData.risk_level,
            ACData.floor_name
        )
        .filter(ACData.email == request.email)
        .all()
    )

    # --- Fetch from battery_live_data ---
    battery_records = (
        db.query(
            BatteryLiveData.instance_id,
            BatteryLiveData.risk_score,
            BatteryLiveData.risk_level,
            BatteryLiveData.floor_name
        )
        .filter(BatteryLiveData.email == request.email)
        .all()
    )

    # --- Fetch from switchboard_live_data ---
    switchboard_records = (
        db.query(
            SwitchboardLiveData.instance_id,
            SwitchboardLiveData.risk_score,
            SwitchboardLiveData.risk_level,
            SwitchboardLiveData.floor_name
        )
        .filter(SwitchboardLiveData.email == request.email)
        .all()
    )

    # --- Fetch from wiring_equipment_data ---
    wiring_equipment_records = (
        db.query(
            WiringEquipmentData.instance_id,
            WiringEquipmentData.floor_name, 
            WiringEquipmentData.risk_score,
            WiringEquipmentData.risk_level
        )
        .filter(WiringEquipmentData.email == request.email)
        .all()
    )

    # --- If no records found in any table ---
    if not panel_records and not ups_records and not ac_records and not battery_records and not switchboard_records and not wiring_equipment_records:
        raise HTTPException(status_code=404, detail="No records found for this email")

    return UserPanelUPSResponse(
        panels=[
            PanelDetails(
                instance_id=r.instance_id,
                risk_score=r.risk_score,
                risk_level=r.risk_level,
                floor_name=r.floor_name,
            )
            for r in panel_records
        ],
        ups_data=[
            UPSDetails(
                instance_id=r.instance_id,
                risk_score=r.risk_score,
                risk_level=r.risk_level,
                risk_created_at=str(r.risk_created_at),
                floor_name=r.floor_name,
            )
            for r in ups_records
        ],
        ac_data=[
            ACDetails(
                instance_id=r.instance_id,
                risk_score=r.risk_score,
                risk_level=r.risk_level,
                floor_name=r.floor_name,
            )
            for r in ac_records
        ],
        battery_data=[
            BatteryDetails(
                instance_id=r.instance_id,
                risk_score=r.risk_score,
                risk_level=r.risk_level,
                floor_name=r.floor_name,
            )
            for r in battery_records
        ],
        switchboard_data=[
            SwitchboardDetails(
                instance_id=r.instance_id,
                risk_score=r.risk_score,
                risk_level=r.risk_level,
                floor_name=r.floor_name,
            )
            for r in switchboard_records
        ],
        wiring_equipment_data=[
            WiringEquipmentDetails(
                instance_id=r.instance_id,
                floor_name=r.floor_name,
                risk_score=r.risk_score,
                risk_level=r.risk_level
            )
            for r in wiring_equipment_records
        ]
    )

class RiskCalculationRequest(BaseModel):
    instance_id: str

def sigmoid(x):
    return 1 / (1 + exp(-x))

@app.post("/calculate_wiring_risk")
def calculate_wiring_risk(request: RiskCalculationRequest):
    db: Session = next(get_db())
    instance_id = request.instance_id

    #Fetch latest sensor data for this panel
    sensor_data = db.query(WiringEquipmentData).filter(WiringEquipmentData.instance_id == instance_id).first()
    if not sensor_data:
        raise HTTPException(status_code=404, detail="No sensor data found for this panel")

    #Assign sensor values
    I = sensor_data.current
    Vdrop = sensor_data.voltage_drop
    Ileak = sensor_data.leakage_current
    ΔT = sensor_data.temperature_rise
    Ifault = sensor_data.fault_current
    I2t = sensor_data.i2t
    Psurge = sensor_data.surge_power
    EnvIdx = sensor_data.environment_index

    #Fixed reference / normalization values (configured in code)
    P_rated = 3000.0        # W
    Vdrop_max = 3.0         # V
    Ileak_ref = 0.005       # A
    T_margin = 40.0         # °C
    Ifault_ref = 0.03       # A
    I2t_ref = 5000.0        # A²·s
    Psurge_max = 200.0      # J
    EnvIdx_max = 1.0        # dimensionless
    R = 0.5                 # Ω

    #Weights (optional)
    w1 = w2 = w3 = w4 = w5 = w6 = w7 = w8 = w9 = 1.0

    #Calculate individual terms
    t1 = w1 * (I**2 * R / P_rated)
    t2 = w2 * (Vdrop / Vdrop_max)
    t3 = w3 * (Ileak / Ileak_ref)
    t4 = 0.0  # Removed Life_ref/Life_current to avoid dominating the score
    t5 = w5 * (ΔT / T_margin)
    t6 = w6 * (Ifault / Ifault_ref)
    t7 = w7 * (I2t / I2t_ref)
    t8 = w8 * (Psurge / Psurge_max)
    t9 = w9 * (EnvIdx / EnvIdx_max)

    #Raw score
    x = t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8 + t9

    #Sigmoid scaling to 0..1
    risk_score = sigmoid(x)

    #Determine risk level
    if risk_score < 0.4:
        risk_level = "Normal"
    elif risk_score < 0.7:
        risk_level = "Medium"
    else:
        risk_level = "High"

    #Update the record with risk values
    sensor_data.risk_score = risk_score
    sensor_data.risk_level = risk_level
    sensor_data.risk_created_at = datetime.utcnow()
    db.commit()

    #Return response
    return {
        "instance_id": instance_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


@app.post("/wiring_loop_calculation")
def calculate_wiring_risk_all():
    db: Session = next(get_db())

    # Fetch all sensor data rows
    all_sensor_data = db.query(WiringEquipmentData).all()
    if not all_sensor_data:
        raise HTTPException(status_code=404, detail="No sensor data found")

    results = []

    # Fixed reference / normalization values
    P_rated = 3000.0
    Vdrop_max = 3.0
    Ileak_ref = 0.005
    T_margin = 40.0
    Ifault_ref = 0.03
    I2t_ref = 5000.0
    Psurge_max = 200.0
    EnvIdx_max = 1.0
    R = 0.5

    # Weights
    w1 = w2 = w3 = w4 = w5 = w6 = w7 = w8 = w9 = 1.0

    # Function to calculate sigmoid
    def sigmoid(x):
        import math
        return 1 / (1 + math.exp(-x))

    for sensor_data in all_sensor_data:
        # Assign sensor values
        I = sensor_data.current
        Vdrop = sensor_data.voltage_drop
        Ileak = sensor_data.leakage_current
        ΔT = sensor_data.temperature_rise
        Ifault = sensor_data.fault_current
        I2t = sensor_data.i2t
        Psurge = sensor_data.surge_power
        EnvIdx = sensor_data.environment_index

        # Calculate terms
        t1 = w1 * (I**2 * R / P_rated)
        t2 = w2 * (Vdrop / Vdrop_max)
        t3 = w3 * (Ileak / Ileak_ref)
        t4 = 0.0
        t5 = w5 * (ΔT / T_margin)
        t6 = w6 * (Ifault / Ifault_ref)
        t7 = w7 * (I2t / I2t_ref)
        t8 = w8 * (Psurge / Psurge_max)
        t9 = w9 * (EnvIdx / EnvIdx_max)

        x = t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8 + t9
        risk_score = sigmoid(x)

        # Determine risk level
        if risk_score < 0.4:
            risk_level = "Normal"
        elif risk_score < 0.7:
            risk_level = "Medium"
        else:
            risk_level = "High"

        # Update record
        sensor_data.risk_score = risk_score
        sensor_data.risk_level = risk_level
        sensor_data.risk_created_at = datetime.utcnow()

        results.append({
            "instance_id": sensor_data.instance_id,
            "floor_name": sensor_data.floor_name, 
            "risk_score": risk_score,
            "risk_level": risk_level
        })

    # Commit all updates at once
    db.commit()

    return {"updated_panels": results, "total": len(results)} 


# Request schema
class FloorDataCreate(BaseModel):
    name: str
    email: EmailStr
    num_floors: int


# ✅ API to add or update floor data
@app.post("/add_floor_data")
def add_or_update_floor_data(request: FloorDataCreate, db: Session = Depends(get_db)):
    # Check if the email already exists
    existing = db.query(models.FloorData).filter(models.FloorData.email == request.email).first()

    if existing:
        # ✅ Update existing record
        existing.name = request.name
        existing.num_floors = request.num_floors
        db.commit()
        db.refresh(existing)
        return {"message": f"Updated: {request.num_floors} floors saved successfully for {request.email}"}
    else:
        # ✅ Create new record
        new_data = models.FloorData(
            name=request.name,
            email=request.email,
            num_floors=request.num_floors
        )
        db.add(new_data)
        db.commit()
        return {"message": f"New record created: {request.num_floors} floors saved successfully for {request.email}"}
    
class EmailRequest(BaseModel):
    email: EmailStr

# API to fetch number of floors by email
@app.post("/get_floors_by_email")
def get_floors_by_email(request: EmailRequest, db: Session = Depends(get_db)):
    record = db.query(models.FloorData).filter(models.FloorData.email == request.email).first()
    if not record:
        raise HTTPException(status_code=404, detail="Email not found")

    return {"num_floors": record.num_floors}