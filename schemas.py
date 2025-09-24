from pydantic import BaseModel
from pydantic import EmailStr 
from datetime import datetime
from typing import Optional



class SensorDataCreate(BaseModel):
    temperature: float
    humidity: float
    smoke_level: float
    voltage: float
    air_velocity: float
    pressure: float
    timestamp: datetime


class SensorData(BaseModel):
    id: int
    temperature: float
    humidity: float
    smoke_level: float
    voltage: float
    air_velocity: float
    pressure: float
    timestamp: datetime
    class Config:
        orm_mode = True
        from_attributes: True


class UserCreate(BaseModel):
    name: str
    last_name: str
    email: EmailStr
    contact_number: str
    password: str
    confirm_password: str

class UserResponse(BaseModel):
    id: int
    name: str
    last_name: str
    email: EmailStr
    contact_number: str


class EmailRequest(BaseModel):
    email: EmailStr


class UserProfileResponse(BaseModel):
    name: str
    last_name: str
    contact_number: str
    email: EmailStr


class UpdateUserRequest(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    last_name: Optional[str] = None
    contact_number: Optional[str] = None


class PanelRiskDataCreate(BaseModel):
    panel_name: str
    I_phaseA: float
    rated_current: float
    R_contact_norm: float
    T_contact_norm: float
    HF_I_env_norm: float
    US_sig_norm: float
    thermal_gradient_norm: float
    IR_norm: float
    I_leak_norm: float
    transient_peak_norm: float
    pulse_rate_norm: float
    HF_energy_norm: float
    T_bus_norm: float
    PD_trend_norm: float
    neutral_imbalance: float

class RiskResponse(BaseModel):
    risk_score: float
    risk_level: str
    created_at: str  # or datetime if you prefer








    class Config:
        from_attributes = True  # replaces orm_mode=True in Pydantic v2  


        
              
