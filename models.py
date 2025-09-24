from sqlalchemy import Boolean, Column, Integer, String, Float, DateTime
from fire_prediction_backend.database import Base
from datetime import datetime
from sqlalchemy.sql import func


class PanelRiskData(Base):
    __tablename__ = "panel_risk_data"

    id = Column(Integer, primary_key=True, index=True)
    panel_name = Column(String(50), nullable=False)
    I_phaseA = Column(Float, nullable=False)
    rated_current = Column(Float, nullable=False)
    R_contact_norm = Column(Float, nullable=False)
    T_contact_norm = Column(Float, nullable=False)
    HF_I_env_norm = Column(Float, nullable=False)
    US_sig_norm = Column(Float, nullable=False)
    thermal_gradient_norm = Column(Float, nullable=False)
    IR_norm = Column(Float, nullable=False)
    I_leak_norm = Column(Float, nullable=False)
    transient_peak_norm = Column(Float, nullable=False)
    pulse_rate_norm = Column(Float, nullable=False)
    HF_energy_norm = Column(Float, nullable=False)
    T_bus_norm = Column(Float, nullable=False)
    PD_trend_norm = Column(Float, nullable=False)
    neutral_imbalance = Column(Float, nullable=False)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())



class SensorData(Base):
    __tablename__ = "sensor_data"

    id = Column(Integer, primary_key=True, index=True)
    temperature = Column(Float)
    humidity = Column(Float)
    smoke_level = Column(Float)
    voltage = Column(Float)
    air_velocity = Column(Float)
    pressure = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
 
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    email = Column(String(100), unique=True, nullable=False, index=True)
    contact_number = Column(String(15), unique=True, nullable=False)
    password = Column(String(255), nullable=False)  
    confirm_password = Column(String(255), nullable=False) 
    otp = Column(String(6), nullable=True)
    otp_expiry = Column(DateTime, nullable=True)
    otp_status = Column(Boolean, default=False)


