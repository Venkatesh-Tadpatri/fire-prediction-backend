from sqlalchemy import Boolean, Column, Integer, String, Float, DateTime, UniqueConstraint
from database import Base
from datetime import datetime
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base


class PanelRiskData(Base):
    __tablename__ = "panel_risk_data"

    id = Column(Integer, primary_key=True, index=True)
    instance_id = Column(String(100), nullable=False)  
    floor_name = Column(String(100), nullable=False)

    I_phaseA = Column(Float, nullable=False,default=0, server_default="0")
    rated_current = Column(Float, nullable=False,default=0, server_default="0")
    R_contact_norm = Column(Float, nullable=False,default=0, server_default="0")
    T_contact_norm = Column(Float, nullable=False,default=0, server_default="0")
    HF_I_env_norm = Column(Float, nullable=False,default=0, server_default="0")
    US_sig_norm = Column(Float, nullable=False,default=0, server_default="0")
    thermal_gradient_norm = Column(Float, nullable=False,default=0, server_default="0")
    IR_norm = Column(Float, nullable=False,default=0, server_default="0")
    I_leak_norm = Column(Float, nullable=False,default=0, server_default="0")
    transient_peak_norm = Column(Float, nullable=False,default=0, server_default="0")
    pulse_rate_norm = Column(Float, nullable=False,default=0, server_default="0")
    HF_energy_norm = Column(Float, nullable=False,default=0, server_default="0")
    T_bus_norm = Column(Float, nullable=False,default=0, server_default="0")
    PD_trend_norm = Column(Float, nullable=False,default=0, server_default="0")
    neutral_imbalance = Column(Float, nullable=False,default=0, server_default="0")
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    email = Column(String(255), unique=False, nullable=True)  # new colum



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
    role = Column(String(50), nullable=False)
    assigned_admin = Column(String(50), nullable=False)
    email = Column(String(100), unique=True, nullable=False, index=True)
    contact_number = Column(String(15), unique=True, nullable=False)
    password = Column(String(255), nullable=False)  
    confirm_password = Column(String(255), nullable=False) 
    otp = Column(String(6), nullable=True)
    otp_expiry = Column(DateTime, nullable=True)
    otp_status = Column(Boolean, default=False)
    company_name = Column(String(50), nullable=False)
    approval_status = Column(String(20),nullable=False)
    token_number = Column(String(200),nullable=True)


Base = declarative_base()

class UPSData(Base):
    __tablename__ = "ups_data"

    id = Column(Integer, primary_key=True, index=True)
    instance_id = Column(String(100), nullable=False)  
    floor_name = Column(String(100), nullable=False)
            
    I = Column(Float, nullable=False,default=0, server_default="0")
    V = Column(Float, nullable=False,default=0, server_default="0")
    PF = Column(Float, nullable=False,default=0, server_default="0")
    TUPS = Column(Float, nullable=False,default=0, server_default="0")
    IL = Column(Float, nullable=False,default=0, server_default="0")
    THD = Column(Float, nullable=False,default=0, server_default="0")

    created_at = Column(DateTime, default=datetime.utcnow)

    # Add risk fields
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="Normal")  # Normal, Medium, High
    risk_created_at = Column(DateTime, default=datetime.utcnow)
    email = Column(String(255), unique=False, nullable=True)  # new colum



class ACData(Base):
    __tablename__ = "AC_data"

    id = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(String(100), nullable=False)  
    floor_name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    
    # Key parameters
    Irated = Column(Float, nullable=False,default=1, server_default="0")
    I_measured = Column(Float, nullable=False,default=1, server_default="0")
    THD = Column(Float, nullable=False,default=1, server_default="0")
    THDmax = Column(Float, default=10.0)
    Tc = Column(Float, nullable=False,default=1, server_default="0")
    Tsafe = Column(Float, default=75.0)
    ESR = Column(Float, nullable=False,default=1, server_default="0")
    ESRlimit = Column(Float, default=1.0)
    C_drop = Column(Float, nullable=False,default=1, server_default="0")  # Capacitance deviation (fraction)
    RHpcb = Column(Float, nullable=False,default=1, server_default="0")
    RHthreshold = Column(Float, default=80.0)
    Ires = Column(Float, nullable=False,default=1, server_default="0")
    Ilimit = Column(Float, default=30.0)
    IR = Column(Float, nullable=False,default=1, server_default="0")
    
    #Calculated risk fields
    risk_score = Column(Float, nullable=True)  # FARInorm
    risk_level = Column(String(50), nullable=True)
    risk_created_at = Column(DateTime, nullable=True)   
    created_at = Column(DateTime, nullable=True)
     

class BatteryLiveData(Base):
    __tablename__ = "battery_live_data"

    id = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(String(100), nullable=False)  
    floor_name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)

    # Live measured / predicted values
    I_meas = Column(Float, nullable=False,default=0, server_default="0")       # Current (A)
    V_meas = Column(Float, nullable=False,default=0, server_default="0")       # Voltage (V)
    T_meas = Column(Float, nullable=False,default=0, server_default="0")       # Temperature (°C)
    SOC_pred = Column(Float, nullable=False,default=0, server_default="0")     # State of Charge (%)
    Cycle_pred = Column(Float, nullable=False,default=0, server_default="0")   # Cycle count
    IR_pred = Column(Float, nullable=False,default=0, server_default="0")      # Internal resistance (Ω)

    # Risk results
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(50), nullable=True)
    risk_created_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=True)
    


class SwitchboardLiveData(Base):
    __tablename__ = "switchboard_live_data"

    id = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(String(100), nullable=False)
    floor_name = Column(String(100), nullable=False)

    # Real-time sensor data
    I_load = Column(Float, nullable=False,default=0, server_default="0")        # Load current (A)
    V_meas = Column(Float, nullable=False,default=0, server_default="0")        # Measured voltage (V)
    T_meas = Column(Float, nullable=False,default=0, server_default="0")        # Measured temperature (°C)
    I_leak = Column(Float, nullable=False,default=0, server_default="0")        # Leakage current (A)
    R_contact = Column(Float, nullable=False,default=0, server_default="0")     # Contact resistance (Ω)
    R_surface = Column(Float, nullable=False,default=0, server_default="0")     # Surface resistance (Ω)
    E_arc = Column(Float, nullable=False,default=0, server_default="0")         # Arc energy (J)
    deltaT_pred = Column(Float, nullable=False,default=0, server_default="0")   # Predicted temperature rise (°C)
   
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(50), nullable=True)
    risk_created_at = Column(DateTime, nullable=True) 
    email = Column(String(100), nullable=False) 
   
class WiringEquipmentData(Base):
    __tablename__ = "wiring_equipment_data"

    id = Column(Integer, primary_key=True, autoincrement=True)
    instance_id = Column(String(100), nullable=False)  # e.g., "Panel_1"
    floor_name = Column(String(100), nullable=False)

    # # Real-time sensor readings
    # current = Column(Float, nullable=False)             # I (A)
    # voltage_drop = Column(Float, nullable=False)        # Vdrop (V)
    # leakage_current = Column(Float, nullable=False)     # Ileak (A)
    # temperature_rise = Column(Float, nullable=False)    # ΔT (°C)
    # fault_current = Column(Float, nullable=False)       # Ifault (A)
    # i2t = Column(Float, nullable=False)                 # I²t (A²·s)
    # surge_power = Column(Float, nullable=False)         # Psurge (J)
    # environment_index = Column(Float, nullable=False)   # EnvIdx (0–1)
    # risk_score = Column(Float, nullable=True)
    # risk_level = Column(String(50), nullable=True)
    # risk_created_at = Column(DateTime, nullable=True)
    # email = Column(String(100), nullable=False)    

    current = Column(Float, nullable=False, default=0, server_default="0")
    voltage_drop = Column(Float, nullable=False, default=0, server_default="0")
    leakage_current = Column(Float, nullable=False, default=0, server_default="0")
    temperature_rise = Column(Float, nullable=False, default=0, server_default="0")
    fault_current = Column(Float, nullable=False, default=0, server_default="0")
    i2t = Column(Float, nullable=False, default=0, server_default="0")
    surge_power = Column(Float, nullable=False, default=0, server_default="0")
    environment_index = Column(Float, nullable=False, default=0, server_default="0")
    risk_score = Column(Float, nullable=True, default=0)
    risk_level = Column(String(50), nullable=True)
    risk_created_at = Column(DateTime, nullable=True)
    email = Column(String(100), nullable=False)


class ComponentLayout(Base):
    __tablename__ = "component_layouts"

    id = Column(Integer, primary_key=True, index=True)
    user_name= Column(String(100), nullable=False)
    floor_name = Column(String(100), nullable=False)
    component_name = Column(String(100), nullable=False)
    instance_id = Column(String(100), nullable=False)
    position_x = Column(Float, nullable=False,default=0)
    position_y = Column(Float, nullable=False,default=0)  
    # grid_number = Column(Integer, nullable=False)
    grid_number = Column(Integer, nullable=False, default=0)
    location = Column(String(100), nullable=True)
   
    _table_args__ = (
        UniqueConstraint('user_name', 'floor_name', 'instance_id', name='unique_component_instance'),
    )  


class FloorData(Base):
    __tablename__ = "Floor_data"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False, unique=True)
    num_floors = Column(Integer, nullable=False)   


class Component(Base):
    __tablename__ = "components"

    id = Column(Integer, primary_key=True, index=True)
    floor_name = Column(String(50))
    component_name = Column(String(50))
    instance_id = Column(String(50))
    position_x = Column(Float)
    position_y = Column(Float)
    grid_number = Column(Integer)
    user_name = Column(String(100))
    location = Column(String(50))