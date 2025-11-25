from pydantic import BaseModel, validator, field_validator, model_validator
from pydantic import EmailStr, Field
from datetime import datetime
from typing import Optional
from typing import List



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
    role: Optional[str] = None
    assigned_admin: Optional[str] = None
    company_name: str
    # token_number: str

    # # Optional: extra validation
    # @validator("contact_number")
    # def contact_must_be_10_digits(cls, v):
    #     if not v.isdigit() or len(v) != 10:
    #         raise ValueError("Contact number must be 10 digits")
    #     return v

    # # ✅ Password fields validation
    # @validator("password", "confirm_password")
    # def password_not_empty(cls, v, field):
    #     if not v or v.strip() == "":
    #         raise ValueError(f"{field.name.replace('_', ' ').capitalize()} cannot be empty")
    #     return v    

    # @validator("confirm_password")
    # def passwords_match(cls, v, values):
    #     if "password" in values and v != values["password"]:
    #         raise ValueError("Passwords do not match")
    #     return v
    
    # @validator("role")
    # def validate_role(cls, v):
    #     if not v or not v.strip():
    #         raise ValueError("role is required and cannot be empty")
    #     if v not in ("user", "admin"):
    #         raise ValueError("role must be either 'user' or 'admin'")
    #     return v.strip()

    # @validator("assigned_admin", always=True)
    # def validate_assigned_admin(cls, v, values):
    #     role = values.get("role")
    #     email = values.get("email")

    #     if role == "user":
    #         # Must have assigned_admin and not empty
    #         if not v or not v.strip():
    #             raise ValueError("assigned_admin is required when role is 'user'")
    #     elif role == "admin":
    #         # Auto-assign admin's own email
    #         return email

    #     return v.strip() if v else v



     # ✅ Contact number validation
    @field_validator("contact_number")
    @classmethod
    def contact_must_be_10_digits(cls, v):
        if not v.isdigit() or len(v) != 10:
            raise ValueError("Contact number must be 10 digits")
        return v

    # ✅ Password non-empty validation
    @field_validator("password", "confirm_password")
    @classmethod
    def password_not_empty(cls, v, info):
        if not v or v.strip() == "":
            raise ValueError(f"{info.field_name.replace('_', ' ').capitalize()} cannot be empty")
        return v

    # ✅ Cross-field password match validation
    @model_validator(mode="after")
    def passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self

    # ✅ Role validation
    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if not v or not v.strip():
            raise ValueError("Role is required and cannot be empty")
        if v not in ("user", "admin"):
            raise ValueError("Role must be either 'user' or 'admin'")
        return v.strip()

    # ✅ Assigned admin validation (depends on role and email)
    @model_validator(mode="after")
    def validate_assigned_admin(self):
        if self.role == "user":
            if not self.assigned_admin or not self.assigned_admin.strip():
                raise ValueError("assigned_admin is required when role is 'user'")
        elif self.role == "admin":
            # Auto-assign admin's own email
            self.assigned_admin = self.email
        return self



class MessageResponse(BaseModel):
    message: str    

class UserResponse(BaseModel):
    id: int
    name: str
    last_name: str
    email: EmailStr
    contact_number: str


class EmailRequest(BaseModel):
    email: EmailStr

class CompanyRequest(BaseModel):
    company_name: str

class ApprovalStatusUpdate(BaseModel):
    email: str
    approval_status: str    

class UserProfileResponse(BaseModel):
    name: str
    last_name: str
    contact_number: str
    email: EmailStr
    company_name: str


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


class UPSDataSchema(BaseModel):
    ups_id: str
    ups_name: str
    I: float
    V: float
    PF: float
    TUPS: float
    IL: float
    THD: float

class RiskResponse(BaseModel):
    risk_score: float
    risk_level: str
    created_at: datetime  

class ACRiskResponse(BaseModel):
    risk_score: float
    risk_level: str
    created_at: str   

# # ✅ Request model for a single component layout
# class ComponentLayoutBase(BaseModel):
#     user_name: str
#     floor_name: str
#     component_name: str
#     instance_id: str
#     position_x: float
#     position_y: float     


class ExcelComponentBase(BaseModel):
    floor_name: str
    component_name: str
    instance_id: str
    grid_number: int
    location: str   

class ComponentBase(BaseModel):
    floor_name: str
    component_name: str
    instance_id: str
    grid_number: int
    # location: str
    position_x: float
    position_y: float   
    location: Optional[str] = None  


class SaveTokenRequest(BaseModel):
    email: EmailStr
    token_number: str = Field(..., min_length=5, max_length=200)    

    
    

class ComponentCreateRequest(BaseModel):
    user_name: str
    components: List[ComponentBase]


# ✅ Extends your existing ComponentBase with user_name
class Component(ComponentBase):
    user_name: str

# ✅ Used by save_components and upload_excel
class ComponentCreateRequest(BaseModel):
    user_name: str
    components: List[ComponentBase]

# ✅ For uniform success messages
class MessageResponse(BaseModel):
    message: str    



    class Config:
        from_attributes = True  # replaces orm_mode=True in Pydantic v2  


        
              
