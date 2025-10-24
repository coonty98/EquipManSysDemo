from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

db = SQLAlchemy()

class BaseModel(db.Model):
    __abstract__ = True

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Settings(db.Model):
    __tablename__ = 'Settings'
    settingID = db.Column(db.Integer, primary_key=True)
    sesssionTimeout_sec = db.Column(db.Integer)
    pwd_chg_days = db.Column(db.Integer)
    secretkey = db.Column(db.String)
    oauth_clientid = db.Column(db.String)
    oauth_clientsecret = db.Column(db.String)

class EquipClass(db.Model):
    __tablename__ = 'EquipClass'
    Equipment_Class = db.Column(db.String, primary_key=True)

class EquipModels(BaseModel):
    __tablename__ = 'EquipModels'
    Model = db.Column(db.String, primary_key=True)
    Manufacturer = db.Column(db.String, nullable=False)
    Equipment_Class = db.Column(db.String, nullable=False)
    PM_Req_Daily = db.Column(db.Boolean, default=False)
    PM_Req_Weekly = db.Column(db.Boolean, default=False)
    PM_Req_Monthly = db.Column(db.Boolean, default=False)
    PM_Req_Quarterly = db.Column(db.Boolean, default=False)
    PM_Req_Annual = db.Column(db.Boolean, default=False)
    modelActive = db.Column(db.Boolean, default=True)

class EquipStatus(db.Model):
    __tablename__ = 'EquipStatus'
    equipStatus = db.Column(db.String, primary_key=True)

class UserStatus(db.Model):
    __tablename__ = 'UserStatus'
    userStatus = db.Column(db.String, primary_key=True)

class Access(db.Model):
    __tablename__ = 'Access'
    access_level = db.Column(db.String, primary_key=True)
    Hierarchy = db.Column(db.Integer)

class Labs(db.Model):
    __tablename__ = 'Labs'
    LabID = db.Column(db.String, primary_key=True)
    LabName = db.Column(db.String)

class PM_form(BaseModel):
    __tablename__ = 'PM_form'
    ID = db.Column(db.Integer, primary_key=True)
    Model = db.Column(db.String, nullable=False)
    Frequency = db.Column(db.String, nullable=False)
    Form_Order = db.Column(db.Integer, nullable=False)
    Task = db.Column(db.String, nullable=False)

class emsAudit(db.Model):
    __tablename__ = 'emsAudit'
    eventID = db.Column(db.Integer, primary_key=True)
    Scope = db.Column(db.String)
    EventType = db.Column(db.String)
    InitiatedBy = db.Column(db.String)
    InitiatedDate = db.Column(db.DateTime, default=func.now())
    EventDetails = db.Column(db.String)

class EquipByLab(BaseModel):
    __tablename__ = 'EquipByLab'
    Serial_Num = db.Column(db.String, primary_key=True)
    Model = db.Column(db.String, nullable=False)
    Created_Date = db.Column(db.Date, default=func.now())
    LabID = db.Column(db.String)
    equipStatus = db.Column(db.String)

class PM_Response(db.Model):
    __tablename__ = 'PM_Response'
    ResponseID = db.Column(db.Integer, primary_key=True)
    Record_Num = db.Column(db.String, nullable=False)
    ID = db.Column(db.Integer)
    Response = db.Column(db.Boolean)
    CreatedDate = db.Column(db.DateTime, default=func.now())

class Records(db.Model):
    __tablename__ = 'Records'
    Record_Num = db.Column(db.String, primary_key=True)
    Serial_Num = db.Column(db.String, nullable=False)
    Frequency = db.Column(db.String)
    Record_Status = db.Column(db.String, nullable=False)
    LabID = db.Column(db.String)
    CreatedDate = db.Column(db.DateTime, default=func.now())
    CompleteDate = db.Column(db.DateTime)
    CompletedBy = db.Column(db.String)
    Due_Date_Start = db.Column(db.Date)
    Due_Date_End = db.Column(db.Date)

class Frequency(db.Model):
    __tablename__ = 'Frequency'
    Frequency = db.Column(db.String, primary_key=True)

class Users(db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    CreatedDate = db.Column(db.DateTime, default=func.now())
    LastLoginDate = db.Column(db.DateTime, default=func.now())
    PrimaryLab = db.Column(db.String)
    FirstName = db.Column(db.String)
    LastName = db.Column(db.String)
    userStatus = db.Column(db.String)
    require_pwd_chg = db.Column(db.Boolean, default=False)
    last_pwd_chg = db.Column(db.Date, default=func.now())

class UsersLabAccess(db.Model):
    __tablename__ = 'UsersLabAccess'
    ID = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    lab_access = db.Column(db.String, nullable=False)
    GrantedDate = db.Column(db.DateTime, default=func.now())
    access_level = db.Column(db.String)
