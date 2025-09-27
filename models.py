from flask_sqlalchemy import SQLAlchemy

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
    PM_Req_Daily = db.Column(db.Boolean)
    PM_Req_Weekly = db.Column(db.Boolean)
    PM_Req_Monthly = db.Column(db.Boolean)
    PM_Req_Quarterly = db.Column(db.Boolean)
    PM_Req_Annual = db.Column(db.Boolean)
    modelActive = db.Column(db.Boolean)

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

class PM_form(db.Model):
    __tablename__ = 'PM_form'
    ID = db.Column(db.Integer, primary_key=True)
    Model = db.Column(db.String, nullable=False)
    Frequency = db.Column(db.String, nullable=False)
    Form_Order = db.Column(db.Integer, nullable=False)
    Task = db.Column(db.String, nullable=False)