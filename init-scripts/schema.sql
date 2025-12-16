SET FOREIGN_KEY_CHECKS = 0;

CREATE DATABASE IF NOT EXISTS emsdemomain;

USE emsdemomain;

CREATE TABLE IF NOT EXISTS Access (
  access_level varchar(50) NOT NULL,
  hierarchy int DEFAULT NULL,
  PRIMARY KEY (access_level)
);

INSERT INTO Access VALUES ('Administrator',1),('Global Audit',2),('Local Audit',4),('Manager',3),('Technician',5);

CREATE TABLE IF NOT EXISTS EquipByLab (
  serial_num varchar(30) NOT NULL,
  model varchar(50) NOT NULL,
  created_date date DEFAULT NULL,
  labid varchar(5) DEFAULT NULL,
  equipstatus varchar(50) DEFAULT 'In Service',
  PRIMARY KEY (serial_num),
  KEY fk__equipbyla__labid__56e8e7ab (labid),
  KEY fk_equipbylab_equipmodels (model),
  KEY fk_equipbylab_equipstatus (equipstatus),
  CONSTRAINT fk__equipbyla__labid__56e8e7ab FOREIGN KEY (labid) REFERENCES Labs (labid),
  CONSTRAINT fk_equipbylab_equipmodels FOREIGN KEY (model) REFERENCES EquipModels (model) ON UPDATE CASCADE,
  CONSTRAINT fk_equipbylab_equipstatus FOREIGN KEY (equipstatus) REFERENCES EquipStatus (equipstatus) ON UPDATE CASCADE
);

INSERT INTO EquipByLab VALUES ('ABC-2145','Mod1','2025-08-14','LAB01','In Service'),('GTP-5623','Mod2','2025-08-14','LAB01','Out of Service'),('HGN-1879','Mod4','2025-08-14','LAB08','Repair offsite'),('NMR-8745','Mod3','2025-08-14','LAB06','Retired offsite'),('XDE-9834','Mod2','2025-08-14','LAB05','In Service');

CREATE TABLE IF NOT EXISTS EquipClass (
  equipment_class varchar(50) NOT NULL,
  PRIMARY KEY (equipment_class)
);

INSERT INTO EquipClass VALUES ('3D Printer'),('Desktop Scanner'),('Mill'),('Sinter Oven');

CREATE TABLE IF NOT EXISTS EquipModels (
  model varchar(50) NOT NULL,
  manufacturer varchar(50) NOT NULL,
  equipment_class varchar(50) NOT NULL,
  pm_req_daily tinyint(1) DEFAULT '0',
  pm_req_weekly tinyint(1) DEFAULT '0',
  pm_req_monthly tinyint(1) DEFAULT '0',
  pm_req_quarterly tinyint(1) DEFAULT '0',
  pm_req_annual tinyint(1) DEFAULT '0',
  modelactive tinyint(1) DEFAULT '1',
  PRIMARY KEY (model),
  KEY fk__equipmode__equip__6e01572d (equipment_class),
  CONSTRAINT fk__equipmode__equip__6e01572d FOREIGN KEY (equipment_class) REFERENCES EquipClass (equipment_class)
);

INSERT INTO EquipModels VALUES ('Mod1','Man1','Mill',1,1,1,1,1,1),('Mod2','Man1','Mill',1,1,0,0,0,1),('Mod3','Man2','Mill',0,0,1,0,0,1),('Mod4','Man3','3D Printer',0,0,0,0,0,1),('test','manufac1','Mill',0,0,0,0,0,0);

CREATE TABLE IF NOT EXISTS EquipStatus (
  equipstatus varchar(50) NOT NULL,
  PRIMARY KEY (equipstatus)
);

INSERT INTO EquipStatus VALUES ('In Service'),('Out of Service'),('Repair offsite'),('Repair onsite'),('Retired offsite'),('Retired onsite');

CREATE TABLE IF NOT EXISTS Frequency (
  frequency char(10) NOT NULL,
  PRIMARY KEY (frequency)
);

INSERT INTO Frequency VALUES ('Annual'),('Daily'),('Monthly'),('Quarterly'),('Weekly');

CREATE TABLE IF NOT EXISTS Labs (
  labid varchar(5) NOT NULL,
  labname varchar(255) NOT NULL,
  PRIMARY KEY (labid)
);

INSERT INTO Labs VALUES ('LAB01','Lab 1'),('LAB02','Lab 2'),('LAB03','Lab 3'),('LAB04','Lab 4'),('LAB05','Lab 5'),('LAB06','Lab 6'),('LAB07','Lab 7'),('LAB08','Lab 8'),('LAB09','Lab 9'),('LAB10','Lab 10');

CREATE TABLE IF NOT EXISTS PM_Response (
  responseid int NOT NULL AUTO_INCREMENT,
  record_num varchar(20) NOT NULL,
  id int DEFAULT NULL,
  response tinyint(1) DEFAULT '0',
  createddate datetime(3) DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (responseid)
);

CREATE TABLE IF NOT EXISTS PM_form (
  id int NOT NULL AUTO_INCREMENT,
  model varchar(50) NOT NULL,
  frequency char(10) NOT NULL,
  form_order int NOT NULL,
  task longtext NOT NULL,
  PRIMARY KEY (id)
);

INSERT INTO PM_form VALUES (1,'Mod1','Daily',1,'This is the first daily task'),(2,'Mod1','Daily',2,'This is the second daily task'),(3,'Mod1','Weekly',1,'This is the first weekly task'),(4,'Mod1','Weekly',2,'This is the second weekly task'),(5,'Mod1','Monthly',1,'This is the first monthly task'),(6,'Mod1','Monthly',2,'This is the second monthly task'),(7,'Mod1','Quarterly',1,'This is the first quarterly task'),(8,'Mod1','Quarterly',2,'This is the second quarterly task'),(9,'Mod1','Annual',1,'This is the first annual task'),(10,'Mod1','Annual',2,'This is the second annual task'),(11,'Mod2','Daily',1,'This is a daily task'),(12,'Mod2','Weekly',1,'This is a weekly task'),(13,'Mod3','Monthly',1,'This is a monthly task');

CREATE TABLE IF NOT EXISTS Records (
  record_num varchar(20) NOT NULL,
  serial_num varchar(30) NOT NULL,
  frequency char(10) DEFAULT NULL,
  record_status varchar(20) NOT NULL DEFAULT 'Created',
  labid varchar(5) NOT NULL,
  createddate datetime(3) DEFAULT CURRENT_TIMESTAMP(3),
  completedate datetime(3) DEFAULT NULL,
  completedby varchar(100) DEFAULT NULL,
  due_date_start date DEFAULT NULL,
  due_date_end date DEFAULT NULL,
  PRIMARY KEY (record_num),
  KEY fk__records__frequen__3c69fb99 (frequency),
  KEY fk_records_equipbylab (serial_num),
  KEY fk_records_labs (labid),
  CONSTRAINT fk__records__frequen__3c69fb99 FOREIGN KEY (frequency) REFERENCES Frequency (frequency),
  CONSTRAINT fk_records_equipbylab FOREIGN KEY (serial_num) REFERENCES EquipByLab (serial_num) ON UPDATE CASCADE,
  CONSTRAINT fk_records_labs FOREIGN KEY (labid) REFERENCES Labs (labid)
);

INSERT INTO Records VALUES ('LAB01000001','ABC-2145','Daily','Created','LAB01','2025-08-14 02:31:20.530',NULL,NULL,'2025-08-13','2025-08-13'),('LAB01000002','ABC-2145','Weekly','Created','LAB01','2025-08-14 02:37:39.913',NULL,NULL,'2025-08-11','2025-08-13'),('LAB01000003','ABC-2145','Monthly','Created','LAB01','2025-08-14 02:37:39.913',NULL,NULL,'2025-08-01','2025-08-10'),('LAB01000004','ABC-2145','Quarterly','Created','LAB01','2025-08-14 02:37:39.913',NULL,NULL,'2025-08-01','2025-08-15'),('LAB01000005','ABC-2145','Annual','Created','LAB01','2025-08-14 02:37:39.913',NULL,NULL,'2025-08-01','2025-08-20'),('LAB01000006','GTP-5623','Daily','Created','LAB01','2025-08-14 02:37:39.913',NULL,NULL,'2025-08-13','2025-08-13'),('LAB01000007','GTP-5623','Weekly','Created','LAB01','2025-08-14 02:37:39.913',NULL,NULL,'2025-08-11','2025-08-13'),('LAB05000001','XDE-9834','Daily','Created','LAB05','2025-08-14 02:37:39.913',NULL,NULL,'2025-08-13','2025-08-13'),('LAB05000002','XDE-9834','Weekly','Created','LAB05','2025-08-14 02:37:39.913',NULL,NULL,'2025-08-11','2025-08-13');

CREATE TABLE IF NOT EXISTS Settings (
  settingid int NOT NULL AUTO_INCREMENT,
  sesssiontimeout_sec int DEFAULT NULL,
  pwd_chg_days int DEFAULT NULL,
  secretkey varchar(255) DEFAULT NULL,
  oauth_clientid varchar(255) DEFAULT NULL,
  oauth_clientsecret varchar(255) DEFAULT NULL,
  PRIMARY KEY (settingid)
);

INSERT INTO Settings VALUES (1,900,30,NULL,NULL,NULL);

CREATE TABLE IF NOT EXISTS UserStatus (
  userstatus varchar(20) NOT NULL,
  PRIMARY KEY (userstatus)
);

INSERT INTO UserStatus VALUES ('Active'),('Disabled'),('Locked');

CREATE TABLE IF NOT EXISTS Users (
  id int NOT NULL AUTO_INCREMENT,
  username varchar(100) NOT NULL,
  password_hash varchar(255) NOT NULL,
  createddate datetime(3) DEFAULT NULL,
  lastlogindate datetime(3) DEFAULT NULL,
  primarylab varchar(5) DEFAULT NULL,
  firstname varchar(50) DEFAULT NULL,
  lastname varchar(50) DEFAULT NULL,
  userstatus varchar(20) DEFAULT 'Active',
  require_pwd_chg tinyint(1) NOT NULL DEFAULT '0',
  last_pwd_chg date DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq__users__f3dbc5725b276421 (username),
  KEY fk_users_labs (primarylab),
  KEY fk_users_userstatus (userstatus),
  CONSTRAINT fk_users_labs FOREIGN KEY (primarylab) REFERENCES Labs (labid),
  CONSTRAINT fk_users_userstatus FOREIGN KEY (userstatus) REFERENCES UserStatus (userstatus) ON UPDATE CASCADE
);

INSERT INTO Users VALUES (1,'emsadmin','scrypt:32768:8:1$wYwK2wS6YtYIZwC1$0d36b64a8cdc2d452e5c773f27d0bdce770e9012cccd3c637539cafa26cc649da34511e82aee02f29f2231d2d75a8ec751967a6a6b7a5015f7c431a77d57ceec','2025-10-24 02:33:45.000','2025-10-24 02:34:24.713','LAB01','Guest','Technician','Active',0,'2025-10-24');

CREATE TABLE IF NOT EXISTS UsersLabAccess (
  id int NOT NULL AUTO_INCREMENT,
  username varchar(100) NOT NULL,
  lab_access varchar(5) NOT NULL,
  granteddate datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  access_level varchar(50) DEFAULT 'technician',
  PRIMARY KEY (id),
  KEY fk__userslaba__usern__2de6d218 (username),
  KEY fk_userslabaccess_access (access_level),
  KEY fk_userslabaccess_labs (lab_access),
  CONSTRAINT fk__userslaba__usern__2de6d218 FOREIGN KEY (username) REFERENCES Users (username) ON UPDATE CASCADE,
  CONSTRAINT fk_userslabaccess_access FOREIGN KEY (access_level) REFERENCES Access (access_level),
  CONSTRAINT fk_userslabaccess_labs FOREIGN KEY (lab_access) REFERENCES Labs (labid)
);

INSERT INTO UsersLabAccess VALUES (1,'emsadmin','LAB01','2025-10-24 02:33:45.000','Administrator');

CREATE TABLE IF NOT EXISTS auditeventtypes (
  eventtype varchar(30) NOT NULL,
  PRIMARY KEY (eventtype)
);

INSERT INTO auditeventtypes VALUES ('equipmentCreate'),('equipmentModify'),('modelCreate'),('modelModify'),('userCreate'),('userLabAccess'),('userModify'),('userStatus');

CREATE TABLE IF NOT EXISTS emsAudit (
  eventid int NOT NULL AUTO_INCREMENT,
  scope varchar(30) DEFAULT NULL,
  eventtype varchar(30) DEFAULT NULL,
  initiatedby varchar(100) DEFAULT NULL,
  initiateddate datetime(3) DEFAULT CURRENT_TIMESTAMP(3),
  eventdetails longtext,
  PRIMARY KEY (eventid),
  KEY fk_emsaudit_auditeventtypes (eventtype),
  CONSTRAINT fk_emsaudit_auditeventtypes FOREIGN KEY (eventtype) REFERENCES auditeventtypes (eventtype) ON UPDATE CASCADE
);

SET FOREIGN_KEY_CHECKS = 1;