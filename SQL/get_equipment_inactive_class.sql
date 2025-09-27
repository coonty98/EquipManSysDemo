SELECT l.Serial_Num, l.Model, m.Manufacturer, m.Equipment_Class, l.LabID, l.Created_Date, m.PM_Req_Daily, m.PM_Req_Weekly, m.PM_Req_Monthly, m.PM_Req_Quarterly, m.PM_Req_Annual, l.equipStatus
FROM EquipByLab l
INNER JOIN EquipModels m ON m.Model=l.Model
WHERE Equipment_Class = ?
    AND l.equipStatus IN ('Retired offsite', 'Retired onsite');