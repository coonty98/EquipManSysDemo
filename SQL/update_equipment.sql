UPDATE EquipByLab
SET 
    Serial_Num = ?, 
    LabID = ?, 
    Model = ?, 
    equipStatus = ?
WHERE Serial_Num = ?
;