SELECT r.Record_Num, l.LabID, r.Serial_Num, l.Model, l.Equipment_Class, r.Due_Date_Start, r.Due_Date_End
FROM
	(SELECT l.Serial_Num, l.Model, l.LabID, m.Equipment_Class
	FROM EquipByLab l
	INNER JOIN EquipModels m ON m.Model=l.Model) l
INNER JOIN Records r ON r.Serial_Num=l.Serial_Num
WHERE r.Frequency = ? AND r.Record_Status != 'Complete' AND l.Equipment_Class = ?;