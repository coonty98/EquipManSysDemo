-- SELECT Records.Record_Num, Records.Serial_Num, EquipByLab.Model, Records.Due_Date_Start, Records.Due_Date_End
-- FROM Records
-- INNER JOIN EquipByLab ON Records.Serial_Num=EquipByLab.Serial_Num
-- WHERE Records.Frequency = '{frequency}' AND Records.Record_Status != 'Complete' AND Records.LabID = '{labid}';

SELECT r.Record_Num, l.LabID, r.Serial_Num, l.Model, l.Equipment_Class, r.Due_Date_Start, r.Due_Date_End
FROM
	(SELECT l.Serial_Num, l.Model, l.LabID, m.Equipment_Class
	FROM EquipByLab l
	INNER JOIN EquipModels m ON m.Model=l.Model) l
INNER JOIN Records r ON r.Serial_Num=l.Serial_Num
WHERE r.Frequency = ? AND r.Record_Status != 'Complete' AND r.LabID = ?;