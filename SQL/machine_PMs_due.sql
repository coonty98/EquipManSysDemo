-- SELECT e.Serial_Num, e.LabID
-- FROM EquipmentMaster e
-- WHERE e.PM_Req_{frequency} = 1
--   AND NOT EXISTS (
--       SELECT 1
--       FROM Records r
--       WHERE r.Serial_Num = e.Serial_Num
--         AND r.Frequency = '{frequency}'
--         AND r.Due_Date BETWEEN '{due_date_start}' AND '{due_date_end}'
--   );

SELECT e.Serial_Num, e.LabID
FROM 
	(SELECT l.Serial_Num, l.Model, l.LabID, m.PM_Req_Daily, m.PM_Req_Weekly, m.PM_Req_Monthly, m.PM_Req_Quarterly, m.PM_Req_Annual
	FROM EquipByLab l
	INNER JOIN EquipModels m ON m.Model=l.Model
  WHERE l.equipStatus = 'In Service') e
WHERE e.PM_Req_{frequency} = 1
  AND NOT EXISTS (
      SELECT 1
      FROM Records r
      WHERE r.Serial_Num = e.Serial_Num
        AND r.Frequency = '{frequency}'
        AND r.Due_Date_Start = '{due_date_start}'
		AND r.Due_Date_End = '{due_date_end}'
  );