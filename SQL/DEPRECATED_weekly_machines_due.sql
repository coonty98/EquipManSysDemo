SELECT e.Serial_Num
FROM EquipmentMaster e
WHERE e.PM_Req_Weekly = 1
  AND NOT EXISTS (
      SELECT 1
      FROM Records r
      WHERE r.Serial_Num = e.Serial_Num
		AND r.Frequency = 'Weekly'
        AND r.Due_Date BETWEEN '{due_date_start}' AND '{due_date_end}'
  );