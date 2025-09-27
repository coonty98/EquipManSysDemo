SELECT TOP(1) CompleteDate FROM Records
WHERE Frequency = '{frequency}' AND Serial_Num = '{serial_num}'
ORDER BY CompleteDate DESC;