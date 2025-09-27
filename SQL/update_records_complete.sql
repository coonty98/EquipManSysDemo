UPDATE Records
SET Record_Status = 'Complete', CompleteDate = GETDATE(), CompletedBy = ?
WHERE Record_Num = ?;