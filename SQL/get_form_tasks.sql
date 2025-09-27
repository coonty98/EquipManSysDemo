-- SELECT * FROM PM_form
-- WHERE Model = '{model}' AND Frequency = '{frequency}'
-- ORDER BY Form_Order ASC

SELECT *
FROM PM_form
WHERE Model = ?
	AND Frequency = (SELECT Frequency FROM Records WHERE Record_Num = ?)
ORDER BY Form_Order ASC;