SELECT LabID, Record_Num
FROM (
    SELECT TOP 1
        LabID,
        CASE
            WHEN Record_Num IS NULL OR Record_Num = '' THEN '{no_record_found}'
            ELSE Record_Num
        END AS Record_Num
    FROM Records
    WHERE LabID = '{labid}'
    ORDER BY Record_Num DESC
) AS t

UNION ALL

SELECT
    '{labid}' AS LabID,
    '{no_record_found}' AS Record_Num
WHERE NOT EXISTS (
    SELECT 1 FROM Records WHERE LabID = '{labid}'
)