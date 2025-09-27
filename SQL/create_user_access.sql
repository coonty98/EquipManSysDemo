INSERT INTO UsersLabAccess (username, lab_access, access_level)
VALUES('{username}', '{labid}', (

SELECT l.access_level
FROM UsersLabAccess l
INNER JOIN Users u ON u.username=l.username
WHERE l.LabID = u.PrimaryLab AND l.username = '{username}'));