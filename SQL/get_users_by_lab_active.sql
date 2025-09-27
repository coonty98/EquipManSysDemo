-- Ensures only access levels manager and below are returned.

SELECT l.username, l.access_level, l.lab_access, u.FirstName, u.LastName, u.PrimaryLab, u.LastLoginDate, u.userStatus, u.require_pwd_chg
FROM UsersLabAccess l
INNER JOIN Users u ON u.username=l.username
INNER JOIN Access a ON a.access_level=l.access_level
WHERE l.lab_access = ?
	AND a.Hierarchy > 2
	AND u.userStatus != 'Disabled';