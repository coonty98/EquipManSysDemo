SELECT l.username, l.access_level, l.lab_access, u.FirstName, u.LastName, u.PrimaryLab, u.LastLoginDate, u.userStatus, u.require_pwd_chg
FROM UsersLabAccess l
INNER JOIN Users u ON u.username=l.username
WHERE l.lab_access = u.PrimaryLab AND u.userStatus != 'Disabled';