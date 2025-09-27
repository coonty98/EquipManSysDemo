UPDATE UsersLabAccess
SET access_level = ?
WHERE username = ? AND lab_access = ?
;

UPDATE Users
SET PrimaryLab = ?, 
    username = ?, 
    FirstName = ?, 
    LastName = ?, 
    userStatus = ?,
    require_pwd_chg = ?
WHERE username = ?
;