INSERT INTO Users (username, password_hash, PrimaryLab, FirstName, LastName, userStatus, require_pwd_chg, last_pwd_chg)
VALUES (?,?,?,?,?,?,?,?);

INSERT INTO UsersLabAccess (username, lab_access, access_level)
VALUES(?, ?, ?);