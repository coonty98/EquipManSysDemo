import pyodbc, os, re
from flask import session, redirect, url_for, abort
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

environment = 'development'

if environment == 'production':
    driver = os.environ.get('PYODBC_DRIVER')
    sqlservername = os.environ.get('SQL_SERVER')
    database = os.environ.get('SQL_DATABASE')
    trusted_connection = os.environ.get('PYODBC_TRST_CON')
    encrypt = os.environ.get('PYODBC_ENCRYPT')
    username = os.environ.get('SQL_USERNAME')
    password = os.environ.get('SQL_PASSWORD')
else:
    # driver = 'ODBC Driver 18 for SQL Server'
    # sqlservername = 'TYCOONCOMPUTER'
    # database = 'EquipManSys'
    # trusted_connection = 'yes'
    # encrypt = 'no'
    driver = os.getenv('PYODBC_DRIVER')
    sqlservername = os.getenv('SQL_SERVER')
    database = os.getenv('SQL_DATABASE')
    trusted_connection = os.getenv('PYODBC_TRST_CON')
    encrypt = os.getenv('PYODBC_ENCRYPT')
    username = os.getenv('SQL_USERNAME')
    password = os.getenv('SQL_PASSWORD')


if trusted_connection.lower() == 'no':
    connection_string = (
        f"DRIVER={driver};"
        f"SERVER={sqlservername};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        f"ENCRYPT={encrypt}"
    )
else:
    connection_string = (
        f"DRIVER={driver};"
        f"SERVER={sqlservername};"
        f"DATABASE={database};"
        f"Trusted_Connection={trusted_connection};"
        f"ENCRYPT={encrypt}"
        )
def create_connection():
    connection = None
    try:
        connection = pyodbc.connect(connection_string)
    except pyodbc.Error as Ex:
        print("An error occurred in SQL Server:",Ex)
    return connection

def close_connection(connection):
    if connection is not None:
        connection.close()

def is_valid_password(password):
    # Minimum 8 characters, at least one uppercase, one lowercase, one digit, one special character
    if len(password) < 8:
        # return False, "Password must be at least 8 characters long."
        return False, "Password does not meet requirements. Try again."
    if not re.search(r"[A-Z]", password):
        # return False, "Password must contain at least one uppercase letter."
        return False, "Password does not meet requirements. Try again."
    if not re.search(r"[a-z]", password):
        # return False, "Password must contain at least one lowercase letter."
        return False, "Password does not meet requirements. Try again."
    if not re.search(r"\d", password):
        # return False, "Password must contain at least one digit."
        return False, "Password does not meet requirements. Try again."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        # return False, "Password must contain at least one special character."
        return False, "Password does not meet requirements. Try again."
    return True, ""

def read_query_execute(connection, file_name, params=None):
    with open('SQL/' + str(file_name), 'r') as f:
        query = f.read()
    cursor = connection.cursor()
    if params:
        cursor.execute(query, params)
        connection.commit()
    else:
        cursor.execute(query)
        connection.commit()

def read_query_get(connection, file_name, params=None):
    with open('SQL/' + str(file_name), 'r') as f:
        query = f.read()
    cursor = connection.cursor()
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        columns = [column[0] for column in cursor.description]
        results = cursor.fetchall()
        results_as_dicts = [dict(zip(columns, row)) for row in results]
        return results_as_dicts
    except pyodbc.Error as Ex:
        print("An error occurred in SQL Server:",Ex)

# def read_query_with_params(file_name, 
#                            frequency=None, 
#                            due_date_start=None, 
#                            due_date_end=None, 
#                            record_status=None, 
#                            labid=None, 
#                            no_record_found=None, 
#                            due_date=None, 
#                            serial_num=None, 
#                            record_num=None, 
#                            model=None, 
#                            form_order=None, 
#                            response=None, 
#                            username=None, 
#                            new_username=None, 
#                            new_accesslevel=None, 
#                            access_level=None, 
#                            new_labaccess=None, 
#                            new_primarylab=None, 
#                            equipment_class=None, 
#                            new_serialnum=None, 
#                            new_labid=None, 
#                            new_model=None, 
#                            new_status=None, 
#                            initiatedby=None,
#                            scope=None,
#                            eventtype=None,
#                            field=None,
#                            oldvalue=None,
#                            newvalue=None,
#                            tasknum=None,
#                            new_task=None,
#                            new_manufacturer=None,
#                            new_equipmentclass=None,
#                            change_task=None,
#                            new_userstatus=None,
#                            new_firstname=None,
#                            new_lastname=None,
#                            require_pwd_chg=None,
#                            last_pwd_chg=None,
#                            passwordhash=None
#                            ):
#     with open('SQL/' + str(file_name), 'r') as f:
#         query = f.read()
#         params = {
#             'frequency': frequency,
#             'due_date_start': due_date_start,
#             'due_date_end': due_date_end,
#             'record_status': record_status,
#             'labid': labid,
#             'no_record_found': no_record_found,
#             'due_date': due_date,
#             'serial_num': serial_num,
#             'record_num': record_num,
#             'model': model,
#             'form_order': form_order,
#             'response': response,
#             'username': username,
#             'new_username': new_username,
#             'new_accesslevel': new_accesslevel,
#             'access_level': access_level,
#             'new_labaccess': new_labaccess,
#             'new_primarylab': new_primarylab,
#             'equipment_class': equipment_class,
#             'new_serialnum': new_serialnum,
#             'new_labid': new_labid,
#             'new_model': new_model,
#             'new_status': new_status,
#             'initiatedby': initiatedby,
#             'scope': scope,
#             'eventtype': eventtype,
#             'field': field,
#             'oldvalue': oldvalue,
#             'newvalue': newvalue,
#             'tasknum': tasknum,
#             'new_task': new_task,
#             'new_manufacturer': new_manufacturer,
#             'new_equipmentclass': new_equipmentclass,
#             'change_task': change_task,
#             'new_userstatus': new_userstatus,
#             'new_firstname': new_firstname,
#             'new_lastname': new_lastname,
#             'require_pwd_chg': require_pwd_chg,
#             'last_pwd_chg': last_pwd_chg,
#             'passwordhash': passwordhash
#         }
#         for key, value in params.items():
#             if value is not None:
#                 query = query.replace('{' + key + '}', f"{value}")
#         return query

def execute_and_return(connection, query, params=None):
    try:
        cursor = connection.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        columns = [column[0] for column in cursor.description]
        results = cursor.fetchall()
        results_as_dicts = [dict(zip(columns, row)) for row in results]
        return results_as_dicts
    except pyodbc.Error as Ex:
        print("An error occurred in SQL Server:",Ex)

def get_user_labs():
    return session.get('labs', [])
    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# def require_access(labid, *levels):
#     def decorator(f):
#         @wraps(f)
#         def decorated_function(*args, **kwargs):
#             # Check if user has any of the required access levels for the lab
#             for access in session.get('lab_access', []):
#                 if access['LabID'] == labid and access['access_level'] in levels:
#                     return f(*args, **kwargs)
#             abort(403)
#         return decorated_function
#     return decorator

def require_access_levels(*levels):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user's access level is in allowed levels
            if session.get('access_level') in levels:
                return f(*args, **kwargs)
            abort(403)
        return decorated_function
    return decorator

# def audit(scope=None, eventtype=None, initiatedby=None, field=None, oldvalue=None, newvalue=None):
#     connection = create_connection()
#     cursor = connection.cursor()
#     if oldvalue is None and newvalue is None: 
#         event_details = f"New {field} {scope} created."
#     if newvalue and field and oldvalue is None:
#         event_details = f"New {field} created: {newvalue}."
#     if  oldvalue and field and newvalue is None:
#         event_details = f"{field} deleted: {oldvalue}."
#     if scope and eventtype and initiatedby and field and oldvalue and newvalue:
#         event_details = f"{field} changed from {oldvalue} to {newvalue}."
#     if eventtype == 'userLabAccess':
#         event_details = newvalue
#     cursor.execute("INSERT INTO emsAudit (Scope, EventType, InitiatedBy, EventDetails) VALUES (?,?,?,?);", (scope, eventtype, initiatedby, event_details))
#     cursor.commit()
#     close_connection

def audit(connection, method=None, auditdata=None):
    # AUDIT METHODS:
    # 1 - NEW EQUIPMENT CREATED
    # 2 - EQUIPMENT MODIFIED
    # 3 - NEW MODEL CREATED
    # 4 - MODEL MODIFIED
    # 5 - NEW USER CREATED
    # 6 - USER DETAILS MODIFIED
    # 7 - USER STATUS MODIFIED
    # 8 - USER LAB ACCESS GRANTED
    # 9 - USER LAB ACCESS REVOKED
    # 10 - TASK CREATED
    # 11 - TASK DELETED
    cursor = connection.cursor()
    if method == 1:
        eventdetails = f"New equipment created: {auditdata["newvalue"]}."
        eventtype = "equipmentCreate"
    if method == 2:
        eventdetails = f"{auditdata["field"]} changed from {auditdata["oldvalue"]} to {auditdata["newvalue"]}."
        eventtype = "equipmentModify"
    if method == 3:
        eventdetails = f"New model created: {auditdata["newvalue"]}."
        eventtype = "modelCreate"
    if method == 4:
        eventdetails = f"{auditdata["field"]} changed from {auditdata["oldvalue"]} to {auditdata["newvalue"]}."
        eventtype = "modelModify"
    if method == 5:
        eventdetails = f"New user created: {auditdata["newvalue"]}."
        eventtype = "userCreate"
    if method == 6:
        eventdetails = f"{auditdata["field"]} changed from {auditdata["oldvalue"]} to {auditdata["newvalue"]}."
        eventtype = "userModify"
    if method == 7:
        eventdetails = f"userStatus changed from {auditdata["oldvalue"]} to {auditdata["newvalue"]}."
        eventtype = "userStatus"
    if method == 8:
        eventdetails = f"{auditdata["access"]} granted for {auditdata["lab"]}."
        eventtype = "userLabAccess"
    if method == 9:
        eventdetails = f"{auditdata["access"]} revoked for {auditdata["lab"]}."
        eventtype = "userLabAccess"
    if method == 10:
        eventdetails = f"New {auditdata["frequency"]} task created: {auditdata["task"]}."
        eventtype = "modelModify"
    if method == 11:
        eventdetails = f"{auditdata["frequency"]} task deleted: {auditdata["task"]}."
        eventtype = "modelModify"
    cursor.execute("INSERT INTO emsAudit (Scope, EventType, InitiatedBy, EventDetails) VALUES (?,?,?,?);", (auditdata["scope"]), eventtype, auditdata["initiatedby"], eventdetails)
    connection.commit()

class DatabaseConnection:
    def __init__(self):
        self.connection = None
        
    def __enter__(self):
        self.connection = create_connection()
        return self.connection
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection:
            close_connection(self.connection)