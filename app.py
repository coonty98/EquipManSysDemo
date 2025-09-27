import uuid, time, os, requests
from logic import (read_query_execute, read_query_get, login_required, require_access_levels, audit, is_valid_password, DatabaseConnection)
from flask import Flask, render_template, request, session, redirect, url_for, abort, jsonify
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, timedelta
from authlib.integrations.flask_client import OAuth
from models import db, Settings, EquipClass, EquipModels, EquipStatus, UserStatus, Access, Labs, PM_form
from sqlalchemy import func
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.env = 'development'
csrf = CSRFProtect(app)
# Load secret key before app context
# app_secret_key = os.environ.get('FLASK_SECRET_KEY')
# print(f"Secret key loaded: {app_secret_key is not None}")

# if not app_secret_key:
#     print("WARNING: No FLASK_SECRET_KEY found in environment variables!")
#     # For development only - NEVER use this in production
#     app_secret_key = 'dev-secret-for-testing-only'
# app_secret_key = 'dev-secret-for-testing-only'
# Set the secret key directly
# app.secret_key = app_secret_key

def init_app():
    app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-for-testing-only')

if app.env == 'production':
    init_app()

    db_username = os.environ.get('SQL_USERNAME')
    db_password = os.environ.get('SQL_PASSWORD')
    db_server = os.environ.get('SQL_SERVER')
    db_name = os.environ.get('SQL_DATABASE')
    oauth_client_id = os.environ.get('OAUTH_CLIENT_ID')
    oauth_client_secret = os.environ.get('OAUTH_CLIENT_SECRET')
    sessionTimeout_sec = int(os.environ.get('SN_TIME_SEC'))
    pwd_chg_days = int(os.environ.get('PWD_CHG_DAY'))

    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mssql+pyodbc://{db_username}:{db_password}@{db_server}/{db_name}?"
        f"driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes&Encrypt=yes"
    )
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )
else:
    # app.config['SQLALCHEMY_DATABASE_URI'] = (
    # "mssql+pyodbc://TYCOONCOMPUTER/EquipManSys?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
    # )
    db_username = os.getenv('SQL_USERNAME')
    db_password = os.getenv('SQL_PASSWORD')
    db_server = os.getenv('SQL_SERVER')
    db_name = os.getenv('SQL_DATABASE')
    oauth_client_id = os.getenv('OAUTH_CLIENT_ID')
    oauth_client_secret = os.getenv('OAUTH_CLIENT_SECRET')
    sessionTimeout_sec = int(os.getenv('SN_TIME_SEC'))
    pwd_chg_days = int(os.getenv('PWD_CHG_DAY'))

    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mssql+pyodbc://{db_username}:{db_password}@{db_server}/{db_name}?"
        f"driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes&Encrypt=yes"
    )

    

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

with app.app_context():
    settings = Settings.query.first()
    if settings:
        app.secret_key = settings.secretkey
        sessionTimeout_sec = settings.sesssionTimeout_sec
        pwd_chg_days = settings.pwd_chg_days
        oauth_client_id = settings.oauth_clientid
        oauth_client_secret = settings.oauth_clientsecret

CORS(app)

oauth = OAuth(app)
oauth.register(
    name='microsoft',
    client_id=oauth_client_id,
    client_secret=oauth_client_secret,
    server_metadata_url='https://login.microsoftonline.com/e7546d4f-84a5-4924-be50-b040e861e520/v2.0/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile User.Read'}
)

@app.before_request
def check_session_timeout():
    timeout_seconds = sessionTimeout_sec
    now = int(time.time())
    last_activity = session.get('last_activity', now)
    if 'logged_in' in session:
        if now - last_activity > timeout_seconds:
            session.clear()
            return redirect(url_for('login'))
        session['last_activity'] = now

# @app.before_request
# def https_redirect():
#     if not request.is_secure and app.env != 'development':
#         url = request.url.replace('http://', 'https://', 1)
#         return redirect(url)
    
@app.before_request
def redirect_to_https():
    if request.headers.get('X-Forwarded-Proto') == 'http':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/password_change', methods=['GET', 'POST'])
def password_change():
    token = request.args.get('token')
    data = session.get(token)
    if not data:
        abort(403)
    username = data['username']
    old_password = request.form.get('old-password')
    new_password = request.form.get('new-password')
    confirm_password = request.form.get('confirm-password')
    if request.method == 'POST':
        valid, message = is_valid_password(new_password)
        if not valid:
            return render_template('password_change.html', error=message)
        with DatabaseConnection() as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT password_hash, userStatus FROM Users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row and check_password_hash(row[0], old_password):
                if new_password == old_password:
                    return render_template('password_change.html', error="New Password cannot be the same as the Old Password!", token=token, username=username)
                if new_password == confirm_password:
                    password_hash = generate_password_hash(new_password)
                    cursor.execute("UPDATE Users SET password_hash = ?, require_pwd_chg = 0, last_pwd_chg = GETDATE() WHERE username = ?", (password_hash, username,))
                    connection.commit()
                    return redirect(url_for('login'))
                else:
                    return render_template('password_change.html', error="Passwords do not match!", token=token, username=username)
            else:
                return render_template('password_change.html', error="Old Password is incorrect!", token=token, username=username)
    return render_template('password_change.html', token=token, username=username)

@app.route('/password_change_link/<username>/')
def password_change_link(username):
    token = str(uuid.uuid4())
    session[token] = {'username': username}
    return redirect(url_for('password_change', token=token))

@app.route('/get_form_data', methods=['POST'])
@login_required
def get_form_data():
    data = request.get_json()
    record_num = data.get('record_num')
    model = data.get('model')
    # Generate a token and store in session if needed
    token = str(uuid.uuid4())
    session[token] = {
        'record_num': record_num,
        'model': model
    }
    username = session.get('username')
    with DatabaseConnection() as connection:
    # query = read_query_with_params(file_name='get_form_tasks.sql', model=model, record_num=record_num)
    # rows = execute_and_return(connection, query)
        rows = read_query_get(connection, 'get_form_tasks.sql', (model,record_num))
    return jsonify({
        "token": token,
        "rows": rows,
        "username": username
    })

@app.route('/modify_user_link', methods=['POST'])
def modify_user_link():
    data = request.get_json()
    username = data.get('username')
    access_level = data.get('access_level')
    lab_access = data.get('lab_access')
    FirstName = data.get('FirstName')
    LastName = data.get('LastName')
    PrimaryLab = data.get('PrimaryLab')
    userStatus = data.get('userStatus')
    require_pwd_chg = data.get('require_pwd_chg')
    token = str(uuid.uuid4())
    sessionLab = session.get('LabID')
    sessionaccesslevel = session.get('access_level')

    session[token] = {
        'username': username, 
        'access_level': access_level, 
        'lab_access': lab_access, 
        'FirstName': FirstName, 
        'LastName': LastName, 
        'PrimaryLab': PrimaryLab, 
        'userStatus': userStatus, 
        'require_pwd_chg': require_pwd_chg,
        'sessionLab': sessionLab,
        'sessionaccesslevel': sessionaccesslevel
    }
    return jsonify({
        'token': token
    })

@app.route('/get_token_data/<token>')
@login_required
def get_token_data(token):
    data = session.get(token, {})
    return jsonify(data)

@app.route('/modify_equipment_link', methods=['POST'])
def modify_equipment_link():
    data = request.get_json()
    Serial_Num = data.get('Serial_Num')
    LabID = data.get('LabID')
    Model = data.get('Model')
    equipStatus = data.get('equipStatus')
    token = str(uuid.uuid4())
    session[token] = {
        'Serial_Num': Serial_Num,
        'LabID': LabID,
        'Model': Model,
        'equipStatus': equipStatus
    }
    return jsonify({
        'token': token
    })

@app.route('/add_equipment_link', methods=['POST'])
def add_equipment_link():
    # data = request.get_json()
    token = str(uuid.uuid4())
    session[token] = {}
    return jsonify({
        'token': token
    })

@app.route('/new_user_link', methods=['POST'])
def new_user_link():
    # data = request.get_json()
    token = str(uuid.uuid4())
    session[token] = {}
    return jsonify({
        'token': token
    })

@app.route('/add_model_link', methods=['POST'])
def add_model_link():
    data = request.get_json()
    Model = data.get('Model')
    Manufacturer = data.get('Manufacturer')
    Equipment_Class = data.get('Equipment_Class')
    token = str(uuid.uuid4())
    session[token] = {
        'Model': Model,
        'Manufacturer': Manufacturer,
        'Equipment_Class': Equipment_Class
    }
    return jsonify({
        'token': token
    })

@app.route('/modify_models_link', methods=['POST'])
def modify_models_link():
    data = request.get_json()
    Model = data.get('Model')
    Manufacturer = data.get('Manufacturer')
    Equipment_Class = data.get('Equipment_Class')
    PM_Req_Daily = data.get('PM_Req_Daily')
    PM_Req_Weekly = data.get('PM_Req_Weekly')
    PM_Req_Monthly = data.get('PM_Req_Monthly')
    PM_Req_Quarterly = data.get('PM_Req_Quarterly')
    PM_Req_Annual = data.get('PM_Req_Annual')
    modelActive = data.get('modelActive')
    token = str(uuid.uuid4())
    session[token] = {
        'Model': Model,
        'Manufacturer': Manufacturer,
        'Equipment_Class': Equipment_Class,
        'PM_Req_Daily': PM_Req_Daily,
        'PM_Req_Weekly': PM_Req_Weekly,
        'PM_Req_Monthly': PM_Req_Monthly,
        'PM_Req_Quarterly': PM_Req_Quarterly,
        'PM_Req_Annual': PM_Req_Annual,
        'modelActive': modelActive
    }
    return jsonify({
        'redirect_url': url_for('modify_models', token=token)
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        with DatabaseConnection() as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT password_hash, PrimaryLab, userStatus, require_pwd_chg, last_pwd_chg FROM Users WHERE username = ?", (username,))
            row = cursor.fetchone()
            cursor.execute("SELECT lab_access, access_level FROM UsersLabAccess WHERE username = ?", (username,))
            lab_access = cursor.fetchall()
            session['labs'] = [r[0] for r in lab_access]
            session['lab_access'] = [{'lab_access': r[0], 'access_level': r[1]} for r in lab_access]
            failed_attempts = session.get('failed_attempts', 0)
            if row:
                userStatus = row[2]
                require_pwd_chg = row[3]
                last_pwd_chg = row[4]
                pwd_expired = None
                ### Set number of days for password expiration
                if (last_pwd_chg) < (date.today() - timedelta(days=pwd_chg_days)):
                    pwd_expired = True
                else:
                    pwd_expired = False
            else:
                return render_template('login.html', error='Invalid Username')
            if userStatus == 'Locked':
                return render_template('login.html', error='Account locked. Contact your Manager.')
            if userStatus == 'Disabled':
                return render_template('login.html', error='Account disabled. Please contact your Manager.')
            if row and check_password_hash(row[0], password):
                if require_pwd_chg == 1:
                    return redirect(url_for('password_change_link', username=username))
                if pwd_expired is True:
                    return redirect(url_for('password_change_link', username=username))
                session['logged_in'] = True
                session['ms_login'] = False
                session['username'] = username
                selected_access_level = None
                for lab, access in lab_access:
                    if lab == row[1]:
                        selected_access_level = access
                        break
                session['access_level'] = selected_access_level
                session['LabID'] = row[1]
                cursor.execute("UPDATE Users SET LastLoginDate = GETDATE() WHERE username = ?", (username,))
                connection.commit()
                if session.get('access_level') in ['Administrator', 'Global Audit']:
                    cursor.execute("SELECT LabID FROM Labs")
                    session['lablist'] = [row[0] for row in cursor.fetchall()]
                else:
                    session['lablist'] = [session.get('LabID')]
                cursor.execute("SELECT * FROM EquipClass")
                session['classlist'] = [row[0] for row in cursor.fetchall()]
                cursor.execute("SELECT Model FROM EquipModels")
                session['modellist'] = [row[0] for row in cursor.fetchall()]
                cursor.execute("SELECT equipStatus FROM EquipStatus")
                session['statuslist'] = [row[0] for row in cursor.fetchall()]
                cursor.execute("SELECT * FROM UserStatus")
                session['userstatuslist'] = [row[0] for row in cursor.fetchall()]
                cursor.execute("SELECT * FROM Access ORDER BY Hierarchy DESC")
                session['access_list'] = [row[0] for row in cursor.fetchall()]
                session['failed_attempts'] = 0
                return redirect(url_for('index'))
            else:
                failed_attempts += 1
                session['failed_attempts'] = failed_attempts
                if failed_attempts >= 3:
                    cursor.execute("UPDATE Users SET userStatus = 'Locked' WHERE username = ?", (username,))
                    connection.commit()
                    # audit(scope=username, eventtype='userStatus', initiatedby='SYSTEM', field='userStatus', oldvalue='Active', newvalue='Locked')
                    audit(connection, 7, auditdata = {"scope": username, "initiatedby": "SYSTEM", "oldvalue": 'Active', "newvalue": 'Locked'})
                    return render_template('login.html', error='Too many invalid login attempts. Account is now locked.')
                return render_template('login.html', error='Invalid Password')
    else:
        session['failed_attempts'] = 0
        return render_template('login.html')

@app.route('/login/microsoft')
def login_microsoft():
    if app.env == 'production':
        redirect_uri = url_for('auth_callback', _external=True, _scheme='https')
    else:
        redirect_uri = url_for('auth_callback', _external=True, _scheme='http')
    return oauth.microsoft.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    token = oauth.microsoft.authorize_access_token()
    user = token.get('userinfo') or token.get('id_token_claims') or token
    # user_groups = user.get('groups', [])

    access_token = token['access_token']
    group_ids = user.get('groups', [])

    # Query Microsoft Graph for group details
    headers = {'Authorization': f'Bearer {access_token}'}
    group_names = []
    for group_id in group_ids:
        resp = requests.get(
            f'https://graph.microsoft.com/v1.0/groups/{group_id}',
            headers=headers
        )
        if resp.ok:
            group_info = resp.json()
            group_names.append(group_info['displayName'])

    for group_name in group_names:
        match group_name:
            case 'EquipManSys.Admins':
                session['access_level'] = 'Administrator'
            case 'EquipManSys.GlobalAudit':
                session['access_level'] = 'Global Audit'
            case _ if 'EquipManSys.LabAccess' in group_name:
                access = group_name.split('.')[3]
                match access:
                    case 'Managers':
                        session['access_level'] = 'Manager'
                    case 'LocalAudit':
                        session['access_level'] = 'Local Audit'
                    case 'Technician':
                        session['access_level'] = 'Technician'
                session['LabID'] = group_name.split('.')[2]
                session['labs'] = session['LabID']
    email = user.get('preferred_username') or user.get('email')
    if email and '@' in email:
        username = email.split('@')[0]
    else:
        username = email
    session['ms_login'] = True
    session['user'] = user
    session['username'] = username
    session['logged_in'] = True
    session['classlist'] = [row.Equipment_Class for row in EquipClass.query.all()]
    session['modellist'] = [row.Model for row in EquipModels.query.all()]
    session['statuslist'] = [row.equipStatus for row in EquipStatus.query.all()]
    session['userstatuslist'] = [row.userStatus for row in UserStatus.query.all()]
    session['access_list'] = [row.access_level for row in Access.query.order_by(Access.Hierarchy.desc()).all()]
    if session.get('access_level') in ['Administrator', 'Global Audit']:
        session['lablist'] = [row.LabID for row in Labs.query.all()]
    else:
        session['lablist'] = [session.get('LabID')]
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', active_page='index', access_level=session.get('access_level'), lablist=session.get('lablist'), classlist=session.get('classlist'), sessionTimeout_sec=sessionTimeout_sec)
    # return render_template('index.html', active_page='index', access_level=session.get('access_level'), lablist=['MIWYO'], classlist=['Mill'], sessionTimeout_sec=sessionTimeout_sec)

@app.route('/change_lab', methods=['POST'])
@login_required
def change_lab():
    labid = request.form.get('labid')
    # Find the access level for the selected lab
    selected_access_level = None
    for access in session.get('lab_access', []):
        if access['lab_access'] == labid:
            selected_access_level = access['access_level']
            break
    session['LabID'] = labid
    session['access_level'] = selected_access_level
    return redirect(request.referrer or url_for('index'))

# Only use this route for dev as this will not redirect to microsoft logout endpoint
# @app.route('/logout')
# def logout():
#     session.clear()
#     return redirect(url_for('login'))

@app.route('/logout')
def logout():
    if session['ms_login'] == True:
        session.clear()
        if app.env == 'production':
            return redirect('https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=' + url_for('login', _external=True, _scheme='https'))
        else:
            return redirect('https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=' + url_for('login', _external=True, _scheme='http'))
    else:
        session.clear()
        return redirect(url_for('login'))


@app.route('/manage')
@login_required
@require_access_levels('Administrator', 'Manager', 'Local Audit', 'Global Audit')
def manage():
    inactivetoggle = session.get('inactivetoggle') or 'False'
    return render_template('manage.html', access_level=session.get('access_level'), lablist=session.get('lablist'), classlist=session.get('classlist'), modellist=session.get('modellist'), statuslist=session.get('statuslist'), inactivetoggle=inactivetoggle, active_page='manage', sessionTimeout_sec=sessionTimeout_sec)

@app.route('/models')
@login_required
@require_access_levels('Administrator', 'Manager', 'Local Audit', 'Global Audit')
def models():
    disabledmodeltoggle = session.get('disabledmodeltoggle') or 'False'
    return render_template('models.html', active_page='models', disabledmodeltoggle=disabledmodeltoggle, classlist=session.get('classlist'), sessionTimeout_sec=sessionTimeout_sec)

@app.route('/reports')
@login_required
@require_access_levels('Administrator', 'Manager', 'Local Audit', 'Global Audit')
def reports():
    return render_template('reports.html', active_page='reports', sessionTimeout_sec=sessionTimeout_sec)

@app.route('/users')
@login_required
@require_access_levels('Administrator', 'Manager', 'Local Audit', 'Global Audit')
def users():
    if session.get('access_level') in ['Administrator', 'Global Audit']:
        lablist = session.get('lablist')
        access_list = session.get('access_list')
    else:
        with DatabaseConnection() as connection:
            cursor = connection.cursor()
            # lablist = [session.get('LabID')]
            cursor.execute("""SELECT u.lab_access
                                FROM UsersLabAccess	u
                                INNER JOIN Access a ON a.access_level=u.access_level
                                WHERE u.username = ? AND a.Hierarchy > 2""", (session.get('username'),))
            lablist = [row[0] for row in cursor.fetchall()]
        access_list = ['Local Audit', 'Manager', 'Technician']
    inactiveusertoggle = session.get('inactiveusertoggle') or 'False'
    return render_template('users.html', active_page='users', lablist=lablist, access_list=access_list, userstatuslist=session.get('userstatuslist'), access_level=session.get('access_level'), inactiveusertoggle=inactiveusertoggle, sessionTimeout_sec=sessionTimeout_sec)

@app.route('/formsubmit', methods=['POST'])
@login_required
def formsubmit():
    token = request.args.get('token')
    data = session.get(token)
    if not data:
        abort(403)
    record_num = data['record_num']
    # model = data['model']
    if request.method == 'POST':
        completedby = request.form.get('completedby')
        checked = list(request.form.items())
        with DatabaseConnection() as connection:
            for key, value in checked:
                form_order = key
                if key in ['record_num', 'model', 'completedby', 'token', 'csrf_token']:
                    continue
                if value == 'on':
                    response = 1
                else:
                    response = 0
                read_query_execute(connection, 'create_form_response.sql', (record_num, form_order, response))
            read_query_execute(connection, 'update_records_complete.sql', (completedby, record_num))
        return redirect(url_for('index'))

@app.route('/modify_user', methods=['GET', 'POST'])
@login_required
@require_access_levels('Administrator', 'Manager')
def modify_user():
    token = request.args.get('token')
    data = session.get(token)
    if not data:
        abort(403)
    hidden_username = request.form.get('hidden_username')
    username = data['username']
    new_username = request.form.get('new_username')
    firstname = data['FirstName']
    new_firstname = request.form.get('new_firstname')
    lastname = data['LastName']
    new_lastname = request.form.get('new_lastname')
    new_password = request.form.get('new_password')
    new_accesslevel = request.form.get('new_accesslevel')
    new_labaccess = request.form.get('new_labaccess')
    new_primarylab = request.form.get('new_primarylab')
    new_userstatus = request.form.get('new_userstatus')
    req_pwd_chg = request.form.get('req-pwd-chg')
    if req_pwd_chg == 'on':
        req_pwd_chg = 1
    else:
        req_pwd_chg = 0
    access_level = data['access_level']
    lab_access = data['lab_access']
    PrimaryLab = data['PrimaryLab']
    userStatus = data['userStatus']
    if request.method == 'POST':
        with DatabaseConnection() as connection:
            cursor = connection.cursor()
            if new_password:
                password_hash = generate_password_hash(new_password)
                cursor.execute("UPDATE Users SET password_hash = ? WHERE username = ?", (password_hash,username,))
                connection.commit()
            if not new_username:
                cursor.execute("UPDATE Users SET userStatus = ?, require_pwd_chg = ? WHERE username = ?", (new_userstatus, req_pwd_chg, hidden_username,))
                connection.commit()
            else:
                params = (
                    new_accesslevel, username, PrimaryLab,
                    new_primarylab, new_username, new_firstname, new_lastname, new_userstatus, req_pwd_chg, username
                )
                read_query_execute(connection, 'update_user.sql', params)
            if new_username and new_username != username:
                # audit(scope=username, eventtype='userModify', initiatedby=session.get('username'), field='username', oldvalue=username, newvalue=new_username)
                audit(connection, 6, auditdata = {"scope": username, "initiatedby": session.get('username'), "oldvalue": username, "newvalue": new_username, "field": "username"})
            if new_accesslevel and new_accesslevel != access_level:
                # audit(scope=username, eventtype='userModify', initiatedby=session.get('username'), field='access_level', oldvalue=access_level, newvalue=new_accesslevel)
                audit(connection, 6, auditdata = {"scope": username, "initiatedby": session.get('username'), "oldvalue": access_level, "newvalue": new_accesslevel, "field": "access_level"})
            if new_primarylab and new_primarylab != PrimaryLab:
                # audit(scope=username, eventtype='userModify', initiatedby=session.get('username'), field='PrimaryLab', oldvalue=PrimaryLab, newvalue=new_primarylab)
                audit(connection, 6, auditdata = {"scope": username, "initiatedby": session.get('username'), "oldvalue": PrimaryLab, "newvalue": new_primarylab, "field": "PrimaryLab"})
            if new_userstatus and new_userstatus != userStatus:
                audit(connection, 7, auditdata = {"scope": username, "initiatedby": session.get('username'), "oldvalue": userStatus, "newvalue": new_userstatus})
                # audit(scope=username, eventtype='userStatus', initiatedby=session.get('username'), field='userStatus', oldvalue=userStatus, newvalue=new_userstatus)
            if new_firstname and new_firstname != firstname:
                # audit(scope=username, eventtype='userModify', initiatedby=session.get('username'), field='FirstName', oldvalue=firstname, newvalue=new_firstname)
                audit(connection, 6, auditdata = {"scope": username, "initiatedby": session.get('username'), "oldvalue": firstname, "newvalue": new_firstname, "field": "FirstName"})
            if new_lastname and new_lastname != lastname:
                # audit(scope=username, eventtype='userModify', initiatedby=session.get('username'), field='LastName', oldvalue=lastname, newvalue=new_lastname)
                audit(connection, 6, auditdata = {"scope": username, "initiatedby": session.get('username'), "oldvalue": lastname, "newvalue": new_lastname, "field": "LastName"})
        data['username'] = new_username
        data['FirstName'] = new_firstname
        data['LastName'] = new_lastname
        data['access_level'] = new_accesslevel
        data['PrimaryLab'] = new_primarylab
        data['userStatus'] = new_userstatus
        session[token] = data
        return redirect(url_for('users', token=token))
        # return render_template('form_result.html', checked=checked, username=username, current_username=current_username, new_username=new_username, new_access_level=new_access_level, back_url=url_for('users'), back_text='Back to Users', right_list_values=right_list_values)
        
    return render_template('users.html', userstatuslist=session.get('userstatuslist'), lablist=session.get('lablist'), access_list=session.get('access_list'), username=username, lab_access=lab_access, PrimaryLab=PrimaryLab, access_level=access_level, userStatus=userStatus, token=token)

@app.route('/get_user_lab_access', methods=['POST'])
@login_required
@require_access_levels('Administrator', 'Manager')
def get_user_lab_access():
    data = request.get_json()
    username = data.get('username')
    with DatabaseConnection() as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT lab_access, access_level FROM UsersLabAccess WHERE username = ?", (username,))
        rows = cursor.fetchall()
        if session.get('access_level') == 'Administrator':
            server_accesslevels = session.get('access_list')
        else:
            server_accesslevels = ['Local Audit', 'Manager', 'Technician']
    user_labs = [row[0] for row in rows]
    user_lab_access = {row[0]: row[1] for row in rows}
    return jsonify({
        "user_labs": user_labs,
        "user_lab_access": user_lab_access,
        "server_accesslevels": server_accesslevels
    })

@app.route('/modify_user_labs', methods=['POST'])
@login_required
@require_access_levels('Administrator', 'Manager')
def modify_user_labs():
    username = request.form.get('username')
    labs = request.form.getlist('labs[]')
    access_levels = request.form.getlist('access_levels[]')
    with DatabaseConnection() as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT lab_access, access_level FROM UsersLabAccess WHERE username = ?", (username,))
        rows_as_tuples = [tuple(row) for row in cursor.fetchall()]
        # Delete current access
        cursor.execute("DELETE FROM UsersLabAccess WHERE username = ?", (username,))
        connection.commit()
        newlabaccess = []
        # Grant new access
        for lab, access in zip(labs, access_levels):
            cursor.execute("INSERT INTO UsersLabAccess (username, lab_access, access_level) VALUES (?, ?, ?)", 
                        (username, lab, access))
            connection.commit()
            newlabaccess.extend([(lab,access)])
        # Create audit event only for new access granted
        for item in newlabaccess:
            if item not in rows_as_tuples:
                newlab = item[0]
                newaccess = item[1]
                # audit(scope=username, eventtype='userLabAccess', initiatedby=session.get('username'), 
                #     field='Lab Access', oldvalue='', newvalue=f"'{newaccess}' access granted for {newlab} lab.")
                audit(connection, 8, auditdata = {"scope": username, "initiatedby": session.get('username'), "access": newaccess, "lab": newlab})
        # Create audit event only for new access revoked
        for item in rows_as_tuples:
                if item not in newlabaccess:
                    oldlab = item[0]
                    oldaccess = item[1]
                    # audit(scope=username, eventtype='userLabAccess', initiatedby=session.get('username'), 
                    # field='Lab Access', oldvalue='', newvalue=f"'{oldaccess}' access revoked for {oldlab} lab.")
                    audit(connection, 9, auditdata = {"scope": username, "initiatedby": session.get('username'), "access": oldaccess, "lab": oldlab})
    return redirect(url_for('users'))

@app.route('/modify_equipment', methods = ['GET', 'POST'])
@login_required
@require_access_levels('Administrator', 'Manager')
def modify_equipment():
    token = request.args.get('token')
    data = session.get(token)
    if not data:
        abort(403)
    Serial_Num = data['Serial_Num']
    LabID = data['LabID']
    Model = data['Model']
    equipStatus = data['equipStatus']
    new_serialnum = request.form.get('new_serialnum')
    new_labid = request.form.get('new_labid')
    new_model = request.form.get('new_model')
    new_status = request.form.get('new_status')
    if request.method == 'POST':
        with DatabaseConnection() as connection:
            read_query_execute(connection, 'update_equipment.sql', (new_serialnum, new_labid, new_model, new_status, Serial_Num))
            if new_serialnum and new_serialnum != Serial_Num:
                # audit(scope=Serial_Num, eventtype='equipmentModify', initiatedby=session.get('username'), field='Serial_Num', oldvalue=Serial_Num, newvalue=new_serialnum)
                audit(connection, 2, auditdata = {"scope": Serial_Num, "initiatedby": session.get('username'), "oldvalue": Serial_Num, "newvalue": new_serialnum, "field": "Serial_Num"})
            if new_labid and new_labid != LabID:
                # audit(scope=Serial_Num, eventtype='equipmentModify', initiatedby=session.get('username'), field='LabID', oldvalue=LabID, newvalue=new_labid)
                audit(connection, 2, auditdata = {"scope": Serial_Num, "initiatedby": session.get('username'), "oldvalue": LabID, "newvalue": new_labid, "field": "LabID"})
            if new_model and new_model != Model:
                # audit(scope=Serial_Num, eventtype='equipmentModify', initiatedby=session.get('username'), field='Model', oldvalue=Model, newvalue=new_model)
                audit(connection, 2, auditdata = {"scope": Serial_Num, "initiatedby": session.get('username'), "oldvalue": Model, "newvalue": new_model, "field": "Model"})
            if new_status and new_status != equipStatus:
                # audit(scope=Serial_Num, eventtype='equipmentModify', initiatedby=session.get('username'), field='equipStatus', oldvalue=equipStatus, newvalue=new_status)
                audit(connection, 2, auditdata = {"scope": Serial_Num, "initiatedby": session.get('username'), "oldvalue": equipStatus, "newvalue": new_status, "field": "equipStatus"})
        data['Serial_Num'] = new_serialnum
        data['LabID'] = new_labid
        data['Model'] = new_model
        data['equipStatus'] = new_status
        session[token] = data
        return redirect(url_for('manage'))
    return render_template('manage.html', token=token)

@app.route('/add_equipment', methods = ['GET', 'POST'])
@login_required
@require_access_levels('Administrator', 'Manager')
def add_equipment():
    token = request.args.get('token')
    data = session.get(token)
    # if not data:
    #     abort(403)
    new_serialnum = request.form.get('new_serialnum')
    new_labid = request.form.get('new_labid')
    new_model = request.form.get('new_model')
    new_status = request.form.get('new_status')
    if request.method == 'POST':
        with DatabaseConnection() as connection:
            read_query_execute(connection, 'create_equipment.sql', (new_serialnum, new_model, new_labid, new_status))
            # audit(scope=new_serialnum, eventtype='equipmentCreate', initiatedby=session.get('username'), field='equipment')
            audit(connection, 1, auditdata = {"scope": new_serialnum, "initiatedby": session.get('username'), "newvalue": new_serialnum})
            # data['Serial_Num'] = new_serialnum
            # data['LabID'] = new_labid
            # data['Model'] = new_model
            # data['equipStatus'] = new_status
        session[token] = data
        return redirect(url_for('manage'))
    return render_template('manage.html', active_page='manage', token=token)

@app.route('/new_user', methods = ['GET', 'POST'])
@login_required
@require_access_levels('Administrator', 'Manager')
def new_user():
    token = request.args.get('token')
    # data = session.get(token)
    # if not data:
    #     abort(403)
    new_username = request.form.get('new_username')
    new_firstname = request.form.get('new_firstname')
    new_lastname = request.form.get('new_lastname')
    new_password = request.form.get('new_password')
    new_accesslevel = request.form.get('new_accesslevel')
    new_primarylab = request.form.get('new_primarylab')
    if request.method == 'POST':
        with DatabaseConnection() as connection:
            password_hash = generate_password_hash(new_password)
            params = (
                new_username, password_hash, new_primarylab, new_firstname, new_lastname,
                'Active', 1, date.today(), new_username, new_primarylab, new_accesslevel
            )
            read_query_execute(connection, 'create_user.sql', params)
            # audit(scope=new_username, eventtype='userCreate', initiatedby=session.get('username'), field='user')
            audit(connection, 5, auditdata = {"scope": new_username, "initiatedby": session.get('username'), "newvalue": new_username})
            # data['username'] = new_username
            # data['access_level'] = new_accesslevel
            # data['Model'] = new_model
            # data['equipStatus'] = new_status
            # session[token] = data
        return redirect(url_for('users'))
    return render_template('users.html', active_page='users', token=token)

@app.route('/add_model', methods = ['GET', 'POST'])
@login_required
@require_access_levels('Administrator')
def add_model():
    token = request.args.get('token')
    data = session.get(token)
    if not data:
        abort(403)
    new_model = request.form.get('new_model')
    new_manufacturer = request.form.get('new_manufacturer')
    new_equipmentclass = request.form.get('new_equipmentclass')
    if request.method == 'POST':
        with DatabaseConnection() as connection:
            read_query_execute(connection, 'create_model.sql', (new_model, new_manufacturer, new_equipmentclass))
            # audit(scope=new_model, eventtype='modelCreate', initiatedby=session.get('username'), field='model')
            audit(connection, 3, auditdata = {"scope": new_model, "initiatedby": session.get('username'), "newvalue": new_model})
        data['Model'] = new_model
        data['Manufacturer'] = new_manufacturer
        data['Equipment_Class'] = new_equipmentclass
        session[token] = data
        return redirect(url_for('models'))
    return render_template('models.html', active_page='models', token=token)

@app.route('/get_PMs_due', methods = ['GET', 'POST'])
@login_required
def get_PMs_due():
    if not request.json:
        return {'results': 'Error. Please send valid post request.'}
    data = request.get_json()
    frequency = data.get('frequency')
    labid = data.get('labid')
    equipment_class = data.get('class')
    with DatabaseConnection() as connection:
        if session.get('access_level') not in ['Administrator', 'Global Audit']:
            labid = session.get('LabID')
        has_lab_filter = labid and (labid != 'All Labs' or session.get('access_level') not in ['Administrator', 'Global Audit'])
        has_class_filter = equipment_class and equipment_class != 'All Classes'
        params = []
        match (bool(has_lab_filter), bool(has_class_filter)):
            case (True, True):
                query_file = 'get_PMs_due_by_lab_and_class.sql'
                params.extend([frequency, labid, equipment_class])
            case (True, False):
                query_file = 'get_PMs_due_by_lab.sql'
                params.extend([frequency, labid])
            case (False, True):
                query_file = 'get_PMs_due_by_class.sql'
                params.extend([frequency, equipment_class])
            case (False, False):
                query_file = 'get_PMs_due.sql'
                params.append(frequency)
        # if has_lab_filter and has_class_filter:
        #     query_file = 'get_PMs_due_by_lab_and_class.sql'
        #     params.extend([frequency, labid, equipment_class])
        # elif has_lab_filter:
        #     query_file = 'get_PMs_due_by_lab.sql'
        #     params.extend([frequency, labid])
        # elif has_class_filter:
        #     query_file = 'get_PMs_due_by_class.sql'
        #     params.extend([frequency, equipment_class])
        # else:
        #     query_file = 'get_PMs_due.sql'
        #     params.append(frequency)
        results = read_query_get(connection, query_file, params)
    return {'results': results}

@app.route('/get_users', methods = ['POST'])
@login_required
@require_access_levels('Administrator', 'Manager', 'Local Audit', 'Global Audit')
def get_users():
    if not request.json:
        return {'results': 'Error. Please send valid post request.'}
    data = request.get_json()
    labid = data.get('labid')
    session['inactiveusertoggle'] = data.get('inactiveusertoggle')
    with DatabaseConnection() as connection:
        if session.get('access_level') not in ['Administrator', 'Global Audit']:
            labid = session.get('LabID')
        query_params = {}
        has_lab_filter = labid and (labid != 'All Labs' or session.get('access_level') not in ['Administrator', 'Global Audit'])
        params = []
        match (bool(has_lab_filter), session['inactiveusertoggle']):
            case (True, 'False'):
                query_file = 'get_users_by_lab_active.sql'
                params.append(labid)
            case (True, 'True'):
                query_file = 'get_users_by_lab_inactive.sql'
                params.append(labid)
            case (False, 'False'):
                query_file = 'get_users_active.sql'
            case (False, 'True'):
                query_file = 'get_users_inactive.sql'
        # if has_lab_filter:
        #     if session['inactiveusertoggle'] == 'False':
        #         query_file = 'get_users_by_lab_active.sql'
        #         params.append(labid)
        #     else:
        #         query_file = 'get_users_by_lab_inactive.sql'
        #         params.append(labid)
        # else:
        #     if session['inactiveusertoggle'] == 'False':
        #         query_file = 'get_users_active.sql'
        #     else:
        #         query_file = 'get_users_inactive.sql'
        if params:
            results = read_query_get(connection, query_file, params)
        else:
            results = read_query_get(connection, query_file)
    return {'results': results}

@app.route('/get_equipment', methods = ['POST'])
@login_required
@require_access_levels('Administrator', 'Manager', 'Local Audit', 'Global Audit')
def get_equipment():
    if  not request.json:
        return {'results': 'Error. Please send valid post request.'}
    data = request.get_json()
    session['inactivetoggle'] = data.get('inactivetoggle')
    equipment_class = data.get('class')
    labid = data.get('labid')
    with DatabaseConnection() as connection:
        params = []
        if session.get('access_level') not in ['Administrator', 'Global Audit']:
            labid = session.get('LabID')
        has_lab_filter = labid and labid != 'All Labs'
        has_class_filter = equipment_class and equipment_class != 'All Classes'
        is_admin_ga = session['access_level'] in ['Administrator', 'Global Audit']
        is_manager_la = session['access_level'] in ['Manager', 'Local Audit']
        match (bool(is_admin_ga), bool(is_manager_la), bool(has_lab_filter), bool(has_class_filter), session['inactivetoggle']):
            case (True, False, True, True, 'False'):
                query_file = 'get_equipment_active_labclass.sql'
                params.extend([equipment_class, labid])
            case (True, False, True, False, 'False'):
                query_file = 'get_equipment_active_lab.sql'
                params.append(labid)
            case (True, False, False, True, 'False'):
                query_file = 'get_equipment_active_class.sql'
                params.extend([equipment_class])
            case (True, False, False, False, 'False'):
                query_file = 'get_equipment_active.sql'
            case (True, False, True, True, 'True'):
                query_file = 'get_equipment_inactive_labclass.sql'
                params.extend([labid, equipment_class])
            case (True, False, True, False, 'True'):
                query_file = 'get_equipment_inactive_lab.sql'
                params.append(labid)
            case (True, False, False, True, 'True'):
                query_file = 'get_equipment_inactive_class.sql'
                params.append(equipment_class)
            case (True, False, False, False, 'True'):
                query_file = 'get_equipment_inactive.sql'
            case (False, True, True, True, 'False'):
                query_file = 'get_equipment_by_lab_active_class.sql'
                params.extend([labid, equipment_class])
            case (False, True, True, False, 'False'):
                query_file = 'get_equipment_by_lab_active.sql'
                params.append(labid)
            case (False, True, True, True, 'True'):
                query_file = 'get_equipment_by_lab_inactive_class.sql'
                params.extend([labid, equipment_class])
            case (False, True, True, False, 'True'):
                query_file = 'get_equipment_by_lab_inactive.sql'
                params.append(labid)
        # if session['access_level'] in ['Administrator', 'Global Audit']:
            # if session['inactivetoggle'] == 'False':
            #     if has_lab_filter and has_class_filter:
            #         query_file = 'get_equipment_active_labclass.sql'
            #         params.extend([equipment_class, labid])
            #     elif has_lab_filter:
            #         query_file = 'get_equipment_active_lab.sql'
            #         params.append(labid)
            #     elif has_class_filter:
            #         query_file = 'get_equipment_active_class.sql'
            #         params.extend([equipment_class])
            #     else:
            #         query_file = 'get_equipment_active.sql'
            # else:
            #     if has_lab_filter and has_class_filter:
            #         query_file = 'get_equipment_inactive_labclass.sql'
            #         params.extend([labid, equipment_class])
            #     elif has_lab_filter:
            #         query_file = 'get_equipment_inactive_lab.sql'
            #         params.append(labid)
            #     elif has_class_filter:
            #         query_file = 'get_equipment_inactive_class.sql'
            #         params.append(equipment_class)
            #     else:
            #         query_file = 'get_equipment_inactive.sql'
        # elif session['access_level'] in ['Manager', 'Local Audit']:
        #     if session['inactivetoggle'] == 'False':
        #         if has_class_filter:
        #             query_file = 'get_equipment_by_lab_active_class.sql'
        #             params.extend([labid, equipment_class])
        #         else:
        #             query_file = 'get_equipment_by_lab_active.sql'
        #             params.append(labid)
        #     else:
        #         query_file = 'get_equipment_by_lab_inactive.sql'
        #         params.append(labid)
        #         if has_class_filter:
        #             query_file = 'get_equipment_by_lab_inactive_class.sql'
        #             params.extend([labid, equipment_class])
        #         else:
        #             query_file = 'get_equipment_by_lab_inactive.sql'
        #             params.append(labid)
        if params:
            results = read_query_get(connection, query_file, params)
        else:
            results = read_query_get(connection, query_file)
    return {'results': results}

@app.route('/get_models', methods = ['GET', 'POST'])
@login_required
@require_access_levels('Administrator', 'Manager', 'Local Audit', 'Global Audit')
def get_models():
    if not request.json:
        return {'results': 'Error. Please send valid post request.'}
    data = request.get_json()
    session['disabledmodeltoggle'] = data.get('disabledmodeltoggle')
    if session['disabledmodeltoggle'] == 'False':
        results = [model.to_dict() for model in EquipModels.query.filter_by(modelActive=True).all()]
    else:
        results = [model.to_dict() for model in EquipModels.query.filter_by(modelActive=False).all()]
    # with DatabaseConnection() as connection:
    #     if session['disabledmodeltoggle'] == 'False':
    #         query = 'SELECT * FROM EquipModels WHERE modelActive = 1;'
    #     else:
    #         query = 'SELECT * FROM EquipModels WHERE modelActive = 0'
    #     results = execute_and_return(connection, query)
    return {'results': results}

@app.route('/modify_models', methods = ['GET', 'POST'])
@login_required
@require_access_levels('Administrator', 'Manager', 'Local Audit', 'Global Audit')
def modify_models():
    token = request.args.get('token')
    data = session.get(token)
    if not data:
        abort(403)
    Model = data['Model']
    new_model = request.form.get('new_model')
    Manufacturer = data['Manufacturer']
    modelActive = data['modelActive']
    if request.form.get('new_modelActive') == 'on':
        new_modelActive = 'true'
    else:
        new_modelActive = 'false'
    new_manufacturer = request.form.get('new_manufacturer')
    Equipment_Class = data['Equipment_Class']
    new_equipmentclass = request.form.get('new_equipmentclass')
    maxformorder_daily = (
        db.session.query(func.max(PM_form.Form_Order))
        .filter(PM_form.Model == Model, PM_form.Frequency == 'Daily')
        .scalar()
    ) or 0
    maxformorder_weekly = (
        db.session.query(func.max(PM_form.Form_Order))
        .filter(PM_form.Model == Model, PM_form.Frequency == 'Weekly')
        .scalar()
    ) or 0
    maxformorder_monthly = (
        db.session.query(func.max(PM_form.Form_Order))
        .filter(PM_form.Model == Model, PM_form.Frequency == 'Monthly')
        .scalar()
    ) or 0
    maxformorder_quarterly = (
        db.session.query(func.max(PM_form.Form_Order))
        .filter(PM_form.Model == Model, PM_form.Frequency == 'Quarterly')
        .scalar()
    ) or 0
    maxformorder_annual = (
        db.session.query(func.max(PM_form.Form_Order))
        .filter(PM_form.Model == Model, PM_form.Frequency == 'Annual')
        .scalar()
    ) or 0
    with DatabaseConnection() as connection:
        cursor = connection.cursor()
        # cursor.execute("SELECT MAX(Form_Order) FROM PM_form WHERE Model = ? AND Frequency = 'Daily'", (Model,))
        # maxformorder_daily = cursor.fetchone()[0] or 0
        # cursor.execute("SELECT MAX(Form_Order) FROM PM_form WHERE Model = ? AND Frequency = 'Weekly'", (Model,))
        # maxformorder_weekly = cursor.fetchone()[0] or 0
        # cursor.execute("SELECT MAX(Form_Order) FROM PM_form WHERE Model = ? AND Frequency = 'Monthly'", (Model,))
        # maxformorder_monthly = cursor.fetchone()[0] or 0
        # cursor.execute("SELECT MAX(Form_Order) FROM PM_form WHERE Model = ? AND Frequency = 'Quarterly'", (Model,))
        # maxformorder_quarterly = cursor.fetchone()[0] or 0
        # cursor.execute("SELECT MAX(Form_Order) FROM PM_form WHERE Model = ? AND Frequency = 'Annual'", (Model,))
        # maxformorder_annual = cursor.fetchone()[0] or 0
        PM_Req_Daily = data['PM_Req_Daily']
        if request.form.get('pmreq-daily') == 'on':
            new_pmreqdaily = 'true'
        else:
            new_pmreqdaily = 'false'
        PM_Req_Weekly = data['PM_Req_Weekly']
        if request.form.get('pmreq-weekly') == 'on':
            new_pmreqweekly = 'true'
        else:
            new_pmreqweekly = 'false'
        PM_Req_Monthly = data['PM_Req_Monthly']
        if request.form.get('pmreq-monthly') == 'on':
            new_pmreqmonthly = 'true'
        else:
            new_pmreqmonthly = 'false'
        PM_Req_Quarterly = data['PM_Req_Quarterly']
        if request.form.get('pmreq-quarterly') == 'on':
            new_pmreqquarterly = 'true'
        else:
            new_pmreqquarterly = 'false'
        PM_Req_Annual = data['PM_Req_Annual']
        if request.form.get('pmreq-annual') == 'on':
            new_pmreqannual = 'true'
        else:
            new_pmreqannual = 'false'
        dailytasks = [
            tuple(getattr(row, col.name) for col in PM_form.__table__.columns)
            for row in PM_form.query.filter_by(Model=Model, Frequency='Daily').all()
        ]
        weeklytasks = [
            tuple(getattr(row, col.name) for col in PM_form.__table__.columns)
            for row in PM_form.query.filter_by(Model=Model, Frequency='Weekly').all()
        ]
        monthlytasks = [
            tuple(getattr(row, col.name) for col in PM_form.__table__.columns)
            for row in PM_form.query.filter_by(Model=Model, Frequency='Monthly').all()
        ]
        quarterlytasks = [
            tuple(getattr(row, col.name) for col in PM_form.__table__.columns)
            for row in PM_form.query.filter_by(Model=Model, Frequency='Quarterly').all()
        ]
        annualtasks = [
            tuple(getattr(row, col.name) for col in PM_form.__table__.columns)
            for row in PM_form.query.filter_by(Model=Model, Frequency='Annual').all()
        ]
        # cursor.execute("SELECT * FROM PM_form WHERE Model = ? AND Frequency = 'Daily'", (Model,))
        # dailytasks = cursor.fetchall()
        # print(dailytasks)
        # cursor.execute("SELECT * FROM PM_form WHERE Model = ? AND Frequency = 'Weekly'", (Model,))
        # weeklytasks = cursor.fetchall()
        # cursor.execute("SELECT * FROM PM_form WHERE Model = ? AND Frequency = 'Monthly'", (Model,))
        # monthlytasks = cursor.fetchall()
        # cursor.execute("SELECT * FROM PM_form WHERE Model = ? AND Frequency = 'Quarterly'", (Model,))
        # quarterlytasks = cursor.fetchall()
        # cursor.execute("SELECT * FROM PM_form WHERE Model = ? AND Frequency = 'Annual'", (Model,))
        # annualtasks = cursor.fetchall()
        if request.method == 'POST':
            print(new_pmreqdaily)
            print(str(PM_Req_Daily).lower())
            print(request.form.get('pmreq-daily'))
            if new_pmreqdaily and new_pmreqdaily != str(PM_Req_Daily).lower():
                cursor.execute("UPDATE EquipModels SET PM_Req_Daily = ? WHERE Model = ?",(new_pmreqdaily,Model,))
                connection.commit()
                # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='PM_Req_Daily', oldvalue=PM_Req_Daily, newvalue=new_pmreqdaily)
                audit(connection, 4, auditdata = {"scope": Model, "initiatedby": session.get('username'), "oldvalue": PM_Req_Daily, "newvalue": new_pmreqdaily, "field": "PM_Req_Daily"})
            if new_pmreqweekly and new_pmreqweekly != str(PM_Req_Weekly).lower():
                cursor.execute("UPDATE EquipModels SET PM_Req_Weekly = ? WHERE Model = ?",(new_pmreqweekly,Model,))
                connection.commit()
                # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='PM_Req_Weekly', oldvalue=PM_Req_Weekly, newvalue=new_pmreqweekly)
                audit(connection, 4, auditdata = {"scope": Model, "initiatedby": session.get('username'), "oldvalue": PM_Req_Weekly, "newvalue": new_pmreqweekly, "field": "PM_Req_Weekly"})
            if new_pmreqmonthly and new_pmreqmonthly != str(PM_Req_Monthly).lower():
                cursor.execute("UPDATE EquipModels SET PM_Req_Monthly = ? WHERE Model = ?",(new_pmreqmonthly,Model,))
                connection.commit()
                # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='PM_Req_Monthly', oldvalue=PM_Req_Monthly, newvalue=new_pmreqmonthly)
                audit(connection, 4, auditdata = {"scope": Model, "initiatedby": session.get('username'), "oldvalue": PM_Req_Monthly, "newvalue": new_pmreqmonthly, "field": "PM_Req_Monthly"})
            if new_pmreqquarterly and new_pmreqquarterly != str(PM_Req_Quarterly).lower():
                cursor.execute("UPDATE EquipModels SET PM_Req_Quarterly = ? WHERE Model = ?",(new_pmreqquarterly,Model,))
                connection.commit()
                # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='PM_Req_Quarterly', oldvalue=PM_Req_Quarterly, newvalue=new_pmreqquarterly)
                audit(connection, 4, auditdata = {"scope": Model, "initiatedby": session.get('username'), "oldvalue": PM_Req_Quarterly, "newvalue": new_pmreqquarterly, "field": "PM_Req_Quarterly"})
            if new_pmreqannual and new_pmreqannual != str(PM_Req_Annual).lower():
                cursor.execute("UPDATE EquipModels SET PM_Req_Annual = ? WHERE Model = ?",(new_pmreqannual,Model,))
                connection.commit()
                # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='PM_Req_Annual', oldvalue=PM_Req_Annual, newvalue=new_pmreqannual)
                audit(connection, 4, auditdata = {"scope": Model, "initiatedby": session.get('username'), "oldvalue": PM_Req_Annual, "newvalue": new_pmreqannual, "field": "PM_Req_Annual"})
            ###Update daily tasks if changed.###
            for i, dailytask in enumerate(dailytasks, start=1):
                change_task = request.form.get(f"pmreq-daily-task-input-{i}")
                Frequency = 'Daily'
                if change_task and change_task != dailytask[4]:
                    read_query_execute(connection, 'update_models.sql', (change_task, Model, i, Frequency))
                if not change_task and change_task != dailytask[4]:
                    cursor.execute("DELETE FROM PM_form WHERE Model = ? AND Frequency = 'Daily' AND Form_Order = ?",(Model,i,))
                    connection.commit()
                    # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Task', oldvalue=dailytask[4])
                    audit(connection, 11, auditdata = {"scope": Model, "initiatedby": session.get('username'), "frequency": Frequency, "task": dailytask[4]})
            ###Add new daily tasks that were submitted.###
            for key in request.form.keys():
                if key.startswith('pmreq-daily-task-new-'):
                    new_task = request.form.get(key)
                    tasknum = key.split('-')[4]
                    ###Ensure empty tasks are not added to database.###
                    if new_task:
                        read_query_execute(connection, 'create_pmform_task.sql', (Model, 'Daily', tasknum, new_task))
                        # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Task', oldvalue=new_task)
                        audit(connection, 10, auditdata = {"scope": Model, "initiatedby": session.get('username'), "frequency": "Daily", "task": new_task})
            ###Update weekly tasks if changed.###
            for i, weeklytask in enumerate(weeklytasks, start=1):
                change_task = request.form.get(f'pmreq-weekly-task-input-{i}')
                Frequency = 'Weekly'
                if change_task and change_task != weeklytask[4]:
                    read_query_execute(connection, 'update_models.sql', (change_task, Model, i, Frequency))
                if not change_task and change_task != weeklytask[4]:
                    cursor.execute("DELETE FROM PM_form WHERE Model = ? AND Frequency = 'Weekly' AND Form_Order = ?",(Model,i,))
                    connection.commit()
                    # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Task', oldvalue=weeklytask[4])
                    audit(connection, 11, auditdata = {"scope": Model, "initiatedby": session.get('username'), "frequency": Frequency, "task": weeklytask[4]})
            ###Add new weekly tasks that were submitted.###
            for key in request.form.keys():
                if key.startswith('pmreq-weekly-task-new-'):
                    new_task = request.form.get(key)
                    tasknum = key.split('-')[4]
                    ###Ensure empty tasks are not added to database.###
                    if new_task:
                        read_query_execute(connection, 'create_pmform_task.sql', (Model, 'Weekly', tasknum, new_task))
                        # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Task', oldvalue=new_task)
                        audit(connection, 10, auditdata = {"scope": Model, "initiatedby": session.get('username'), "frequency": "Weekly", "task": new_task})
            ###Update monthly tasks if changed.###
            for i, monthlytask in enumerate(monthlytasks, start=1):
                change_task = request.form.get(f'pmreq-monthly-task-input-{i}')
                Frequency = 'Monthly'
                if change_task and change_task != monthlytask[4]:
                    read_query_execute(connection, 'update_models.sql', (change_task, Model, i, Frequency))
                if not change_task and change_task != monthlytask[4]:
                    cursor.execute("DELETE FROM PM_form WHERE Model = ? AND Frequency = 'Monthly' AND Form_Order = ?",(Model,i,))
                    connection.commit()
                    # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Task', oldvalue=monthlytask[4])
                    audit(connection, 11, auditdata = {"scope": Model, "initiatedby": session.get('username'), "frequency": Frequency, "task": monthlytask[4]})
            ###Add new monthly tasks that were submitted.###
            for key in request.form.keys():
                if key.startswith('pmreq-monthly-task-new-'):
                    new_task = request.form.get(key)
                    tasknum = key.split('-')[4]
                    ###Ensure empty tasks are not added to database.###
                    if new_task:
                        read_query_execute(connection, 'create_pmform_task.sql', (Model, 'Monthly', tasknum, new_task))
                        # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Task', oldvalue=new_task)
                        audit(connection, 10, auditdata = {"scope": Model, "initiatedby": session.get('username'), "frequency": "Monthly", "task": new_task})
            ###Update quarterly tasks if changed.###
            for i, quarterlytask in enumerate(quarterlytasks, start=1):
                change_task = request.form.get(f'pmreq-quarterly-task-input-{i}')
                Frequency = 'Quarterly'
                if change_task and change_task != quarterlytask[4]:
                    read_query_execute(connection, 'update_models.sql', (change_task, Model, i, Frequency))
                if not change_task and change_task != quarterlytask[4]:
                    cursor.execute("DELETE FROM PM_form WHERE Model = ? AND Frequency = 'Quarterly' AND Form_Order = ?",(Model,i,))
                    connection.commit()
                    # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Task', oldvalue=quarterlytask[4])
                    audit(connection, 11, auditdata = {"scope": Model, "initiatedby": session.get('username'), "frequency": Frequency, "task": quarterlytask[4]})
            ###Add new quarterly tasks that were submitted.###
            for key in request.form.keys():
                if key.startswith('pmreq-quarterly-task-new-'):
                    new_task = request.form.get(key)
                    tasknum = key.split('-')[4]
                    ###Ensure empty tasks are not added to database.###
                    if new_task:
                        read_query_execute(connection, 'create_pmform_task.sql', (Model, 'Quarterly', tasknum, new_task))
                        # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Task', oldvalue=new_task)
                        audit(connection, 10, auditdata = {"scope": Model, "initiatedby": session.get('username'), "frequency": "Quarterly", "task": new_task})
            ###Update annual tasks if changed.###
            for i, annualtask in enumerate(annualtasks, start=1):
                change_task = request.form.get(f'pmreq-annual-task-input-{i}')
                Frequency = 'Annual'
                if change_task and change_task != annualtask[4]:
                    read_query_execute(connection, 'update_models.sql', (change_task, Model, i, Frequency))
                if not change_task and change_task != annualtask[4]:
                    cursor.execute("DELETE FROM PM_form WHERE Model = ? AND Frequency = 'Annual' AND Form_Order = ?",(Model,i,))
                    connection.commit()
                    # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Task', oldvalue=annualtask[4])
                    audit(connection, 11, auditdata = {"scope": Model, "initiatedby": session.get('username'), "frequency": Frequency, "task": annualtask[4]})
            ###Add new annual tasks that were submitted.###
            for key in request.form.keys():
                if key.startswith('pmreq-annual-task-new-'):
                    new_task = request.form.get(key)
                    tasknum = key.split('-')[4]
                    ###Ensure empty tasks are not added to database.###
                    if new_task:
                        read_query_execute(connection, 'create_pmform_task.sql', (Model, 'Annual', tasknum, new_task))
                        # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Task', oldvalue=new_task)
                        audit(connection, 10, auditdata = {"scope": Model, "initiatedby": session.get('username'), "frequency": "Annual", "task": new_task})
            ###Update Manufacturer if changed.###
            if new_manufacturer and new_manufacturer != Manufacturer:
                cursor.execute("UPDATE EquipModels SET Manufacturer = ? WHERE Model = ?",(new_manufacturer,Model,))
                connection.commit()
                # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Manufacturer', oldvalue=Manufacturer, newvalue=new_manufacturer)
                audit(connection, 4, auditdata = {"scope": Model, "initiatedby": session.get('username'), "oldvalue": Manufacturer, "newvalue": new_manufacturer, "field": "Manufacturer"})
            ###Update Class if changed.###
            if new_equipmentclass and new_equipmentclass != Equipment_Class:
                cursor.execute("UPDATE EquipModels SET Equipment_Class = ? WHERE Model = ?", (new_equipmentclass,Model,))
                connection.commit()
                # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Equipment_Class', oldvalue=Equipment_Class, newvalue=new_equipmentclass)
                audit(connection, 4, auditdata = {"scope": Model, "initiatedby": session.get('username'), "oldvalue": Equipment_Class, "newvalue": new_equipmentclass, "field": "Equipment_Class"})
            if new_modelActive and new_modelActive != str(modelActive).lower():
                cursor.execute("UPDATE EquipModels SET modelActive = ? WHERE Model = ?", (new_modelActive,Model,))
                connection.commit()
                # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='modelActive', oldvalue=modelActive, newvalue=new_modelActive)
                audit(connection, 4, auditdata = {"scope": Model, "initiatedby": session.get('username'), "oldvalue": modelActive, "newvalue": new_modelActive, "field": "modelActive"})
            ###Update Model if changed.###
            if new_model and new_model != Model:
                cursor.execute("UPDATE EquipModels SET Model = ? WHERE Model = ?",(new_model,Model,))
                connection.commit()
                # audit(scope=Model, eventtype='modelModify', initiatedby=session.get('username'), field='Model', oldvalue=Model, newvalue=new_model)
                audit(connection, 4, auditdata = {"scope": Model, "initiatedby": session.get('username'), "oldvalue": Model, "newvalue": new_model, "field": "Model"})
            ###Update session data so new values display on submit.###
            # data['Model'] = new_model
            # data['Manufacturer'] = new_manufacturer
            # data['Equipment_Class'] = new_equipmentclass
            # data['modelActive'] = new_modelActive
            # data['PM_Req_Daily'] = new_pmreqdaily
            # data['PM_Req_Weekly'] = new_pmreqweekly
            # data['PM_Req_Monthly'] = new_pmreqmonthly
            # data['PM_Req_Quarterly'] = new_pmreqquarterly
            # data['PM_Req_Annual'] = new_pmreqannual
            # session[token] = data
            return redirect(url_for('models', token=token))
    return render_template('modify_models.html', classlist=session.get('classlist'), 
                           dailytasks=dailytasks, weeklytasks=weeklytasks, 
                           monthlytasks=monthlytasks, quarterlytasks=quarterlytasks, 
                           annualtasks=annualtasks, Model=Model, Manufacturer=Manufacturer, 
                           Equipment_Class=Equipment_Class, modelActive=modelActive,
                           PM_Req_Daily=PM_Req_Daily, PM_Req_Weekly=PM_Req_Weekly,
                           PM_Req_Monthly=PM_Req_Monthly, PM_Req_Quarterly=PM_Req_Quarterly,
                           PM_Req_Annual=PM_Req_Annual, 
                           maxformorder_daily=maxformorder_daily, 
                           maxformorder_weekly=maxformorder_weekly, 
                           maxformorder_monthly=maxformorder_monthly, 
                           maxformorder_quarterly=maxformorder_quarterly, 
                           maxformorder_annual=maxformorder_annual, token=token,
                           sessionTimeout_sec=sessionTimeout_sec)