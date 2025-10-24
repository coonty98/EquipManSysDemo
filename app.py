import uuid, time, requests, os
from logic import (read_secret, login_required, require_access_levels, is_valid_password)
from flask import Flask, render_template, request, session, redirect, url_for, abort, jsonify
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime, timedelta
from authlib.integrations.flask_client import OAuth
from models import db, Settings, EquipClass, EquipModels, EquipStatus, UserStatus, Access, Labs, PM_form, emsAudit, EquipByLab, PM_Response, Records, Users, UsersLabAccess
from sqlalchemy import func

app = Flask(__name__)

if __name__ == "__main__":
 app.run(port=5050)

app.env = os.getenv('FLASK_ENV')
csrf = CSRFProtect(app)

def init_app():
    app.secret_key = read_secret(os.environ.get("FLASK_SECRET_KEY", "/run/secrets/flask_secret_key"))

if app.env == 'production':
    init_app()

    db_username = read_secret(os.environ.get("MYSQL_USERNAME", "/run/secrets/mysql_user"))
    db_password = read_secret(os.environ.get("MYSQL_PASSWORD", "/run/secrets/mysql_password"))
    db_name = read_secret(os.environ.get("MYSQL_DATABASE", "/run/secrets/mysql_database"))
    db_server = 'emsdemoDB'
    oauth_client_id = read_secret(os.environ.get("OAUTH_CLIENT_ID", "/run/secrets/oauth_client_id"))
    oauth_client_secret = read_secret(os.environ.get("OAUTH_CLIENT_SECRET", "/run/secrets/oauth_client_secret"))
    sessionTimeout_sec = read_secret(os.environ.get("SESSIONTIMEOUT_SEC", "/run/secrets/sessionTimeout_sec"))
    pwd_chg_days = read_secret(os.environ.get("PWD_CHG_DAYS", "/run/secrets/pwd_chg_days"))

    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mysql+pymysql://{db_username}:{db_password}@{db_server}:3306/{db_name}?charset=utf8mb4"
    )
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )
else:
    init_app()
    
    db_username = read_secret(os.environ.get("MYSQL_USERNAME", "/run/secrets/mysql_user"))
    db_password = read_secret(os.environ.get("MYSQL_PASSWORD", "/run/secrets/mysql_password"))
    db_name = read_secret(os.environ.get("MYSQL_DATABASE", "/run/secrets/mysql_database"))
    db_server = 'emsdemoDB'
    oauth_client_id = read_secret(os.environ.get("OAUTH_CLIENT_ID", "/run/secrets/oauth_client_id"))
    oauth_client_secret = read_secret(os.environ.get("OAUTH_CLIENT_SECRET", "/run/secrets/oauth_client_secret"))
    sessionTimeout_sec = read_secret(os.environ.get("SESSIONTIMEOUT_SEC", "/run/secrets/sessionTimeout_sec"))
    pwd_chg_days = read_secret(os.environ.get("PWD_CHG_DAYS", "/run/secrets/pwd_chg_days"))

    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mysql+pymysql://{db_username}:{db_password}@{db_server}:3306/{db_name}?charset=utf8mb4"
    )


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    settings = Settings.query.first()
    if settings:
        app.secret_key = settings.secretkey
        sessionTimeout_sec = settings.sesssionTimeout_sec
        pwd_chg_days = settings.pwd_chg_days
        secretkey = settings.secretkey
        oauth_clientid = settings.oauth_clientid
        oauth_clientsecret = settings.oauth_clientsecret

CORS(app)

oauth = OAuth(app)
oauth.register(
    name='microsoft',
    client_id=oauth_clientid,
    client_secret=oauth_clientsecret,
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
        userinfo = Users.query.filter_by(username=username).first()
        if userinfo:
            passwordhash = userinfo.password_hash
        if passwordhash and check_password_hash(passwordhash, old_password):
            if new_password == old_password:
                return render_template('password_change.html', error="New Password cannot be the same as the Old Password!", token=token, username=username)
            if new_password == confirm_password:
                password_hash = generate_password_hash(new_password)
                update_user = Users.query.filter_by(username=username).first()
                if update_user:
                    update_user.password_hash=password_hash
                    update_user.require_pwd_chg=0
                    update_user.last_pwd_chg=date.today()
                    db.session.commit()
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
    record = Records.query.filter_by(Record_Num=record_num).first()
    frequency = record.Frequency if record else None
    if frequency:
        rows = (
            PM_form.query.filter_by(Model=model, Frequency=frequency)
            .order_by(PM_form.Form_Order.asc()).all()
        )
        rows_data = [row.to_dict() for row in rows]
    else:
        rows_data = []
    return jsonify({
        "token": token,
        "rows": rows_data,
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
    token = str(uuid.uuid4())
    session[token] = {}
    return jsonify({
        'token': token
    })

@app.route('/new_user_link', methods=['POST'])
def new_user_link():
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
        userinfo = Users.query.filter_by(username=username).first()
        if userinfo:
            passwordhash = userinfo.password_hash
            primarylab = userinfo.PrimaryLab
            userStatus = userinfo.userStatus
            require_pwd_chg = userinfo.require_pwd_chg
            last_pwd_chg = userinfo.last_pwd_chg
            pwd_expired = None
            if (last_pwd_chg) < (date.today() - timedelta(days=pwd_chg_days)):
                pwd_expired = True
            else:
                pwd_expired = False
        else:
            return render_template('login.html', error='Invalid Username')
        lab_access_info = UsersLabAccess.query.filter_by(username=username).all()
        if lab_access_info:
            session['labs'] = [row.lab_access for row in lab_access_info]
            session['lab_access'] = [{'lab_access': row.lab_access, 'access_level': row.access_level} for row in lab_access_info]

        failed_attempts = session.get('failed_attempts', 0)

        if userStatus == 'Locked':
            return render_template('login.html', error='Account locked. Contact your Manager.')
        if userStatus == 'Disabled':
            return render_template('login.html', error='Account disabled. Please contact your Manager.')
        if userinfo and check_password_hash(passwordhash, password):
            if require_pwd_chg == 1 or require_pwd_chg is True:
                return redirect(url_for('password_change_link', username=username))
            if pwd_expired is True:
                return redirect(url_for('password_change_link', username=username))
            session['logged_in'] = True
            session['ms_login'] = False
            session['username'] = username
            selected_access_level = None
            for item in session['lab_access']:
                if item['lab_access'] == primarylab:
                    selected_access_level = item['access_level']
                    break
            session['access_level'] = selected_access_level
            session['LabID'] = primarylab
            update_users = Users.query.filter_by(username=username).first()
            if update_users:
                update_users.LastLoginDate = datetime.now()
                db.session.commit()
            if session.get('access_level') in ['Administrator', 'Global Audit']:
                session['lablist'] = [row.LabID for row in Labs.query.all()]
            else:
                session['lablist'] = [session.get('LabID')]
            session['classlist'] = [row.Equipment_Class for row in EquipClass.query.all()]
            session['modellist'] = [row.Model for row in EquipModels.query.all()]
            session['statuslist'] = [row.equipStatus for row in EquipStatus.query.all()]
            session['userstatuslist'] = [row.userStatus for row in UserStatus.query.all()]
            if session.get('access_level') in ['Manager', 'Local Audit']:
                session['access_list'] = ['Local Audit', 'Manager', 'Technician']
            else:
                session['access_list'] = [row.access_level for row in Access.query.order_by(Access.Hierarchy.desc())]
            session['failed_attempts'] = 0
            return redirect(url_for('index'))
        else:
            failed_attempts += 1
            session['failed_attempts'] = failed_attempts
            if failed_attempts >= 3:
                update_userstatus = Users.query.filter_by(username=username).first()
                if update_userstatus:
                    update_userstatus.userStatus = 'Locked'
                    db.session.commit()
                create_audit = emsAudit(
                    Scope=username,
                    EventType='userStatus',
                    InitiatedBy='SYSTEM',
                    EventDetails=f"userStatus changed from {'Active'} to {'Locked'}."
                )
                db.session.add(create_audit)
                db.session.commit()
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
        lablist = session.get('labs')
        access_list = session.get('access_list')
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
    if request.method == 'POST':
        completedby = request.form.get('completedby')
        checked = list(request.form.items())
        for key, value in checked:
            form_order = key
            if key in ['record_num', 'model', 'completedby', 'token', 'csrf_token']:
                continue
            if value == 'on':
                response = 1
            else:
                response = 0
            new_form_response = PM_Response(
                Record_Num=record_num,
                ID=form_order,
                Response=response
            )
            db.session.add(new_form_response)
            db.session.commit()
        update_records_complete = Records.query.filter_by(Record_Num=record_num).first()
        if update_records_complete:
            update_records_complete.Record_Status = 'Complete'
            update_records_complete.CompleteDate = datetime.now()
            update_records_complete.CompletedBy = completedby
            db.session.commit()
        return redirect(url_for('index'))

@app.route('/modify_user', methods=['GET', 'POST'])
@login_required
@require_access_levels('Administrator', 'Manager')
def modify_user():
    token = request.args.get('token')
    data = session.get(token)
    if not data:
        abort(403)
    username = data['username']
    new_username = request.form.get('new_username')
    firstname = data['FirstName']
    new_firstname = request.form.get('new_firstname')
    lastname = data['LastName']
    new_lastname = request.form.get('new_lastname')
    new_password = request.form.get('new_password')
    new_accesslevel = request.form.get('new_accesslevel')
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
        if new_password:
            password_hash = generate_password_hash(new_password)
            update_user_password = Users.query.filter_by(username=username).first()
            if update_user_password:
                update_user_password.password_hash = password_hash
                db.session.commit()
        if not new_username:
            update_user_details = Users.query.filter_by(username=username)
            if update_user_details:
                update_user_details.userStatus = new_userstatus
                update_user_details.require_pwd_chg = req_pwd_chg
                db.session.commit()
        else:
            update_useraccess = UsersLabAccess.query.filter_by(username=username, lab_access=PrimaryLab).first()
            update_useraccess.access_level = new_accesslevel if update_useraccess else None
            db.session.commit()
            update_user = Users.query.filter_by(username=username).first()
            if update_user:
                update_user.PrimaryLab = new_primarylab
                update_user.username = new_username
                update_user.FirstName = new_firstname
                update_user.LastName = new_lastname
                update_user.userStatus = new_userstatus
                update_user.require_pwd_chg = req_pwd_chg
                db.session.commit()
        if new_username and new_username != username:
            create_audit = emsAudit(Scope=username, EventType='userModify', InitiatedBy=session.get('username'), EventDetails=f"username changed from {username} to {new_username}.")
            db.session.add(create_audit)
            db.session.commit()
        if new_accesslevel and new_accesslevel != access_level:
            create_audit = emsAudit(Scope=username, EventType='userModify', InitiatedBy=session.get('username'), EventDetails=f"access_level changed from {access_level} to {new_accesslevel}.")
            db.session.add(create_audit)
            db.session.commit()
        if new_primarylab and new_primarylab != PrimaryLab:
            create_audit = emsAudit(Scope=username, EventType='userModify', InitiatedBy=session.get('username'), EventDetails=f"PrimaryLab changed from {PrimaryLab} to {new_primarylab}.")
            db.session.add(create_audit)
            db.session.commit()
        if new_userstatus and new_userstatus != userStatus:
            create_audit = emsAudit(Scope=username, EventType='userModify', InitiatedBy=session.get('username'), EventDetails=f"userStatus changed from {userStatus} to {new_userstatus}.")
            db.session.add(create_audit)
            db.session.commit()
        if new_firstname and new_firstname != firstname:
            create_audit = emsAudit(Scope=username, EventType='userModify', InitiatedBy=session.get('username'), EventDetails=f"firstname changed from {firstname} to {new_firstname}.")
            db.session.add(create_audit)
            db.session.commit()
        if new_lastname and new_lastname != lastname:
            create_audit = emsAudit(Scope=username, EventType='userModify', InitiatedBy=session.get('username'), EventDetails=f"lastname changed from {lastname} to {new_lastname}.")
            db.session.add(create_audit)
            db.session.commit()
        data['username'] = new_username
        data['FirstName'] = new_firstname
        data['LastName'] = new_lastname
        data['access_level'] = new_accesslevel
        data['PrimaryLab'] = new_primarylab
        data['userStatus'] = new_userstatus
        session[token] = data
        return redirect(url_for('users', token=token))        
    return render_template('users.html', userstatuslist=session.get('userstatuslist'), lablist=session.get('lablist'), access_list=session.get('access_list'), username=username, lab_access=lab_access, PrimaryLab=PrimaryLab, access_level=access_level, userStatus=userStatus, token=token)

@app.route('/get_user_lab_access', methods=['POST'])
@login_required
@require_access_levels('Administrator', 'Manager')
def get_user_lab_access():
    data = request.get_json()
    username = data.get('username')
    lab_access_info = UsersLabAccess.query.filter_by(username=username).all()
    if lab_access_info:
        user_labs = [row.lab_access for row in lab_access_info]
        user_lab_access = {row.lab_access: row.access_level for row in lab_access_info}
    if session.get('access_level') == 'Administrator':
        server_accesslevels = session.get('access_list')
    else:
        server_accesslevels = ['Local Audit', 'Manager', 'Technician']
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
    lab_access_info = UsersLabAccess.query.filter_by(username=username).all()
    if lab_access_info:
        rows_as_tuples = [(row.lab_access, row.access_level) for row in lab_access_info]
    UsersLabAccess.query.filter_by(username=username).delete()
    db.session.commit()
    newlabaccess = []
    # Grant new access
    for lab, access in zip(labs, access_levels):
        create_useraccess = UsersLabAccess(
            username=username,
            lab_access=lab,
            access_level=access
        )
        db.session.add(create_useraccess)
        db.session.commit()
        newlabaccess.extend([(lab,access)])
    # Create audit event only for new access granted
    for item in newlabaccess:
        if item not in rows_as_tuples:
            newlab = item[0]
            newaccess = item[1]
            create_audit = emsAudit(Scope=username, EventType='userLabAccess', InitiatedBy=session.get('username'), EventDetails=f"{newaccess} granted for {newlab}.")
            db.session.add(create_audit)
            db.session.commit()
    # Create audit event only for new access revoked
    for item in rows_as_tuples:
        if item not in newlabaccess:
            oldlab = item[0]
            oldaccess = item[1]
            create_audit = emsAudit(Scope=username, EventType='userLabAccess', InitiatedBy=session.get('username'), EventDetails=f"{oldaccess} revoked for {oldlab}.")
            db.session.add(create_audit)
            db.session.commit()
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
        update_equipment = EquipByLab.query.filter_by(Serial_Num=Serial_Num).first()
        if update_equipment:
            update_equipment.Serial_Num=new_serialnum
            update_equipment.LabID=new_labid
            update_equipment.Model=new_model
            update_equipment.equipStatus=new_status
            db.session.commit()
        if new_serialnum and new_serialnum != Serial_Num:
            create_audit = emsAudit(
                Scope=Serial_Num,
                EventType='equipmentModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"Serial_Num changed from {Serial_Num} to {new_serialnum}."
            )
            db.session.add(create_audit)
            db.session.commit()
        if new_labid and new_labid != LabID:
            create_audit = emsAudit(
                Scope=LabID,
                EventType='equipmentModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"LabID changed from {LabID} to {new_labid}."
            )
            db.session.add(create_audit)
            db.session.commit()
        if new_model and new_model != Model:
            create_audit = emsAudit(
                Scope=Model,
                EventType='equipmentModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"Model changed from {Model} to {new_model}."
            )
            db.session.add(create_audit)
            db.session.commit()
        if new_status and new_status != equipStatus:
            create_audit = emsAudit(
                Scope=equipStatus,
                EventType='equipmentModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"equipStatus changed from {equipStatus} to {new_status}."
            )
            db.session.add(create_audit)
            db.session.commit()
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
        new_equipment = EquipByLab(
            Serial_Num=new_serialnum,
            Model=new_model,
            LabID=new_labid,
            equipStatus=new_status
        )
        db.session.add(new_equipment)
        db.session.commit()
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
        password_hash = generate_password_hash(new_password)
        create_user = Users(
            username=new_username,
            password_hash=password_hash,
            PrimaryLab=new_primarylab,
            FirstName=new_firstname,
            LastName=new_lastname,
            userStatus='Active',
            require_pwd_chg=1,
            last_pwd_chg=date.today()
        )
        db.session.add(create_user)
        db.session.commit()
        create_useraccess = UsersLabAccess(
            username=new_username,
            lab_access=new_primarylab,
            access_level=new_accesslevel
        )
        db.session.add(create_useraccess)
        db.session.commit()
        create_audit = emsAudit(Scope=new_username, EventType='userCreate', InitiatedBy=session.get('username'), EventDetails=f"New user created: {new_username}.")
        db.session.add(create_audit)
        db.session.commit()
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
        create_model = EquipModels(
            Model=new_model,
            Manufacturer=new_manufacturer,
            Equipment_Class=new_equipmentclass
        )
        db.session.add(create_model)
        db.session.commit()
        create_audit = emsAudit(
            Scope=new_model,
            EventType='modelCreate',
            InitiatedBy=session.get('username'),
            EventDetails=f"New model created: {new_model}."
        )
        db.session.add(create_audit)
        db.session.commit()
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
    if session.get('access_level') not in ['Administrator', 'Global Audit']:
        labid = session.get('LabID')
    has_lab_filter = labid and (labid != 'All Labs' or session.get('access_level') not in ['Administrator', 'Global Audit'])
    has_class_filter = equipment_class and equipment_class != 'All Classes'
    match (bool(has_lab_filter), bool(has_class_filter)):
        case (True, True):
            rows = (
                db.session.query(Records.Record_Num, EquipByLab.LabID, Records.Serial_Num, EquipByLab.Model, EquipModels.Equipment_Class, Records.Due_Date_Start, Records.Due_Date_End)
                .join(EquipByLab, Records.Serial_Num == EquipByLab.Serial_Num)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(Records.Frequency == frequency, Records.Record_Status != 'Complete', EquipModels.Equipment_Class == equipment_class, Records.LabID == labid).all()
            )
            results_list = [dict(zip([
                'Record_Num', 'LabID', 'Serial_Num', 'Model', 'Equipment_Class', 'Due_Date_Start', 'Due_Date_End'
                ], row)) for row in rows]
        case (True, False):
            rows = (
                db.session.query(Records.Record_Num, EquipByLab.LabID, Records.Serial_Num, EquipByLab.Model, EquipModels.Equipment_Class, Records.Due_Date_Start, Records.Due_Date_End)
                .join(EquipByLab, Records.Serial_Num == EquipByLab.Serial_Num)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(Records.Frequency == frequency, Records.Record_Status != 'Complete', Records.LabID == labid).all()
            )
            results_list = [dict(zip([
                'Record_Num', 'LabID', 'Serial_Num', 'Model', 'Equipment_Class', 'Due_Date_Start', 'Due_Date_End'
                ], row)) for row in rows]
        case (False, True):
            rows = (
                db.session.query(Records.Record_Num, EquipByLab.LabID, Records.Serial_Num, EquipByLab.Model, EquipModels.Equipment_Class, Records.Due_Date_Start, Records.Due_Date_End)
                .join(EquipByLab, Records.Serial_Num == EquipByLab.Serial_Num)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(Records.Frequency == frequency, Records.Record_Status != 'Complete', EquipModels.Equipment_Class == equipment_class).all()
            )
            results_list = [dict(zip([
                'Record_Num', 'LabID', 'Serial_Num', 'Model', 'Equipment_Class', 'Due_Date_Start', 'Due_Date_End'
                ], row)) for row in rows]
        case (False, False):
            rows = (
                db.session.query(Records.Record_Num, EquipByLab.LabID, Records.Serial_Num, EquipByLab.Model, EquipModels.Equipment_Class, Records.Due_Date_Start, Records.Due_Date_End)
                .join(EquipByLab, Records.Serial_Num == EquipByLab.Serial_Num)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(Records.Frequency == frequency, Records.Record_Status != 'Complete').all()
            )
            results_list = [dict(zip([
                'Record_Num', 'LabID', 'Serial_Num', 'Model', 'Equipment_Class', 'Due_Date_Start', 'Due_Date_End'
                ], row)) for row in rows]
    return {'results': results_list}

@app.route('/get_users', methods = ['POST'])
@login_required
@require_access_levels('Administrator', 'Manager', 'Local Audit', 'Global Audit')
def get_users():
    if not request.json:
        return {'results': 'Error. Please send valid post request.'}
    data = request.get_json()
    labid = data.get('labid')
    session['inactiveusertoggle'] = data.get('inactiveusertoggle')
    if session.get('access_level') not in ['Administrator', 'Global Audit']:
        labid = session.get('LabID')
    query_params = {}
    has_lab_filter = labid and (labid != 'All Labs' or session.get('access_level') not in ['Administrator', 'Global Audit'])
    params = []
    match (bool(has_lab_filter), session['inactiveusertoggle']):
        case (True, 'False'):
            rows = (
                db.session.query(UsersLabAccess.username, UsersLabAccess.access_level, UsersLabAccess.lab_access, Users.FirstName, Users.LastName,
                                    Users.PrimaryLab, Users.LastLoginDate, Users.userStatus, Users.require_pwd_chg)
                                    .join(Users, Users.username == UsersLabAccess.username)
                                    .join(Access, Access.access_level == UsersLabAccess.access_level)
                                    .filter(UsersLabAccess.lab_access == labid, Access.Hierarchy > 2, Users.userStatus != 'Disabled').all()
            )
            results = [dict(zip(['username', 'access_level', 'lab_access', 'FirstName', 'LastName', 'PrimaryLab',
                                'LastLoginDate', 'userStatus', 'require_pwd_chg'], row)) for row in rows]
        case (True, 'True'):
            rows = (
                db.session.query(UsersLabAccess.username, UsersLabAccess.access_level, UsersLabAccess.lab_access, Users.FirstName, Users.LastName,
                                    Users.PrimaryLab, Users.LastLoginDate, Users.userStatus, Users.require_pwd_chg)
                                    .join(Users, Users.username == UsersLabAccess.username)
                                    .join(Access, Access.access_level == UsersLabAccess.access_level)
                                    .filter(UsersLabAccess.lab_access == labid, Access.Hierarchy > 2, Users.userStatus == 'Disabled').all()
            )
            results = [dict(zip(['username', 'access_level', 'lab_access', 'FirstName', 'LastName', 'PrimaryLab',
                                'LastLoginDate', 'userStatus', 'require_pwd_chg'], row)) for row in rows]
        case (False, 'False'):
            rows = (
                db.session.query(UsersLabAccess.username, UsersLabAccess.access_level, UsersLabAccess.lab_access, Users.FirstName, Users.LastName,
                                    Users.PrimaryLab, Users.LastLoginDate, Users.userStatus, Users.require_pwd_chg)
                                    .join(Users, Users.username == UsersLabAccess.username)
                                    .filter(UsersLabAccess.lab_access == Users.PrimaryLab, Users.userStatus != 'Disabled').all()
            )
            results = [dict(zip(['username', 'access_level', 'lab_access', 'FirstName', 'LastName', 'PrimaryLab',
                                'LastLoginDate', 'userStatus', 'require_pwd_chg'], row)) for row in rows]
        case (False, 'True'):
            rows = (
                db.session.query(UsersLabAccess.username, UsersLabAccess.access_level, UsersLabAccess.lab_access, Users.FirstName, Users.LastName,
                                    Users.PrimaryLab, Users.LastLoginDate, Users.userStatus, Users.require_pwd_chg)
                                    .join(Users, Users.username == UsersLabAccess.username)
                                    .filter(UsersLabAccess.lab_access == Users.PrimaryLab, Users.userStatus == 'Disabled').all()
            )
            results = [dict(zip(['username', 'access_level', 'lab_access', 'FirstName', 'LastName', 'PrimaryLab',
                                'LastLoginDate', 'userStatus', 'require_pwd_chg'], row)) for row in rows]
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
    if session.get('access_level') not in ['Administrator', 'Global Audit']:
        labid = session.get('LabID')
    has_lab_filter = labid and labid != 'All Labs'
    has_class_filter = equipment_class and equipment_class != 'All Classes'
    is_admin_ga = session['access_level'] in ['Administrator', 'Global Audit']
    is_manager_la = session['access_level'] in ['Manager', 'Local Audit']
    
    match (bool(is_admin_ga), bool(is_manager_la), bool(has_lab_filter), bool(has_class_filter), session['inactivetoggle']):
        case (True, False, True, True, 'False') | (False, True, True, True, 'False'):
            get_equipment_active_labclass = (
                db.session.query(EquipByLab.Serial_Num, EquipByLab.Model, EquipModels.Manufacturer, EquipModels.Equipment_Class,
                    EquipByLab.LabID, EquipByLab.Created_Date, EquipModels.PM_Req_Daily, EquipModels.PM_Req_Weekly,
                    EquipModels.PM_Req_Monthly, EquipModels.PM_Req_Quarterly, EquipModels.PM_Req_Annual, EquipByLab.equipStatus)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(~EquipByLab.equipStatus.in_(['Retired Offsite', 'Retired onsite']), EquipModels.Equipment_Class == equipment_class, EquipByLab.LabID == labid).all()
            )
            results_list = [dict(zip(
                ['Serial_Num', 'Model', 'Manufacturer', 'Equipment_Class', 'LabID', 'Created_Date',
                'PM_Req_Daily', 'PM_Req_Weekly', 'PM_Req_Monthly', 'PM_Req_Quarterly', 'PM_Req_Annual', 'equipStatus'
                ], row)) for row in get_equipment_active_labclass]
        case (True, False, True, False, 'False') | (False, True, True, False, 'False'):
            get_equipment_active_lab = (
                db.session.query(EquipByLab.Serial_Num, EquipByLab.Model, EquipModels.Manufacturer, EquipModels.Equipment_Class,
                    EquipByLab.LabID, EquipByLab.Created_Date, EquipModels.PM_Req_Daily, EquipModels.PM_Req_Weekly,
                    EquipModels.PM_Req_Monthly, EquipModels.PM_Req_Quarterly, EquipModels.PM_Req_Annual, EquipByLab.equipStatus)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(~EquipByLab.equipStatus.in_(['Retired Offsite', 'Retired onsite']), EquipByLab.LabID == labid).all()
            )
            results_list = [dict(zip(
                ['Serial_Num', 'Model', 'Manufacturer', 'Equipment_Class', 'LabID', 'Created_Date',
                'PM_Req_Daily', 'PM_Req_Weekly', 'PM_Req_Monthly', 'PM_Req_Quarterly', 'PM_Req_Annual', 'equipStatus'
                ], row)) for row in get_equipment_active_lab]
        case (True, False, False, True, 'False'):
            get_equipment_active_class = (
                db.session.query(EquipByLab.Serial_Num, EquipByLab.Model, EquipModels.Manufacturer, EquipModels.Equipment_Class,
                    EquipByLab.LabID, EquipByLab.Created_Date, EquipModels.PM_Req_Daily, EquipModels.PM_Req_Weekly,
                    EquipModels.PM_Req_Monthly, EquipModels.PM_Req_Quarterly, EquipModels.PM_Req_Annual, EquipByLab.equipStatus)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(~EquipByLab.equipStatus.in_(['Retired Offsite', 'Retired onsite']), EquipModels.Equipment_Class == equipment_class).all()
            )
            results_list = [dict(zip(
                ['Serial_Num', 'Model', 'Manufacturer', 'Equipment_Class', 'LabID', 'Created_Date',
                'PM_Req_Daily', 'PM_Req_Weekly', 'PM_Req_Monthly', 'PM_Req_Quarterly', 'PM_Req_Annual', 'equipStatus'
                ], row)) for row in get_equipment_active_class]
        case (True, False, False, False, 'False'):
            get_equipment_active = (
                db.session.query(EquipByLab.Serial_Num, EquipByLab.Model, EquipModels.Manufacturer, EquipModels.Equipment_Class,
                    EquipByLab.LabID, EquipByLab.Created_Date, EquipModels.PM_Req_Daily, EquipModels.PM_Req_Weekly,
                    EquipModels.PM_Req_Monthly, EquipModels.PM_Req_Quarterly, EquipModels.PM_Req_Annual, EquipByLab.equipStatus)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(~EquipByLab.equipStatus.in_(['Retired Offsite', 'Retired onsite'])).all()
            )
            results_list = [dict(zip(
                ['Serial_Num', 'Model', 'Manufacturer', 'Equipment_Class', 'LabID', 'Created_Date',
                'PM_Req_Daily', 'PM_Req_Weekly', 'PM_Req_Monthly', 'PM_Req_Quarterly', 'PM_Req_Annual', 'equipStatus'
                ], row)) for row in get_equipment_active]
        case (True, False, True, True, 'True') | (False, True, True, True, 'True'):
            get_equipment_inactive_labclass = (
                db.session.query(EquipByLab.Serial_Num, EquipByLab.Model, EquipModels.Manufacturer, EquipModels.Equipment_Class,
                    EquipByLab.LabID, EquipByLab.Created_Date, EquipModels.PM_Req_Daily, EquipModels.PM_Req_Weekly,
                    EquipModels.PM_Req_Monthly, EquipModels.PM_Req_Quarterly, EquipModels.PM_Req_Annual, EquipByLab.equipStatus)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(EquipByLab.equipStatus.in_(['Retired Offsite', 'Retired onsite']), EquipModels.Equipment_Class == equipment_class, EquipByLab.LabID == labid).all()
            )
            results_list = [dict(zip(
                ['Serial_Num', 'Model', 'Manufacturer', 'Equipment_Class', 'LabID', 'Created_Date',
                'PM_Req_Daily', 'PM_Req_Weekly', 'PM_Req_Monthly', 'PM_Req_Quarterly', 'PM_Req_Annual', 'equipStatus'
                ], row)) for row in get_equipment_inactive_labclass]
        case (True, False, True, False, 'True') | (False, True, True, False, 'True'):
            get_equipment_inactive_lab = (
                db.session.query(EquipByLab.Serial_Num, EquipByLab.Model, EquipModels.Manufacturer, EquipModels.Equipment_Class,
                    EquipByLab.LabID, EquipByLab.Created_Date, EquipModels.PM_Req_Daily, EquipModels.PM_Req_Weekly,
                    EquipModels.PM_Req_Monthly, EquipModels.PM_Req_Quarterly, EquipModels.PM_Req_Annual, EquipByLab.equipStatus)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(EquipByLab.equipStatus.in_(['Retired Offsite', 'Retired onsite']), EquipByLab.LabID == labid).all()
            )
            results_list = [dict(zip(
                ['Serial_Num', 'Model', 'Manufacturer', 'Equipment_Class', 'LabID', 'Created_Date',
                'PM_Req_Daily', 'PM_Req_Weekly', 'PM_Req_Monthly', 'PM_Req_Quarterly', 'PM_Req_Annual', 'equipStatus'
                ], row)) for row in get_equipment_inactive_lab]
        case (True, False, False, True, 'True'):
            get_equipment_inactive_class = (
                db.session.query(EquipByLab.Serial_Num, EquipByLab.Model, EquipModels.Manufacturer, EquipModels.Equipment_Class,
                    EquipByLab.LabID, EquipByLab.Created_Date, EquipModels.PM_Req_Daily, EquipModels.PM_Req_Weekly,
                    EquipModels.PM_Req_Monthly, EquipModels.PM_Req_Quarterly, EquipModels.PM_Req_Annual, EquipByLab.equipStatus)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(EquipByLab.equipStatus.in_(['Retired Offsite', 'Retired onsite']), EquipModels.Equipment_Class == equipment_class).all()
            )
            results_list = [dict(zip(
                ['Serial_Num', 'Model', 'Manufacturer', 'Equipment_Class', 'LabID', 'Created_Date',
                'PM_Req_Daily', 'PM_Req_Weekly', 'PM_Req_Monthly', 'PM_Req_Quarterly', 'PM_Req_Annual', 'equipStatus'
                ], row)) for row in get_equipment_inactive_class]
        case (True, False, False, False, 'True'):
            get_equipment_inactve = (
                db.session.query(EquipByLab.Serial_Num, EquipByLab.Model, EquipModels.Manufacturer, EquipModels.Equipment_Class,
                    EquipByLab.LabID, EquipByLab.Created_Date, EquipModels.PM_Req_Daily, EquipModels.PM_Req_Weekly,
                    EquipModels.PM_Req_Monthly, EquipModels.PM_Req_Quarterly, EquipModels.PM_Req_Annual, EquipByLab.equipStatus)
                .join(EquipModels, EquipByLab.Model == EquipModels.Model)
                .filter(EquipByLab.equipStatus.in_(['Retired Offsite', 'Retired onsite'])).all()
            )
            results_list = [dict(zip(
                ['Serial_Num', 'Model', 'Manufacturer', 'Equipment_Class', 'LabID', 'Created_Date',
                'PM_Req_Daily', 'PM_Req_Weekly', 'PM_Req_Monthly', 'PM_Req_Quarterly', 'PM_Req_Annual', 'equipStatus'
                ], row)) for row in get_equipment_inactve]
    return {'results': results_list}

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
        new_modelActive = True
    else:
        new_modelActive = False
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
        
    PM_Req_Daily = data['PM_Req_Daily']
    if request.form.get('pmreq-daily') == 'on':
        new_pmreqdaily = True
    else:
        new_pmreqdaily = False
    PM_Req_Weekly = data['PM_Req_Weekly']
    if request.form.get('pmreq-weekly') == 'on':
        new_pmreqweekly = True
    else:
        new_pmreqweekly = False
    PM_Req_Monthly = data['PM_Req_Monthly']
    if request.form.get('pmreq-monthly') == 'on':
        new_pmreqmonthly = True
    else:
        new_pmreqmonthly = False
    PM_Req_Quarterly = data['PM_Req_Quarterly']
    if request.form.get('pmreq-quarterly') == 'on':
        new_pmreqquarterly = True
    else:
        new_pmreqquarterly = False
    PM_Req_Annual = data['PM_Req_Annual']
    if request.form.get('pmreq-annual') == 'on':
        new_pmreqannual = True
    else:
        new_pmreqannual = False
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

    if request.method == 'POST':
        if bool(new_pmreqdaily) != bool(PM_Req_Daily):
            update_models = EquipModels.query.filter_by(Model=Model).first()
            if update_models:
                update_models.PM_Req_Daily = new_pmreqdaily
                db.session.commit()
            create_audit = emsAudit(
                Scope=Model,
                EventType='modelModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"PM_Req_Daily changed from {PM_Req_Daily} to {new_pmreqdaily}."
            )
            db.session.add(create_audit)
            db.session.commit()
        if bool(new_pmreqweekly) != bool(PM_Req_Weekly):
            update_models = EquipModels.query.filter_by(Model=Model).first()
            if update_models:
                update_models.PM_Req_Weekly = new_pmreqweekly
                db.session.commit()
            create_audit = emsAudit(
                Scope=Model,
                EventType='modelModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"PM_Req_Weekly changed from {PM_Req_Weekly} to {new_pmreqweekly}."
            )
            db.session.add(create_audit)
            db.session.commit()
        if bool(new_pmreqmonthly) != bool(PM_Req_Monthly):
            update_models = EquipModels.query.filter_by(Model=Model).first()
            if update_models:
                update_models.PM_Req_Monthly = new_pmreqmonthly
                db.session.commit()
            create_audit = emsAudit(
                Scope=Model,
                EventType='modelModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"PM_Req_Monthly changed from {PM_Req_Monthly} to {new_pmreqmonthly}."
            )
            db.session.add(create_audit)
            db.session.commit()
        if bool(new_pmreqquarterly) != bool(PM_Req_Quarterly):
            update_models = EquipModels.query.filter_by(Model=Model).first()
            if update_models:
                update_models.PM_Req_Quarterly = new_pmreqquarterly
                db.session.commit()
            create_audit = emsAudit(
                Scope=Model,
                EventType='modelModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"PM_Req_Quarterly changed from {PM_Req_Quarterly} to {new_pmreqquarterly}."
            )
            db.session.add(create_audit)
            db.session.commit()
        if bool(new_pmreqannual) != bool(PM_Req_Annual):
            update_models = EquipModels.query.filter_by(Model=Model).first()
            if update_models:
                update_models.PM_Req_Annual = new_pmreqannual
                db.session.commit()
            create_audit = emsAudit(
                Scope=Model,
                EventType='modelModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"PM_Req_Annual changed from {PM_Req_Annual} to {new_pmreqannual}."
            )
            db.session.add(create_audit)
            db.session.commit()

        ###Update daily tasks if changed.###
        for i, dailytask in enumerate(dailytasks, start=1):
            change_task = request.form.get(f"pmreq-daily-task-input-{i}")
            Frequency = 'Daily'
            if change_task and change_task != dailytask[4]:
                update_models = PM_form.query.filter_by(Model=Model, Form_Order=i, Frequency=Frequency).first()
                if update_models:
                    update_models.Task = change_task
                    db.session.commit()
            if not change_task and change_task != dailytask[4]:
                PM_form.query.filter_by(Model=Model, Frequency='Daily', Form_Order=i).delete()
                db.session.commit()
                create_audit = emsAudit(
                    Scope=Model,
                    EventType='modelModify',
                    InitiatedBy=session.get('username'),
                    EventDetails=f"Daily task deleted: {dailytask[4]}."
                )
                db.session.add(create_audit)
                db.session.commit()
        ###Add new daily tasks that were submitted.###
        for key in request.form.keys():
            if key.startswith('pmreq-daily-task-new-'):
                new_task = request.form.get(key)
                tasknum = key.split('-')[4]
                ###Ensure empty tasks are not added to database.###
                if new_task:
                    create_task = PM_form(
                        Model=Model,
                        Frequency='Daily',
                        Form_Order=tasknum,
                        Task=new_task
                    )
                    db.session.add(create_task)
                    db.session.commit()
                    create_audit = emsAudit(
                        Scope=Model,
                        EventType='modelModify',
                        InitiatedBy=session.get('username'),
                        EventDetails=f"New Daily task created: {new_task}."
                    )
                    db.session.add(create_audit)
                    db.session.commit()
        ###Update weekly tasks if changed.###
        for i, weeklytask in enumerate(weeklytasks, start=1):
            change_task = request.form.get(f'pmreq-weekly-task-input-{i}')
            Frequency = 'Weekly'
            if change_task and change_task != weeklytask[4]:
                update_models = PM_form.query.filter_by(Model=Model, Form_Order=i, Frequency=Frequency).first()
                if update_models:
                    update_models.Task = change_task
                    db.session.commit()
            if not change_task and change_task != weeklytask[4]:
                PM_form.query.filter_by(Model=Model, Frequency='Weekly', Form_Order=i).delete()
                db.session.commit()
                create_audit = emsAudit(
                    Scope=Model,
                    EventType='modelModify',
                    InitiatedBy=session.get('username'),
                    EventDetails=f"Weekly task deleted: {dailytask[4]}."
                )
                db.session.add(create_audit)
                db.session.commit()
        ###Add new weekly tasks that were submitted.###
        for key in request.form.keys():
            if key.startswith('pmreq-weekly-task-new-'):
                new_task = request.form.get(key)
                tasknum = key.split('-')[4]
                ###Ensure empty tasks are not added to database.###
                if new_task:
                    create_task = PM_form(
                        Model=Model,
                        Frequency='Weekly',
                        Form_Order=tasknum,
                        Task=new_task
                    )
                    db.session.add(create_task)
                    db.session.commit()
                    create_audit = emsAudit(
                        Scope=Model,
                        EventType='modelModify',
                        InitiatedBy=session.get('username'),
                        EventDetails=f"New Weekly task created: {new_task}."
                    )
                    db.session.add(create_audit)
                    db.session.commit()
        ###Update monthly tasks if changed.###
        for i, monthlytask in enumerate(monthlytasks, start=1):
            change_task = request.form.get(f'pmreq-monthly-task-input-{i}')
            Frequency = 'Monthly'
            if change_task and change_task != monthlytask[4]:
                update_models = PM_form.query.filter_by(Model=Model, Form_Order=i, Frequency=Frequency).first()
                if update_models:
                    update_models.Task = change_task
                    db.session.commit()
            if not change_task and change_task != monthlytask[4]:
                PM_form.query.filter_by(Model=Model, Frequency='Monthly', Form_Order=i).delete()
                db.session.commit()
                create_audit = emsAudit(
                    Scope=Model,
                    EventType='modelModify',
                    InitiatedBy=session.get('username'),
                    EventDetails=f"Monthly task deleted: {dailytask[4]}."
                )
                db.session.add(create_audit)
                db.session.commit()
        ###Add new monthly tasks that were submitted.###
        for key in request.form.keys():
            if key.startswith('pmreq-monthly-task-new-'):
                new_task = request.form.get(key)
                tasknum = key.split('-')[4]
                ###Ensure empty tasks are not added to database.###
                if new_task:
                    create_task = PM_form(
                        Model=Model,
                        Frequency='Monthly',
                        Form_Order=tasknum,
                        Task=new_task
                    )
                    db.session.add(create_task)
                    db.session.commit()
                    create_audit = emsAudit(
                        Scope=Model,
                        EventType='modelModify',
                        InitiatedBy=session.get('username'),
                        EventDetails=f"New Monthly task created: {new_task}."
                    )
                    db.session.add(create_audit)
                    db.session.commit()
        ###Update quarterly tasks if changed.###
        for i, quarterlytask in enumerate(quarterlytasks, start=1):
            change_task = request.form.get(f'pmreq-quarterly-task-input-{i}')
            Frequency = 'Quarterly'
            if change_task and change_task != quarterlytask[4]:
                update_models = PM_form.query.filter_by(Model=Model, Form_Order=i, Frequency=Frequency).first()
                if update_models:
                    update_models.Task = change_task
                    db.session.commit()
            if not change_task and change_task != quarterlytask[4]:
                PM_form.query.filter_by(Model=Model, Frequency='Quarterly', Form_Order=i).delete()
                db.session.commit()
                create_audit = emsAudit(
                    Scope=Model,
                    EventType='modelModify',
                    InitiatedBy=session.get('username'),
                    EventDetails=f"Quarterly task deleted: {dailytask[4]}."
                )
                db.session.add(create_audit)
                db.session.commit()
        ###Add new quarterly tasks that were submitted.###
        for key in request.form.keys():
            if key.startswith('pmreq-quarterly-task-new-'):
                new_task = request.form.get(key)
                tasknum = key.split('-')[4]
                ###Ensure empty tasks are not added to database.###
                if new_task:
                    create_task = PM_form(
                        Model=Model,
                        Frequency='Quarterly',
                        Form_Order=tasknum,
                        Task=new_task
                    )
                    db.session.add(create_task)
                    db.session.commit()
                    create_audit = emsAudit(
                        Scope=Model,
                        EventType='modelModify',
                        InitiatedBy=session.get('username'),
                        EventDetails=f"New Quarterly task created: {new_task}."
                    )
                    db.session.add(create_audit)
                    db.session.commit()
        ###Update annual tasks if changed.###
        for i, annualtask in enumerate(annualtasks, start=1):
            change_task = request.form.get(f'pmreq-annual-task-input-{i}')
            Frequency = 'Annual'
            if change_task and change_task != annualtask[4]:
                update_models = PM_form.query.filter_by(Model=Model, Form_Order=i, Frequency=Frequency).first()
                if update_models:
                    update_models.Task = change_task
                    db.session.commit()
            if not change_task and change_task != annualtask[4]:
                PM_form.query.filter_by(Model=Model, Frequency='Annual', Form_Order=i).delete()
                db.session.commit()
                create_audit = emsAudit(
                    Scope=Model,
                    EventType='modelModify',
                    InitiatedBy=session.get('username'),
                    EventDetails=f"Annual task deleted: {dailytask[4]}."
                )
                db.session.add(create_audit)
                db.session.commit()
        ###Add new annual tasks that were submitted.###
        for key in request.form.keys():
            if key.startswith('pmreq-annual-task-new-'):
                new_task = request.form.get(key)
                tasknum = key.split('-')[4]
                ###Ensure empty tasks are not added to database.###
                if new_task:
                    create_task = PM_form(
                        Model=Model,
                        Frequency='Annual',
                        Form_Order=tasknum,
                        Task=new_task
                    )
                    db.session.add(create_task)
                    db.session.commit()
                    create_audit = emsAudit(
                        Scope=Model,
                        EventType='modelModify',
                        InitiatedBy=session.get('username'),
                        EventDetails=f"New Annual task created: {new_task}."
                    )
                    db.session.add(create_audit)
                    db.session.commit()
        ###Update Manufacturer if changed.###
        if new_manufacturer and new_manufacturer != Manufacturer:
            update_models = EquipModels.query.filter_by(Model=Model).first()
            if update_models:
                update_models.Manufacturer = new_manufacturer
                db.session.commit()
            create_audit = emsAudit(
                Scope=Model,
                EventType='modelModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"Manufacturer changed from {Manufacturer} to {new_manufacturer}."
            )
            db.session.add(create_audit)
            db.session.commit()
        ###Update Class if changed.###
        if new_equipmentclass and new_equipmentclass != Equipment_Class:
            update_models = EquipModels.query.filter_by(Model=Model).first()
            if update_models:
                update_models.Equipment_Class = new_equipmentclass
                db.session.commit()
            create_audit = emsAudit(
                Scope=Model,
                EventType='modelModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"Equipment_Class changed from {Equipment_Class} to {new_equipmentclass}."
            )
            db.session.add(create_audit)
            db.session.commit()
        if bool(new_modelActive) != bool(modelActive):
            update_models = EquipModels.query.filter_by(Model=Model).first()
            if update_models:
                update_models.modelActive = new_modelActive
                db.session.commit()
            create_audit = emsAudit(
                Scope=Model,
                EventType='modelModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"modelActive changed from {modelActive} to {new_modelActive}."
            )
            db.session.add(create_audit)
            db.session.commit()
        ###Update Model if changed.###
        if new_model and new_model != Model:
            update_models = EquipModels.query.filter_by(Model=Model).first()
            if update_models:
                update_models.Model = new_model
                db.session.commit()
            create_audit = emsAudit(
                Scope=Model,
                EventType='modelModify',
                InitiatedBy=session.get('username'),
                EventDetails=f"Model changed from {Model} to {new_model}."
            )
            db.session.add(create_audit)
            db.session.commit()
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
