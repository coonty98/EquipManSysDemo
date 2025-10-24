# Introduction

The purpose of this project is to replace the current equipment preventive maintenance process and asset tracking. Currently, a different excel spreadsheet is used for every machine in the company. These are used to document the daily, weekly, and monthly maintenance being performed. There is also a separate asset log to track equipment at each location. I wanted to create something that was unified and made it easier to document preventive maintenance. With this app, users can easily see tasks that have not been completed. This can also be used for reporting and will allow necessary reports to be generated for the compliance team and external audits. Power BI can be used for even deeper reporting and visualizations in future developments.

---

# Create Records Script

After building the database, I needed a way to generate the records that would be used for the app. I decided to create a script that is intended to run on a server once daily. This script creates records within the specified date ranges. The logic is a bit complex and could probably be simplified so that it is a little cleaner, but this is the high-level overview. The script iterates through the different frequencies, then iterates through all equipment where there is not a record within the specified date range. The logic branches to obtain the record number to be used for the record creation in the current iteration. It gets the last record for the lab of the equipment in the iteration, then increments by one and returns to the main function where the record is finally created.

---

# HTML Page Details

## login.html

This page began as a simple login form. I had a register.html to create an account which would generate a password hash and save it in the database. The login form would check this hash and redirect to index.html if it matched. Once I added user creation logic to the ‘users’ page, I removed register.html. Later, I added the below functionality:

- Lock user account after 3 invalid login attempts
- Perform checks before checking password hash such as user status and password change required
- If password change is required, then redirect to password\_change.html
- Authentication with Microsoft. See [OAuth](#oauth)

Within the login route, a check is performed to compare the last\_pwd\_chg date with the current date. There is also an environment variable for length of time before passwords expire so that it can be easily changed without needing to re-deploy the app. If the last password change exceeds that number, then the route redirects to password\_change.html.

## password\_change.html

This page is a simple form to allow a user to change their password. The code includes validation to ensure only strong passwords are created. I also added functionality to toggle password visibility. The list of password requirements is displayed as well. I used JavaScript to dynamically change the color of these requirements to indicate when they are met as the user is typing. Once the password change is complete, it redirects back to login.

## index.html

Upon successful login, the user is redirected to this page. This page is the primary purpose of the app. It displays the records in separate tables for each frequency. Using CSS, limited the size of the tables and allowed scrolling to prevent the web page from getting too large with hundreds of records. When the user opens a record, a modal pops up and displays the required tasks with checkboxes. Upon submission, the record is marked complete along with the username and completion date/time. The form results are also saved in a table.

Before I had a modal, I used a separate formresult.html to display the form for the opened record. When I learned about modals, I felt that this would contribute to an improved user experience. I then used these modals for all other forms except for the modify\_models form where there was too much information to display in a single modal.

> []()
> ##### **Permissions**
>
> - Administrator
>
>   - Read-Write; can see all records for every lab.
>   - The lab filter includes all labs.
> - Global Audit
>
>   - Read-Only; can see all records for every lab.
>   - The lab filter includes all labs.
> - Manager
>
>   - Read-Write; can see records for current lab.
>   - The lab filter only shows current lab.
> - Local Audit
>
>   - Read-Only; can see records for current lab.
>   - The lab filter only shows current lab.
> - Technician
>
>   - Read-Write; can see records for current lab.
>   - The lab filter only shows current lab.

## manage.html

This page displays equipment and allows admins and managers to add and edit equipment. This could even be used to “transfer” equipment to another lab by changing the LabID. The status is expected to be updated when needed. For example, if the machine is in repair, then the status needs to reflect that. Any equipment that is obsolete is hidden from the table and the view can be toggled to show hidden items.

> []()
> ##### **Permissions**
>
> - Administrator
>
>   - Read-Write; can see all equipment for every lab.
>   - The lab filter includes all labs.
>   - Can edit and add equipment.
> - Global Audit
>
>   - Read-Only; can see all equipment for every lab.
>   - The lab filter includes all labs.
>   - Can only view, unable to edit or add equipment.
> - Manager
>
>   - Read-Write; can see equipment for current lab.
>   - The lab filter only shows current lab.
>   - Can edit and add equipment.
> - Local Audit
>
>   - Read-Only; can see equipment for current lab.
>   - The lab filter only shows current lab.
>   - Can only view, unable to edit or add equipment.
> - Technician
>
>   - No access.

## models.html

This page displays a table of all equipment models. The view can be toggled to show disabled models and also allows admins to create new models. When the view button is clicked for a model, the modify\_models.html is opened.

> []()
> ##### **Permissions**
>
> - Administrator
>
>   - Read-Write; can see all models.
>   - Can add models.
> - Global Audit
>
>   - Read-Only; can see all models.
>   - Can only view, unable to add models.
> - Manager
>
>   - Read-Only; can see all models.
>   - Can only view, unable to add models.
> - Local Audit
>
>   - Read-Only; can see all models.
>   - Can only view, unable to add models.
> - Technician
>
>   - No access.

## modify\_models.html

This page displays the model details when a model is opened from models.html. Only and admin is able to edit the details in a model. The purpose of this page is to allow an admin to create new tasks as needed. For example, if in the future, it was decided that an annual calibration is required for a certain model, then an admin would enable the annual frequency and add a task for “Calibration” or other appropriate name.

> Currently, there is no logic to create records outside of the daily script. I’m not sure if this will ultimately be necessary, but I may add it in a future enhancement.
{.is-warning}

> []()
> ##### **Permissions**
>
> - Administrator
>
>   - Read-Write; can modify model details.
> - Global Audit
>
>   - Read-Only; can view model details.
> - Manager
>
>   - Read-Only; can view model details.
> - Local Audit
>
>   - Read-Only; can view model details.
> - Technician
>
>    - No access.

## users.html

This page displays a table with users along with the ability to create users and toggle disabled users. Each user can be opened to modify the user details. Part of this is a feature to change the password and set the require\_pwd\_chg value. The idea with that, is if a user forgets their password, they can go to their manager who will set a temporary password. When the user logs in with that password, they will be redirected to the password\_change.html. This is also where the manager would go to unlock the user if they lock themselves out. They can simply change the status from ‘Locked’ to ‘Active’. The ‘Disabled’ status is intended to be set when a user is terminated or no longer needs access to the app. I decided against deleting users because this would prevent reports from being run since those would need to query the users table.

The second half of the user details modal displays the lab access for that user. The purpose is to give a user access to other labs so they can assist. Admins can see all labs and access levels while managers can only see labs they have access to and access levels at Manager and below.

> The feature of adding lab access may not be necessary so I might remove it. Also, when logging in with Microsoft, only one lab is available. If I want to expand the functionality, I would need to create a lot more security groups in Azure.
{.is-warning}

> []()
> ##### **Permissions**
>
> - Administrator
>
>   - Read-Write; can see all users at all labs.
>   - Can add/edit users.
>   - Can assign users to any lab with any permissions.
> - Global Audit
>
>   - Read-Only; can see all users at all labs.
>   - Can only view users, unable to add/edit.
> - Manager
>
>   - Read-Write; can see users at labs they have access to, excluding Admins and Global Audit.
>   - Can add users at labs they have access to.
>   - Can edit all details for users whose primary lab is the current session’s lab.
>   - Can edit only password and status for users whose primary lab is different than the current session’s lab.
>   - Can assign lab access to users for labs the manager has access to. Can only assign Manager, Local Audit, and Technician access.
> - Local Audit
>
>   - Read-Only; can see users at current lab, excluding Admins and Global Audit.
>   - Can only view users, unable to add/edit.
> - Technician
>
>   - No access.

## reports.html

I don’t yet know what direction I want to take this page. I set up SQL Server Reporting Services and began trying out report creation with Visual Studio. Ultimately, I believe Power BI will be used for running reports and adding visualizations. If set up properly, I could remove the audit permissions from my app since the compliance team would no longer need direct access to the app.

---

# Auditing

When I began adding functionality for adding/modifying models/equipment/users, I decided to implement auditing as well. At first, I used a helper function in logic[]().py that I could call in the main app. I passed parameters for the values needed then used several if/elif statements to build the event descriptions for the INSERT statement based on what variables were not null. Later, I realized that this wasn’t very scalable and presented potentials issues since it relied on variables being empty or not. There was simply too much room for error. I then changed the helper function to only require 2 variables, method and auditdata. The method was an integer that indicated different audit events such as new user created or model modified. The auditdata variable was a dictionary of the necessary data to pass to the function to build the event description. Once I integrated SQLAlchemy, I changed all of the audit function calls to use SQLAlchemy. This added extra lines to the main code, but ultimately it was better since it is now easier to see exactly what is going into the audit event and it can be changed if needed.

---

# Security

This section describes the various security measures and vulnerability mitigations I have utilized in my project.

## Tokens

This was the first security measure that I used in this project. While I was creating the formsubmit.html page, I noticed that the URL was displaying the parameters such as the record number. This would let users manipulate the URL and potentially submit forms incorrectly. To fix this, I learned about session tokens. Instead of the route redirecting to the formsubmit.html page, it would redirect to a route that creates the token based on the supplied parameters, then save the token in the session. I used these tokens to pass data to my HTML and JavaScript as well as to save data important for the user session.

## CSRF

As I understand it, Cross-Site Request Forgery is a way for attackers to trick a browser into submitting POST requests using the users’s session since they are authenticated. To mitigate this risk, I am using Flask-WTF CSRF protection. In my Flask app, I enabled CSRF protection globally which ensures that all requests require a valid CSRF token.

```py
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)
```

In my HTML forms, I include a hidden input field with the CSRF token which is checked by Flask-WTF upon submission.

```html
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

I include the CSRF token in a meta tag in the HTML page so that JavaScript can access it.

```html
<meta name="csrf-token" content="{{ csrf_token() }}">
```

In my JavaScript, I then fetch the CSRF token from the meta tag and send it in the X-CSRFToken header for AJAX requests.

```js
function fetchWithCSRF(url, options = {}) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    return fetch(url, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken,
            ...(options.headers || {})
        }
    });
}
```

## CORS

Cross-Origin Resource Sharing is used by browsers. This controls how a web page in one domain can access resources in another domain. This is blocked by default, but can be enabled through CORS. By using CORS in my app, I can specify what domains are allowed to access resources within my server. By using CORS(App) I allow any website to make requests by adding the appropriate CORS headers such as ‘Access-Control-Allow-Origin:\*’. In production, I should restrict CORS to my frontend domain if it is on a different domain or port from my server:

```py
CORS(app, origins=["https://frontenddomain.com"])
```

## HTTPS Redirect

This feature protects against attacks such as Man-In-The-Middle by requiring secure HTTPs protocol instead of HTTP. In my code, I check if the request is HTTP then redirect to HTTPS. Azure App Service and other platforms use the X-Forwarded-Proto header to hold the protocol. In my code, I get this header, then replace http in the URL with https and redirect with a 301 code to ensure the user permanently uses HTTPS.

## Security Headers

By using these, I protect against different vulnerabilities such as XSS, clickjacking, and content sniffing. Below are the headers I have added:

- Content-Security-Policy (CSP)

  - Restricts where resources can be loaded from. I use this to ensure I can only load scripts and styles from my own domain.
  - When I enabled this, my app stopped functioning because I had inline scripts and inline styles. To fix this temporarily, I set the CSP to allow scripts and styles from ‘self’ and ‘unsafe-inline’. Once I removed the inline scripts/styles, I removed ‘unsafe-inline’.
  - This prevents XSS attacks.
- X-Content-Type-Options

  - By setting this to ‘nosniff’, this ensures that a browser will implicitly trust the declared type without guessing.
  - This prevents MIME-Type confusion attacks
- X-Frame-Options

  - By setting this to ‘DENY’, it ensures my site cannot be loaded within an iFrame.
  - Protects against clickjacking attacks.
- Referrer-Policy

  - By setting this to 'strict-origin-when-cross-origin', it restricts how much referrer info is sent with requests.
  - This protects user privacy.

## Cross Site Scripting (XSS)

This security vulnerability allows an attacker to inject malicious scripts into web pages so they can steal cookies, hijack sessions, deface websites, or redirect users to malicious sites. Below are the different ways I mitigate this risk in my project:

- Template Auto-Escaping

  - In Flask Jinja2 templates, variables are auto-escaped by default. This means that special characters like “<, >, “ “ are converted to safe HTML entities.
  - ```html
    <div>{{ username }}</div>

    <!-- In this example, if the username is entered as: -->
    <script>alert(1)</script>
    <!-- Then it will be converted to plaintext instead of being used as a script. -->
    ```
- Content-Security-Policy

  - See [CSP](#csp)
- No untrusted HTML injection

  - I ensure that raw user input is not rendered as HTML

## Validation and Sanitization

In my app I do not explicitly trust client-side validation. I make sure to validate input server-side as well as sanitize data. Examples of this include the use of Flask-WTF and SQLAlchemy.

## SQL Injection

See [SQLAlchemy](#sqlalchemy)

## Access Control

I used access control throughout my project, both in frontend and backend. First, I made sure each Flask route required the user to be logged in, so I created a login-required decorator that could easily be added to each route. I then created a decorator for managing access requirements for specific routes. For example, the Users route requires Administrator, Manager, Global Audit, or Local Audit access. Since I used a decorator, I can easily modify access. I also use access control with Jinja 2 in my HTML pages to show/hide the navigation links and modify behavior of some elements. In my JavaScript code, I use access control to modify certain behavior. For example, only Administrators can modify equipment models while Managers, Global Audit, and Local Audit can only view the data. So, I was able to disable or hide buttons to prevent modification.

> Currently, I only use frontend access control for read-only vs edit access. I may need to change the logic in my Flask routes to prevent modification if permission denied.
{.is-warning}

---

# Microsoft Authentication (OAuth)

Since the company uses Microsoft for authentication, I decided to integrate OAuth into my app. I added the app to Microsoft Entra ID in App Registrations. I then created different security groups that aligned with the access levels in the app. In the ‘auth/callback’ route, the required info is extracted from Microsoft, such as the groups and user info. The security groups are specifically named so that I can pull the lab and access level needed. This info is assigned to the appropriate session cookies. Just like the login route, this route also performs the necessary queries for labs, classes, etc. and saves them to the session. Upon logout, the user is redirected to the Microsoft logout endpoint, then returned back to the login page. For additional details, see [OAuth](#oauth)

---

# SQLAlchemy

At the start of this project, I did not consider vulnerabilities in my code. Later, I did a security review and found that I was at risk of SQL injection in several areas, including the SQL files and inline SQL. I was using string concatenation to build my queries, even in my helper functions in logic[]().py. To mitigate the risk of SQL injection, I learned about parameterization and subsequently modified all raw SQL to use this technique. While this technique protected my project from SQL injection, it wasn’t very scalable. I then looked into other solutions, which brought me to SQLAlchemy, specifically Flask-SQLAlchemy. I learned that the features include built-in parameterization and connection pooling which I figured would improve performance since this app relies very heavily on SQL queries. Prior to SQLAlchemy I had touched on this a little bit by created a helper function to create single connections. I found that I was opening/closing connections several times within most routes which would probably lock up the database at some point with dozens of users utilizing the app. Since SQLAlchemy manages the opening/closing of connections, I can remove all that from my code, as well as the helper function.

With the integration of SQLAlchemy, I have mixed feelings about its usefulness as it pertains to code cleanliness and simplicity. In many instances, it simplified the code where it replaced raw SQL. For example, 2-3 lines turned into 1 line. I can also see that it will make future changes easier because of how objects are assigned as variables. If I modify tables in the database, it will also be easier to integrate those changes in my code. Where things get complex is the more complex SQL queries, specifically in the “get” functions where I use joins then transform the results into dictionaries to be used in the JSON for the frontend. The more of these I did, the easier it got as I understood it better, so I think with more practice I will see the benefits more clearly.

---

# Demo

My project has now reached a point where I can share it with others. In fact, it is ready to go to production as a first version. I needed a way to deploy a demo version so that others can try it out publicly. With my knowledge of Azure, I thought that would be a good start, but it can be costly. I researched the cost of the services I would need and eventually found that I could make it work for a minimal cost as long as I limit usage. Now that I identified the platform, it was time to build the demo.

### SQL Server

I started with migrating my SQL Server database to azure. I chose Azure SQL Server with DTU-based usage. This was the cheapest option. What I discovered later during testing was that this tier contributes to very slow performance. It’s fine for a demo but would be wholly inadequate for any production solution. Once I created the SQL Server resource, I provisioned a SQL database. I then used Azure Data Studio on my local machine to access the database and replicate my current SQL Server database. To simplify this process, I used SSMS to generate the “CREATE TO” queries for each table. I put these together into a single query, copied it to Azure Data Studio and ran the query to create all required tables in my database. I then added the base data such as Frequency, UserStatus, Access, etc. I also added some sample data to all tables instead of using any confidential or proprietary info.

> []()
> #### Problems
>
> When I was trying to create my database in Azure, I kept getting an error that the resource could not be created due to subscription limits. I didn’t target the source of the issue, but I thought it may be caused by the SQL server database through Azure Arc. So, I attempted creating the resource in a different region which was successful.
{.is-danger}

### App Service

After the SQL database was created, it was time to provision the app service and webapp. Provisioning was the easy part. Next, I had to prepare my code for deployment. The first step of this was to prepare my environment variables, including the SQL Server authentication info and Flask environment info. I added all necessary environment variables to the app service environment variables setting, then modified my code to use them. The last step was to deploy using the Azure CLI in PowerShell, which is where I ran into issues.

#### Azure CLI Commands

##### Deploy Code

```powershell
az webapp up --name <app-name> --resource-group <resource-group-name> --runtime <runtime>
```

##### View Logs

```powershell
az webapp log tail --name <your-app-name> --resource-group <your-resource-group>
```

> []()
> #### Problems
>
>  I could not deploy because the resource group was not found. After listing the resource groups, I found that the CLI was using the wrong subscription. After changing the default subscription, I was able to deploy successfully.
> 
>  Once deployed, the webapp would not open. Using the logs, I found that the flask session secret was empty. The issue was where the secret was being called in my code. I needed to move it so that it would be called in the beginning before the environment was set.
>
>  After fixing the issue of the session secret, the logs showed another error where ‘timedelta’ was not defined. I had mistakenly removed ‘import timedelta’ prior to deploying.
>
>  When I fixed the session secret and timedelta issues, my app still would not open, and the logs showed the same errors. I eventually learned that the logs seem to be lagging behind. When I viewed the logs in Azure, it would start them from several minutes' prior, then repeat everything. I kept making code changes and redeploying and it seemed that the same errors would occur. I also found that I needed to navigate to the webapp to initiate the first build. This took a couple minutes, but once complete, as long as the app service remained in the running state, I could access the app right away.
{.is-danger}

### OAuth

When I deployed the app, I had commented out the OAuth logic just in case it was the cause of my previous errors. Once those were addressed, I proceeded to re-implement OAuth so that it would work for the webapp in a production environment. To do this, I had to modify the app registration in Microsoft Entra ID so that it used redirect URIs for my webapp, instead of just localhost.

I added functionality for users to choose to sign in with Microsoft from the login page. Before, it would automatically route to Microsoft login and bypass the login route. I added the button to the login page by using Microsoft’s requirements for the HTML/CSS. I then added a route that would be used specifically for this button, that way I could keep the normal login route, and have another login with Microsoft route. After verifying that I could log in both ways, I realized I needed a way to logout depending on how the user logged in. Before, it would just redirect to Microsoft logout. So, I added a session cookie for ‘ms\_login’ that was set at login. For normal login, this was set to false, and for Microsoft login it was set to true. Then, I was able to create a single logout route that would first check this session cookie and redirect to the login page or Microsoft page as needed.

> []()
> #### Problems
>
>  I still could not login using Microsoft which turned out to be because of HTTPS. My code was using HTTP, but the redirect URIs required HTTPS. The fix for this was to add the scheme in the routes depending on whether the environment was production or development
>
> ```py
> url_for('auth/callback', _external=True, _scheme='https'))
> ```
>
>  Whenever I logged out with Microsoft, it wouldn’t redirect back to my login screen, even though I had this set in my code. I actually needed to add a new redirect URI in Entra ID for “/login” so that it would logout, then redirect back to my login page.
{.is-danger}

### Custom Domain

Once my app was successfully deployed, I wanted to add my “tybax[]().com ” custom domain. This was easier said than done because it just showed errors or would get stuck on “Get Certificates”. These are the steps that ultimately proved successful:

> App Service must be running before creating certificates, otherwise it will fail.
{.is-warning}

1. Add custom domain in Azure App Service for equipmansys[]().tybax.com.
2. In GoDaddy, add the DNS records using info generated from Azure.

   1. asuid token
   2. CNAME for equipmansys subdomain
3. Check for DNS propagation using a tool such as <https://dnschecker.org/>
4. In **App Service > Certificates**, add a new managed certificate using the custom domain created in step 1. This should happen automatically but for me it was not, so I needed to do it manually.
5. In **App Service > Custom Domain**, add binding using the new certificate if it did not automatically bind.
6. In Entra ID app registrations, make sure to add new redirect URIs for this custom domain.
# Self-Host
In this section, I describe the process of deploying my demo locally using Docker.
## Dockerfile
Before I could deploy a Docker container, I needed to get my Flask app and environment set up. The first step was to create a Dockerfile that would build the image.
```docker
# syntax=docker/dockerfile:1
```
- This is a bit confusing, but essentially, it is needed for BuildKit when you use commands such as RUN. For now, I am just going to trust that it's needed and leave it at that.
```docker
FROM python:3.12-alpine3.21
```
- This describes the base image to be used.
- When I first tried building my image with this Dockerfile, I ran into an error with pip saying it could not find the version of Flask from my requirements.txt. This was because I had put python:3.8 which was outdated. I went on Docker Hub to find an image that was closer to the python version on my local pc.
```docker
WORKDIR /python-docker
```
- This indicates the directory inside the image where the rest of the commands will be run.
```docker
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
RUN pip3 install gunicorn
```
- This copies the requirements.txt file from the local directory to the directory indicated by `WORKDIR`.
- Then the pip3 command is called to install requirements.txt. and gunicorn (explained below).
```docker
COPY . .
```
- This will copy all remaining files from the local directory to the directory indicated by `WORKDIR`.
## Dockerfile Command {.tabset}
### Development
```docker
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0", "--port=5050"]
```
> Use this command for **DEVELOPMENT**. {.is-warning}
- This is the final command to be run in the image. It is calling the flask module from python3 and telling it to run. It is also binding the host ip address and changing the port from the default of 5000.
- When I ran this on my macbook without `--port=5050`, it did not work because port 5000 was already in use. When I used `lsof` I found that a system command was using that port so I decided to change to 5050.
### Production
```docker
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5050", "app:app"]
```
> Use this command for **PRODUCTION**. {.is-warning}
- Gunicorn is a production HTTP server that will run the flask app. In the command, `-w` `4` indicates 4 workers will be used.
- A worker is an individual process on the host that handles HTTP requests. The more workers you have, the more requests you can handle at one time.
- `-b` `0.0.0.0:5050` binds the port on localhost and `app:app` binds the flask app.

The completed Dockerfile is as follows:
```docker
# syntax=docker/dockerfile:1

FROM python:3.12-alpine3.21

WORKDIR /python-docker

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
RUN pip3 install gunicorn

COPY . .

# For DEVELOPMENT environment
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0", "--port=5050"]

# For PRODUCTION environment
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5050", "app:app"]
```
> Only 1 **CMD** command can be used. Add the command necessary for the environment. {.is-danger}

Once the Dockerfile is complete, build the new image:
```docker
docker build -t emsimage .
```
- `emsimage` is the tag name of the image.
- `.` indicates to build from the current directory.
## Docker Compose
The next step was to create the docker-compose.yml. Let's break it down:
```docker
services:
  EquipManSys:
    image: emsimage
    container_name: EquipManSys
    depends_on:
      emsdemoDB:
        condition: service_healthy
    ports:
      - "5050:5050"
```
- This first section defines a new service called `EquipManSys` using the image created from the Dockerfile, 'emsimage'.
- `container_name` is not required. If omitted, the service name will be used.
- `depends_on` tells Docker that this service needs another service to function, in this case, the database 'emsdemoDB'.
- `condition` is an extra parameter that will ensure the database returns a healthy status before the EquipManSys container starts.
- `ports` binds the local port 5050 to the container port 5050.
```docker
environment:
      MYSQL_HOST: emsdemoDB
      FLASK_ENV: development
      MYSQL_DATABASE_FILE: /run/secrets/mysql_database
      MYSQL_USER_FILE: /run/secrets/mysql_user
      MYSQL_PASSWORD_FILE: /run/secrets/mysql_password
      FLASK_SECRET_KEY_FILE: /run/secrets/flask_secret_key
      OAUTH_CLIENT_ID_FILE: /run/secrets/oauth_client_id
      OAUTH_CLIENT_SECRET_FILE: /run/secrets/oauth_client_secret
      PWD_CHG_DAYS_FILE: /run/secrets/pwd_chg_days
      SESSIONTIMEOUT_SEC_FILE: /run/secrets/sessionTimeout_sec
    secrets:
      - mysql_database
      - mysql_user
      - mysql_password
      - flask_secret_key
      - oauth_client_id
      - oauth_client_secret
      - pwd_chg_days
      - sessionTimeout_sec
```
- The environment variables will be passed into the container.
- `MYSQL_HOST` is important to ensure that the correct database is used.
- `FLASK_ENV` is used to easily toggle the flask environment between production and development
- The rest of the variables are secrets as defined by Docker's documentation. Instead of hard-coding credentials and other important info, secrets are a way to securely pass data into the container. Docker will copy the variable from a txt file and save it in **/run/secrets/**.
- `_FILE` is added to indicate the variable is stored inside a file.
```docker
emsdemoDB:
   image: mysql:8.0
   healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 10
   container_name: emsdemoDB
```
- Similar to the previous service, this contains a service name, image, and container_name. Additionally, there is a `healthcheck`. This is a test done to ensure the database is running and accessible. If so, it will return a healthy status.
```docker
environment:
    MYSQL_ROOT_PASSWORD_FILE: /run/secrets/mysql_root_password
    MYSQL_DATABASE_FILE: /run/secrets/mysql_database
    MYSQL_USER_FILE: /run/secrets/mysql_user
    MYSQL_PASSWORD_FILE: /run/secrets/mysql_password
   secrets:
    - mysql_root_password
    - mysql_database
    - mysql_user
    - mysql_password
```
- Same as the previous service.
```docker
volumes:
    - ./data:/var/lib/mysql
   ports:
    - "3306:3306"
   restart: always
```
- `volumes` contains the bind mounts. When `./` is used, the directory inside the container is bound to a directory on the local machine (in the current project folder), in this case 'data'.
- If `./` is omitted, the container volume will be bound to a directory inside the VM that runs Docker. This is more secure as it is not directly accessible on the host.
- The port for MYSQL is 3306.
- `restart: always` ensures that the container will restart if it ever stops for any reason.
```docker
secrets:
 mysql_root_password:
  file: ./secrets/mysql_root_password.txt
 mysql_password:
  file: ./secrets/mysql_password.txt
 mysql_database:
  file: ./secrets/mysql_database.txt
 mysql_user:
  file: ./secrets/mysql_user.txt
 flask_secret_key:
  file: ./secrets/flask_secret_key.txt
 oauth_client_id:
  file: ./secrets/oauth_client_id.txt
 oauth_client_secret:
  file: ./secrets/oauth_client_secret.txt
 pwd_chg_days:
  file: ./secrets/pwd_chg_days.txt
 sessionTimeout_sec:
  file: ./secrets/sessionTimeout_sec.txt

volumes:
 data:
```
- This section tells Docker where to find the files containing each secret.
- `volumes` indicates any volumes that are bound in the containers. This completes the docker compose file.
## Flask App
Now that the Docker environment is ready, the flask app can be prepared. I first had to remove the **.env** file and remove all references to it.
### Environment Variables
In **logic[]().py**, I added this helper function:
```python
def read_secret(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return None
```
This will extract the secret from the associated file in **/run/secrets**. Then in **app[]().py**, make sure to add:
```python
from logic import read_secret
```
Next, I added this line:
```python
app.env = os.getenv('FLASK_ENV')
```
This is where the production or development variable gets passed from the docker compose file. Then the other variables can be added:
```python
app.secret_key = read_secret(os.environ.get("FLASK_SECRET_KEY", "/run/secrets/flask_secret_key"))
```
Here, `FLASK_SECRET_KEY` is an ENV variable and `/run/secrets/flask_secret_key` is what we passed from docker compose and this is the default to be used. This is then passed into the **read_secret** function and assigned as the secret_key for the app.

All remaining environment variables were added the same way.
### SqlAlchemy Database URI
The last thing for **app[]().py** was to change the SqlAlchemy Database URI. This is the connection string used to connect to the database. Up until this point, I had been using Microsoft SQL Server, so now I needed to change the string to work with MySQL.

The most important part here is the driver which is used to facilitate the connection. Multiple drivers are available to use with MySQL, but I chose PyMySQL. Once installed, this can be used as the driver for SqlAlchemy.
```shell
pip install pymysql
```
>pymysql does not need to be imported as a package in the flask app since this is not used directly by the app. It only needs to be available in the environment for SqlAlchemy to use.
{.is-warning}

```python
app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mysql+pymysql://{db_username}:{db_password}@{db_server}:3306/{db_name}?charset=utf8mb4"
    )
```
`?charset=utf8mb4` is important to make sure all characters can be used. Otherwise, the default is UTF-8.
## Database Setup
At this point, I had a database on my local pc using SQL Server as well as a cloud database in Azure, but for the dockerization of my demo, I wanted everything packaged up neatly in containers. My goal was to make it more portable and easily customizable.

With that said, I already prepared the docker compose file with the MySQL container, so all that was left was to add all my tables and data. Since my demo database in Azure had the data I wanted to use, I needed a way to migrate to a MySQL database. Luckily, I found a tool that helped automate this process.

I downloaded ***ESF Database Migration Toolkit - Pro*** from the Microsoft store. The process was actually very simple. I entered the source and destination database information, selected the tables I wanted to migrate, and within a couple minutes my new database was a replica of the old.

>The caveat with this tool is when it's used in the trial version, it creates an extra field in each table for 'Trial', and it also only migrates 50,000 records per table. {.is-warning}
## Initial Deployment
The app is now ready to be deployed, but we will need to backtrack for a moment. Since we made modifications to **app[]().py** and **logic[]().py**, we will need to rebuild the image using the command from earlier. Once done, we can deploy with `docker compose up -d`.

In a browser, navigate to **localhost:5050** and the flask app should come up. In my case, I was working from a different computer, so I entered the IP address of the docker host instead of localhost. Once I verified the app was functional, I was ready to release to the public.
## 