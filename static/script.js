let logoutTimer;
let warningTimer;
const AUTO_LOGOUT_SECONDS = window.sessionTimeoutSeconds || 900; // Total inactivity time
const WARNING_BEFORE_LOGOUT_SECONDS = 60; // Show warning 60 seconds before logout

function showLogoutWarning(secondsLeft) {
    let modal = document.getElementById('logout-warning-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'logout-warning-modal';
        modal.className = 'modal';
        const contentDiv = document.createElement('div');
        contentDiv.className = 'modal-content';
        contentDiv.style.textAlign = 'center';
        const paragraph = document.createElement('p');
        const span = document.createElement('span');
        span.id = 'logout-countdown';
        span.textContent = secondsLeft;
        paragraph.appendChild(document.createTextNode('You will be logged out in '));
        paragraph.appendChild(span);
        paragraph.appendChild(document.createTextNode(' seconds due to inactivity.'))
        const button = document.createElement('button');
        button.id = 'continue-session-btn';
        button.textContent = 'Continue Session';
        contentDiv.appendChild(paragraph);
        contentDiv.appendChild(button);
        modal.appendChild(contentDiv);
        document.body.appendChild(modal);
    }
    modal.style.display = 'block';
    document.getElementById('logout-countdown').textContent = secondsLeft;
    document.getElementById('continue-session-btn').onclick = function() {
        modal.style.display = 'none';
    };
}

function startWarningCountdown() {
    let secondsLeft = WARNING_BEFORE_LOGOUT_SECONDS;
    showLogoutWarning(secondsLeft);
    warningTimer = setInterval(() => {
        secondsLeft--;
        document.getElementById('logout-countdown').textContent = secondsLeft;
        if (secondsLeft <= 0) {
            clearInterval(warningTimer);
            window.location.href = '/logout';
        }
    }, 1000);
}

function resetLogoutTimer() {
    clearTimeout(logoutTimer);
    clearInterval(warningTimer);
    const modal = document.getElementById('logout-warning-modal');
    if (modal) modal.style.display = 'none';
    logoutTimer = setTimeout(() => {
        startWarningCountdown();
    }, (AUTO_LOGOUT_SECONDS * 1000) - (WARNING_BEFORE_LOGOUT_SECONDS * 1000));
}

function formatDate(dateStr) {
    if (!dateStr) return '';
    const d = new Date(dateStr);
    if (isNaN(d)) return dateStr;
    // Use UTC methods to avoid timezone shift
    const weekday = d.toLocaleDateString('en-US', { weekday: 'short', timeZone: 'UTC' });
    const day = d.getUTCDate(); // No leading zero
    const month = d.toLocaleDateString('en-US', { month: 'short', timeZone: 'UTC' });
    const year = d.getUTCFullYear();
    return `${weekday}, ${day} ${month} ${year}`;
}

function handleEmptyTable(tableId, frequency) {
    const table = document.getElementById(tableId);
    const tableContainer = table.closest('.table-container');
    const tableBody = table.querySelector('tbody');
    const tableHead = table.querySelector('thead');
    const emptyMessage = document.createElement('div');
    emptyMessage.className = 'empty-table-message';
    emptyMessage.innerHTML = `<p>No ${frequency} PMs are currently due.</p>`;
    
    // If no rows or only hidden rows
    const visibleRows = Array.from(tableBody.querySelectorAll('tr')).filter(row => 
        row.style.display !== 'none');
        
    if (tableBody.children.length === 0 || visibleRows.length === 0) {
        // Hide the table headers
        tableHead.style.display = 'none';
        
        // Show message if not already there
        if (!tableContainer.querySelector('.empty-table-message')) {
            tableContainer.appendChild(emptyMessage);
        }
    } else {
        // Show the table headers
        tableHead.style.display = '';
        
        // Remove message if it exists
        const existingMessage = tableContainer.querySelector('.empty-table-message');
        if (existingMessage) {
            existingMessage.remove();
        }
    }
}

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

function fetchPMs(frequency, selectedLab, selectedClass, tableId) {
    fetchWithCSRF('/get_PMs_due', {
        method: 'POST',
        body: JSON.stringify({ frequency, labid: selectedLab, class: selectedClass })
    })
    .then(response => response.json())
    .then(data => {
        const tableBody = document.querySelector(`#${tableId} tbody`);
        tableBody.innerHTML = ''; // Clear is fine here as we're not inserting user data
        
        data.results.forEach(item => {
            const row = document.createElement('tr');
            
            // Cell 1: Record Number with button
            const cell1 = document.createElement('td');
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'open-formsubmit-modal';
            button.dataset.record_num = item.Record_Num;
            button.dataset.model = item.Model;
            button.textContent = item.Record_Num;
            cell1.appendChild(button);
            
            // Cell 2: Lab ID
            const cell2 = document.createElement('td');
            cell2.textContent = item.LabID;
            
            // Cell 3: Serial Number
            const cell3 = document.createElement('td');
            cell3.textContent = item.Serial_Num;
            
            // Cell 4: Model
            const cell4 = document.createElement('td');
            cell4.textContent = item.Model;
            
            // Cell 5: Equipment Class
            const cell5 = document.createElement('td');
            cell5.textContent = item.Equipment_Class;
            
            // Cell 6: Due Date Start
            const cell6 = document.createElement('td');
            cell6.textContent = formatDate(item.Due_Date_Start);
            
            // Cell 7: Due Date End
            const cell7 = document.createElement('td');
            cell7.textContent = formatDate(item.Due_Date_End);
            
            // Add all cells to the row
            row.appendChild(cell1);
            row.appendChild(cell2);
            row.appendChild(cell3);
            row.appendChild(cell4);
            row.appendChild(cell5);
            row.appendChild(cell6);
            row.appendChild(cell7);
            
            // Add row to table
            tableBody.appendChild(row);
            
            // Add event listener directly to the button
            button.addEventListener('click', function() {
                openFormSubmitModal({
                    record_num: this.dataset.record_num,
                    model: this.dataset.model
                });
            });
        });

        // Apply permissions after creating the DOM elements
        const forms = document.getElementsByClassName('table-container');
        const sessionAccessLevel = window.sessionAccessLevel;
        const canEdit = (sessionAccessLevel === 'Administrator' || 
                         sessionAccessLevel === 'Manager' || 
                         sessionAccessLevel === 'Technician');

        Array.from(forms).forEach(form => {
            const formInputs = form.querySelectorAll('button');
            formInputs.forEach(input => {
                const exclude = [];
                if (!exclude.includes(input.id)) {
                    input.disabled = !canEdit;
                }
            });
        });

        // Check if table is empty and handle accordingly
        handleEmptyTable(tableId, frequency);
    })
    .catch(error => { 
        console.error('Error:', error); 
        handleEmptyTable(tableId, frequency);
    });
}

function fetchAllPMs(selectedLab, selectedClass) {
    fetchPMs('Daily', selectedLab, selectedClass, 'daily-pm-table');
    fetchPMs('Weekly', selectedLab, selectedClass, 'weekly-pm-table');
    fetchPMs('Monthly', selectedLab, selectedClass, 'monthly-pm-table');
    fetchPMs('Quarterly', selectedLab, selectedClass, 'quarterly-pm-table');
    fetchPMs('Annual', selectedLab, selectedClass, 'annual-pm-table');
}

function filterPMTables(searchTerm) {
    searchTerm = searchTerm.toLowerCase();
    const tableIds = [
        'daily-pm-table',
        'weekly-pm-table',
        'monthly-pm-table',
        'quarterly-pm-table',
        'annual-pm-table'
    ];
    const frequencies = [
        'Daily',
        'Weekly',
        'Monthly',
        'Quarterly',
        'Annual'
    ];

    tableIds.forEach(tableId => {
        const table = document.getElementById(tableId);
        if (!table) return;
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            const rowText = row.textContent.toLowerCase();
            row.style.display = rowText.includes(searchTerm) ? '' : 'none';
        });

        // Check if all rows are now hidden after filtering
        handleEmptyTable(tableId, frequencies[index]);
    });
}

function fetchUsersWrapper(inactiveUserToggle) {
    let selectedLab = document.getElementById('lablist').value;
    // Only allow "All Labs" for Administrators
    if (window.sessionAccessLevel === 'Manager') {
        selectedLab = window.sessionLabID;
    }
    fetchUsers(selectedLab, inactiveUserToggle);
}

function fetchUsers(selectedLab, inactiveUserToggle) {
    fetchWithCSRF('/get_users', {
        method: 'POST',
        body: JSON.stringify({ labid: selectedLab, inactiveusertoggle: inactiveUserToggle })
    })
    .then(response => response.json())
    .then(data => {
        const userTable = document.querySelector('#users-table tbody');
        userTable.innerHTML = ''; // Clear previous rows
        data.results.forEach(item => {
            const row = document.createElement('tr');

            const cell1 = document.createElement('td');
            cell1.textContent = item.username;
            const cell2 = document.createElement('td');
            cell2.textContent = item.access_level;
            const cell3 = document.createElement('td');
            cell3.textContent = item.FirstName + ' ' + item.LastName;
            const cell4 = document.createElement('td');
            cell4.textContent = item.PrimaryLab;
            const cell5 = document.createElement('td');
            cell5.textContent = item.LastLoginDate;
            const cell6 = document.createElement('td');
            cell6.textContent = item.userStatus;
            const cell7 = document.createElement('td');
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'open-user-modal';
            button.dataset.token = item.token;
            button.dataset.username = item.username;
            button.dataset.access_level = item.access_level;
            button.dataset.firstname = item.FirstName;
            button.dataset.lastname = item.LastName;
            button.dataset.labaccess = item.lab_access;
            button.dataset.primarylab = item.PrimaryLab;
            button.dataset.userstatus = item.userStatus;
            button.dataset.require_pwd_chg = item.require_pwd_chg;
            button.textContent = 'Modify';
            cell7.appendChild(button);

            row.appendChild(cell1);
            row.appendChild(cell2);
            row.appendChild(cell3);
            row.appendChild(cell4);
            row.appendChild(cell5);
            row.appendChild(cell6);
            row.appendChild(cell7);

            userTable.appendChild(row);

            button.addEventListener('click', function() {
                openUserModal({
                    token: this.dataset.token,
                    username: this.dataset.username,
                    access_level: this.dataset.access_level,
                    FirstName: this.dataset.firstname,
                    LastName: this.dataset.lastname,
                    lab_access: this.dataset.lab_access,
                    PrimaryLab: this.dataset.primarylab,
                    userStatus: this.dataset.userstatus,
                    require_pwd_chg: this.dataset.require_pwd_chg
                });
            })
        });

        const form = document.getElementById('users-table');
        const sessionAccessLevel = window.sessionAccessLevel;
        const canEdit = (sessionAccessLevel === 'Administrator' || sessionAccessLevel === 'Manager' || sessionAccessLevel === 'Technician');

        const formInputs = form.querySelectorAll('button');
        formInputs.forEach(input => {
            const exclude = [];
            if (!exclude.includes(input.id)) {
                input.disabled = !canEdit;
            }
        });
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function fetchEquipment(selectedLab, selectedClass, inactiveToggle) {
    fetchWithCSRF('/get_equipment', {
        method: 'POST',
        body: JSON.stringify({ labid: selectedLab, class: selectedClass, inactivetoggle: inactiveToggle })
    })
    .then(response => response.json())
    .then(data => {
        const equipmentTable = document.querySelector('#equipment-table tbody');
        equipmentTable.innerHTML = ''; // Clear previous rows
        data.results.forEach(item => {
            const row = document.createElement('tr');
            const cell1 = document.createElement('td');
            cell1.textContent = item.Serial_Num;
            const cell2 = document.createElement('td');
            cell2.textContent = item.Model;
            const cell3 = document.createElement('td');
            cell3.textContent = item.Manufacturer;
            const cell4 = document.createElement('td');
            cell4.textContent = item.Equipment_Class;
            const cell5 = document.createElement('td');
            cell5.textContent = item.LabID;
            const cell6 = document.createElement('td');
            cell6.textContent = formatDate(item.Created_Date);
            const cell7 = document.createElement('td');
            cell7.textContent = item.PM_Req_Daily ? '✔' : '✗';
            const cell8 = document.createElement('td');
            cell8.textContent = item.PM_Req_Weekly ? '✔' : '✗';
            const cell9 = document.createElement('td');
            cell9.textContent = item.PM_Req_Monthly ? '✔' : '✗';
            const cell10 = document.createElement('td');
            cell10.textContent = item.PM_Req_Quarterly ? '✔' : '✗';
            const cell11 = document.createElement('td');
            cell11.textContent = item.PM_Req_Annual ? '✔' : '✗';
            const cell12 = document.createElement('td');
            cell12.textContent = item.equipStatus;
            const cell13 = document.createElement('td');
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'open-modify-modal';
            button.dataset.token = item.token;
            button.dataset.serial = item.Serial_Num;
            button.dataset.labid = item.LabID;
            button.dataset.model = item.Model;
            button.dataset.status = item.equipStatus;
            button.textContent = 'Modify';
            cell13.appendChild(button);

            row.appendChild(cell1);
            row.appendChild(cell2);
            row.appendChild(cell3);
            row.appendChild(cell4);
            row.appendChild(cell5);
            row.appendChild(cell6);
            row.appendChild(cell7);
            row.appendChild(cell8);
            row.appendChild(cell9);
            row.appendChild(cell10);
            row.appendChild(cell11);
            row.appendChild(cell12);
            row.appendChild(cell13);

            equipmentTable.appendChild(row);

            button.addEventListener('click', function() {
                openModifyModal({
                    token: this.dataset.token,
                    Serial_Num: this.dataset.serial,
                    LabID: this.dataset.labid,
                    Model: this.dataset.model,
                    equipStatus: this.dataset.status
                });
            });
        });

        const form = document.getElementById('equipment-table');
        const sessionAccessLevel = window.sessionAccessLevel;
        const canEdit = (sessionAccessLevel === 'Administrator' || sessionAccessLevel === 'Manager' || sessionAccessLevel === 'Technician');

        const formInputs = form.querySelectorAll('button');
        formInputs.forEach(input => {
            const exclude = [];
            if (!exclude.includes(input.id)) {
                input.disabled = !canEdit;
            }
        });
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function fetchEquipmentModels(disabledModelToggle) {
    fetchWithCSRF('/get_models', {
        method: 'POST',
        body: JSON.stringify({ disabledmodeltoggle: disabledModelToggle })
    })
    .then(response => response.json())
    .then(data => {
        const modelsTable = document.querySelector('#models-table tbody');
        modelsTable.innerHTML = ''; // Clear previous rows
        data.results.forEach(item => {
            const row = document.createElement('tr');
            const cell1 = document.createElement('td');
            cell1.textContent = item.Model;
            const cell2 = document.createElement('td');
            cell2.textContent = item.Manufacturer;
            const cell3 = document.createElement('td');
            cell3.textContent = item.Equipment_Class;
            const cell4 = document.createElement('td');
            cell4.textContent = item.PM_Req_Daily ? '✔' : '✗';
            const cell5 = document.createElement('td');
            cell5.textContent = item.PM_Req_Weekly ? '✔' : '✗';
            const cell6 = document.createElement('td');
            cell6.textContent = item.PM_Req_Monthly ? '✔' : '✗';
            const cell7 = document.createElement('td');
            cell7.textContent = item.PM_Req_Quarterly ? '✔' : '✗';
            const cell8 = document.createElement('td');
            cell8.textContent = item.PM_Req_Annual ? '✔' : '✗';
            const cell9 = document.createElement('td');
            const detailsBtn = document.createElement('button');
            detailsBtn.textContent = 'Details';
            cell9.appendChild(detailsBtn);
            detailsBtn.addEventListener('click', function() {
                fetchWithCSRF('/modify_models_link', {
                    method: 'POST',
                    body: JSON.stringify({
                        Model: item.Model,
                        Manufacturer: item.Manufacturer,
                        Equipment_Class: item.Equipment_Class,
                        PM_Req_Daily: item.PM_Req_Daily,
                        PM_Req_Weekly: item.PM_Req_Weekly,
                        PM_Req_Monthly: item.PM_Req_Monthly,
                        PM_Req_Quarterly: item.PM_Req_Quarterly,
                        PM_Req_Annual: item.PM_Req_Annual,
                        modelActive: item.modelActive
                    })
                })
                .then(response => response.json())
                .then(data => {
                    window.location.href = data.redirect_url;
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Failed to load model details.');
                });
            });

            modelsTable.appendChild(row);

            row.appendChild(cell1);
            row.appendChild(cell2);
            row.appendChild(cell3);
            row.appendChild(cell4);
            row.appendChild(cell5);
            row.appendChild(cell6);
            row.appendChild(cell7);
            row.appendChild(cell8);
            row.appendChild(cell9);
        });
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function setupEditCancelLogic(config) {
    const {
        editBtn, saveBtn, cancelBtn, backLnk,
        textFields, inputFields, extraOnEdit = () => {}, extraOnCancel = () => {}
    } = config;

    if (editBtn && saveBtn && cancelBtn && backLnk) {
        editBtn.addEventListener('click', function() {
            textFields.forEach(el => el && (el.classList.add('hidden')));
            inputFields.forEach(el => el && (el.classList.remove('hidden')));
            editBtn.classList.add('hidden');
            saveBtn.classList.remove('hidden');
            cancelBtn.classList.remove('hidden');
            backLnk.classList.add('hidden');
            extraOnEdit();
        });
        cancelBtn.addEventListener('click', function() {
            textFields.forEach(el => el && (el.classList.remove('hidden')));
            inputFields.forEach(el => el && (el.classList.add('hidden')));
            editBtn.classList.remove('hidden');
            saveBtn.classList.add('hidden');
            cancelBtn.classList.add('hidden');
            backLnk.classList.remove('hidden');
            extraOnCancel();
        });
    }
}

function setupPMTaskInput(containerId, buttonId, inputNamePrefix) {
    const container = document.getElementById(containerId);
    const button = document.getElementById(buttonId);
    let fieldCount = 0;
    if (container && button) {
        fieldCount = parseInt(container.dataset.maxformorder, 10) || 0;
        button.addEventListener('click', function() {
            fieldCount++;
            const newFormGroup = document.createElement('div');
            newFormGroup.className = 'add-pmreqs-group';
            const newField = document.createElement('input');
            newField.type = 'text';
            newField.name = `${inputNamePrefix}-new-${fieldCount}`;
            newField.placeholder = 'Enter value';
            newField.style.display = '';
            newFormGroup.appendChild(newField);
            container.appendChild(newFormGroup);
            newField.focus();
        });
    }
}

function filterTables(searchTerm, tableIds) {
    searchTerm = searchTerm.toLowerCase();
    tableIds.forEach(tableId => {
        const table = document.getElementById(tableId);
        if (!table) return;
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            const rowText = row.textContent.toLowerCase();
            row.style.display = rowText.includes(searchTerm) ? '' : 'none';
        });
    });
}

// Open user modal and fill form with user data
function openUserModal(user) {
    fetchWithCSRF('/modify_user_link', {
        method: 'POST',
        body: JSON.stringify({
            username: user.username,
            access_level: user.access_level,
            lab_access: user.lab_access,
            FirstName: user.FirstName,
            LastName: user.LastName,
            PrimaryLab: user.PrimaryLab,
            userStatus: user.userStatus,
            require_pwd_chg: String(user.require_pwd_chg)
        })
    })
        .then(response => response.json())
        .then(data => {
            const token = data.token;
            // Fetch the token data first to get sessionLab
            fetch(`/get_token_data/${token}`)
                .then(response => response.json())
                .then(data => {
                const modal = document.getElementById('modify-user-modal');
                modal.classList.remove('hidden');
                modal.style.display = 'block';
                
                // Add null checks before setting values
                const usernameField = document.getElementById('modal-username');
                if (usernameField) usernameField.value = user.username || '';

                const hiddenusernameField = document.getElementById('modal-hidden-username');
                if (hiddenusernameField) hiddenusernameField.value = user.username || '';
                
                const firstnameField = document.getElementById('modal-firstname');
                if (firstnameField) firstnameField.value = user.FirstName || '';
                
                const lastnameField = document.getElementById('modal-lastname');
                if (lastnameField) lastnameField.value = user.LastName || '';
                
                const accessLevelField = document.getElementById('modal-accesslevel');
                if (accessLevelField) accessLevelField.value = user.access_level || '';
                
                const primaryLabField = document.getElementById('modal-primarylab');
                if (primaryLabField) primaryLabField.value = user.PrimaryLab || '';
                
                const userStatusField = document.getElementById('modal-userstatus');
                if (userStatusField) userStatusField.value = user.userStatus || '';

                const reqpwdchgCheckbox = document.getElementById('req-pwd-chg');
                if (reqpwdchgCheckbox) {
                    reqpwdchgCheckbox.checked = user.require_pwd_chg === "true" || user.require_pwd_chg === true;
                }
                
                const tokenField = document.getElementById('modal-token-user');
                if (tokenField) tokenField.value = token || '';
                
                const form = document.getElementById('modify-user-form');
                if (form) form.action = '/modify_user?token=' + encodeURIComponent(token || '');
                
                // Check if the user has permission to edit this user
                // const sessionLab = document.getElementById('lablist').value; // Or however you get the current user's lab
                const sessionLab = data.sessionLab
                const sessionAccessLevel = data.sessionaccesslevel
                const canEdit = (sessionAccessLevel === 'Administrator') || (sessionLab === user.PrimaryLab);
               
                // Enable/disable form fields based on permission
                const formInputs = form.querySelectorAll('input, select');
                formInputs.forEach(input => {
                    const exclude = ['modal-password', 'req-pwd-chg', 'modal-userstatus', 'modal-hidden-username'];
                    if (!exclude.includes(input.id)) {
                        input.disabled = !canEdit;
                    }
                });
                
                // Show/hide submit button based on permission
                // const submitButton = form.querySelector('button[type="submit"]');
                // if (submitButton) {
                //     submitButton.style.display = canEdit ? '' : 'none';
                // }

                fetchUserLabAccess(user.username);
            })
            .catch(error => {
                console.error('Error fetching token data:', error);
                alert('Failed to load user details.');
            });
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Failed to load user details.');
    });
}

function fetchUserLabAccess(username) {
    fetchWithCSRF('/get_user_lab_access', {
        method: 'POST',
        body: JSON.stringify({
            username: username
        })
    })
    .then(response => response.json())
    .then(data => {
        const tbody = document.getElementById('lab-access-tbody');
        tbody.innerHTML = '';
        
        // Get all available labs and access levels
        const allLabs = Array.from(document.getElementById('lablist').options)
            .map(opt => opt.value)
            .filter(val => val !== 'All Labs');
            
        // const allAccessLevels = window.serverAccessLevels || ['Administrator', 'Manager', 'User']
        // const allAccessLevels = Array.from(document.getElementById('modal-accesslevel').options)
        //     .map(opt => opt.value);
        const allAccessLevels = data.server_accesslevels

        allLabs.forEach(lab => {
            const row = document.createElement('tr');
            
            // Lab checkbox
            const tdLab = document.createElement('td');
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.name = 'labs[]';
            checkbox.value = lab;
            checkbox.checked = data.user_labs.includes(lab);
            tdLab.appendChild(checkbox);
            tdLab.appendChild(document.createTextNode(' ' + lab));
            
            // Access level dropdown
            const tdAccess = document.createElement('td');
            const select = document.createElement('select');
            select.name = 'access_levels[]';
            allAccessLevels.forEach(level => {
                const option = document.createElement('option');
                option.value = level;
                option.textContent = level;
                option.selected = data.user_lab_access[lab] === level;
                select.appendChild(option);
            });
            tdAccess.appendChild(select);
            
            row.appendChild(tdLab);
            row.appendChild(tdAccess);
            tbody.appendChild(row);
        });
    });
}

// Open modify equipment modal and fill form with equipment data
function openModifyModal(equipment) {
    fetchWithCSRF('/modify_equipment_link', {
        method: 'POST',
        body: JSON.stringify({
            Serial_Num: equipment.Serial_Num,
            LabID: equipment.LabID,
            Model: equipment.Model,
            equipStatus: equipment.equipStatus
        })
    })
    .then(response => response.json())
    .then(data => {
        const token = data.token
        const modal = document.getElementById('modify-equipment-modal');
        modal.classList.remove('hidden');
        modal.style.display = 'block';
        document.getElementById('modal-token').value = token || '';
        document.getElementById('modal-serialnum').value = equipment.Serial_Num || '';
        document.getElementById('modal-labid').value = equipment.LabID || '';
        document.getElementById('modal-model').value = equipment.Model || '';
        document.getElementById('modal-status').value = equipment.equipStatus || '';
        document.getElementById('modify-equipment-form').action = '/modify_equipment?token=' + encodeURIComponent(token || '');
    });
}

// Open add equipment modal and fill form with equipment data
function openAddEquipModal() {
    fetchWithCSRF('/add_equipment_link', {
        method: 'POST',
        body: JSON.stringify({})
    })
    .then(response => response.json())
        .then(data => {
            const token = data.token;
            const modal = document.getElementById('add-equipment-modal');
            modal.classList.remove('hidden');
            modal.style.display = 'block';
            document.getElementById('modal-token-addequip').value = token || '';
            document.getElementById('add-equipment-form').action = '/add_equipment?token=' + encodeURIComponent(token || '');
            document.getElementById('modal-serialnum-addequip').focus();
        });
}

// Open new user modal
function openNewUserModal() {
    fetchWithCSRF('/new_user_link', {
        method: 'POST',
        body: JSON.stringify({})
    })
    .then(response => response.json())
        .then(data => {
            const token = data.token;
            const modal = document.getElementById('new-user-modal');
            modal.classList.remove('hidden');
            modal.style.display = 'block';
            document.getElementById('modal-token-newuser').value = token || '';
            document.getElementById('new-user-form').action = '/new_user?token=' + encodeURIComponent(token || '');
            document.getElementById('modal-username-newuser').focus();
        });
}

// Open add Equipment Model modal and fill form with Model data
function openAddEquipModelModal(model) {
    fetchWithCSRF('/add_model_link', {
        method: 'POST',
        body: JSON.stringify({
            Model: model.Model,
            Manufacturer: model.Manufacturer,
            Equipment_Class: model.Equipment_Class
        })
    })
    .then(response => response.json())
        .then(data => {
            const token = data.token;
            const modal = document.getElementById('add-model-modal');
            modal.classList.remove('hidden');
            modal.style.display = 'block';
            document.getElementById('modal-token-addequipmodel').value = token || '';
            document.getElementById('add-model-form').action = '/add_model?token=' + encodeURIComponent(token || '');
        });
}

// Open add formsubmit modal and fill form with data
function openFormSubmitModal(formsubmit) {
    fetchWithCSRF('/get_form_data', {
        method: 'POST',
        body: JSON.stringify({
            record_num: formsubmit.record_num,
            model: formsubmit.model
        })
    })
    .then(response => response.json())
        .then(data => {
            const token = data.token
            const modal = document.getElementById('formsubmit-modal');
            modal.classList.remove('hidden');
            modal.style.display = 'block';
            document.getElementById('modal-token-formsubmit').value = token || '';
            document.getElementById('modal-recordnum-formsubmit').value = formsubmit.record_num || '';
            document.getElementById('modal-model-formsubmit').value = formsubmit.model || '';
            document.getElementById('modal-completeby-formsubmit').value = data.username || '';
            document.getElementById('formsubmit-form').action = '/formsubmit?token=' + encodeURIComponent(token || '');

            // Dynamically generate form fields
            const fieldsDiv = document.getElementById('formsubmit-fields');
            fieldsDiv.innerHTML = '';
            data.rows.forEach(row => {
                const label = document.createElement('label');
                label.htmlFor = row.Form_Order;
                label.textContent = row.Task + ':';
                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.id = row.Form_Order;
                checkbox.name = row.Form_Order;
                checkbox.required = true;
                fieldsDiv.appendChild(checkbox);
                fieldsDiv.appendChild(label);
                fieldsDiv.appendChild(document.createElement('br'));
            });
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Failed to load form.');
        });
}

// Close modals when clicking outside content
window.onclick = function(event) {
    [
        'add-equipment-modal',
        'add-model-modal',
        'modify-equipment-modal',
        'formsubmit-modal',
        'modify-user-modal',
        'new-user-modal'
    ].forEach(modalId => {
        const modal = document.getElementById(modalId);
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
};

function showPassword() {
  var fields = document.getElementsByClassName("password-field");
  for (let i = 0; i < fields.length; i++) {
    fields[i].type = fields[i].type === "password" ? "text" : "password";
  }
}

function setupFormConfirmations() {
  const forms = document.querySelectorAll('.needs-confirmation');
  
  forms.forEach(form => {
    form.addEventListener('submit', function(event) {
      event.preventDefault();
      
      const modal = document.getElementById('confirmation-modal');
      const confirmBtn = document.getElementById('confirm-submit');
      const cancelBtn = document.getElementById('cancel-submit');
      const message = document.getElementById('confirmation-message');
      
      message.textContent = `Are you sure you want to submit this ${form.dataset.formType || 'form'}?`;
      
      modal.classList.remove('hidden');
      modal.style.display = 'block';
      
      confirmBtn.onclick = function() {
        modal.style.display = 'none';
        form.submit();
      };
      
      cancelBtn.onclick = function() {
        modal.style.display = 'none';
      };
    });
  });
}

document.addEventListener('DOMContentLoaded', setupFormConfirmations);

/////////////////////////////////////////////////////////////////////////////////////////

document.addEventListener('DOMContentLoaded', function() {
    
    const userData = document.getElementById('user-data');
    if (userData) {
        window.sessionAccessLevel = userData.dataset.accessLevel || 'Technician';
        window.sessionLabID = userData.dataset.primaryLab || '';
        window.sessionTimeoutSeconds = parseInt(userData.dataset.timeoutSeconds || '900', 10);
    }
    
    const pwdInput = document.getElementById('reg-password');
    const reqLength = document.getElementById('req-length');
    const reqUpper = document.getElementById('req-upper');
    const reqLower = document.getElementById('req-lower');
    const reqNumber = document.getElementById('req-number');
    const reqSpecial = document.getElementById('req-special');
    const confirmpwdInput = document.getElementById('reg-confirmpwd');
    const reqMatch = document.getElementById('req-match');

    if (pwdInput && confirmpwdInput) {
        pwdInput.addEventListener('input', function() {
            const val = pwdInput.value;
            // Validate each requirement
            reqLength.style.color = val.length >= 8 ? 'green' : 'red';
            reqUpper.style.color = /[A-Z]/.test(val) ? 'green' : 'red';
            reqLower.style.color = /[a-z]/.test(val) ? 'green' : 'red';
            reqNumber.style.color = /\d/.test(val) ? 'green' : 'red';
            reqSpecial.style.color = /[!@#$%^&*(),.?":{}|<>]/.test(val) ? 'green' : 'red';
            confirmpwdInput.addEventListener('input', function() {
                const confirmval = confirmpwdInput.value;
                reqMatch.style.color = confirmval == val ? 'green' : 'red';
            })
        })
    }

    
    resetLogoutTimer();

    function isWarningVisible() {
        const modal = document.getElementById('logout-warning-modal');
        return modal && modal.style.display === 'block';
    }

    function safeResetLogoutTimer() {
        if (!isWarningVisible()) {
            resetLogoutTimer();
        }
    }

    document.addEventListener('mousemove', safeResetLogoutTimer);
    document.addEventListener('keydown', safeResetLogoutTimer);
    document.addEventListener('click', safeResetLogoutTimer);
    
    // Filters for lablist and classlist to filter PM tables.
    const lablist = document.getElementById('lablist');
    const classlist = document.getElementById('classlist');
    function triggerFetch() {
        // Only fetch if both dropdowns have a value
        if (lablist && classlist && lablist.value && classlist.value) {
            fetchAllPMs(lablist.value, classlist.value);
        }
    }
    if (lablist && classlist) {
        // Initial fetch for all tables
        triggerFetch();

        // Fetch again when either dropdown changes
        lablist.addEventListener('change', triggerFetch);
        classlist.addEventListener('change', triggerFetch);
    }    

    const lablistusers = document.getElementById('lablist');
    const usertogglebox = document.getElementById('inactive-user-toggle');
    if (lablistusers && usertogglebox && document.querySelector('#users-table')) {
        // Initial fetch
        // fetchUsersWrapper();

        let inactiveUserToggle = usertogglebox.checked ? 'True' : 'False';
        fetchUsersWrapper(inactiveUserToggle);
        
        usertogglebox.addEventListener('change', function() {
            inactiveUserToggle = this.checked ? 'True' : 'False';
            fetchUsersWrapper(inactiveUserToggle);
        });

        lablistusers.addEventListener('change', function() {
            fetchUsersWrapper(inactiveUserToggle);
        });
    }

    const modeltogglebox = document.getElementById('disabled-model-toggle');
    if (modeltogglebox && document.querySelector('#models-table')) {

        let disabledModelToggle = modeltogglebox.checked ? 'True' : 'False';
        fetchEquipmentModels(disabledModelToggle);
        
        modeltogglebox.addEventListener('change', function() {
            disabledModelToggle = this.checked ? 'True' : 'False';
            fetchEquipmentModels(disabledModelToggle);
        });
    }

    // Search box to filter the PM tables.
    const searchInput = document.getElementById('pm-search');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            filterPMTables(searchInput.value);
        });
    }
    

    if(document.querySelector('#equipment-table')) {
        const equiptogglebox = document.getElementById('inactive-equip-toggle');
        let inactiveToggle = equiptogglebox.checked ? 'True' : 'False';
        // Filters for lablist and classlist to equipment management table.
        const lablistEquipment = document.getElementById('lablist-equipment');
        const classlistEquipment = document.getElementById('classlist-equipment');
        function triggerFetchEquip() {
            // Only fetch if both dropdowns have a value
            if (lablistEquipment && classlistEquipment && lablistEquipment.value && classlistEquipment.value) {
                fetchEquipment(lablistEquipment.value, classlistEquipment.value, inactiveToggle);
            }
        }
        if (lablistEquipment && classlistEquipment) {
            // Initial fetch for all tables
            triggerFetchEquip();

            // Fetch again when either dropdown changes
            equiptogglebox.addEventListener('change', function() {
                inactiveToggle = this.checked ? 'True' : 'False';
                triggerFetchEquip(inactiveToggle);
            });
            lablistEquipment.addEventListener('change', function() {
                triggerFetchEquip(inactiveToggle);
            });
            classlistEquipment.addEventListener('change', function() {
                triggerFetchEquip(inactiveToggle);
            });
        }
        

        // fetchEquipment(inactiveToggle);
    }

    // if(document.querySelector('#models-table')) {
    //     fetchEquipmentModels()
    // }

    // --- modify_equipment.html ---
    setupEditCancelLogic({
        editBtn: document.getElementById('edit-btn'),
        saveBtn: document.getElementById('save-btn'),
        cancelBtn: document.getElementById('cancel-btn'),
        backLnk: document.getElementById('back-link'),
        textFields: [
            document.getElementById('serialnum-text'),
            document.getElementById('labid-text'),
            document.getElementById('model-text'),
            document.getElementById('status-text')
        ],
        inputFields: [
            document.getElementById('new_serialnum'),
            document.getElementById('new_labid'),
            document.getElementById('new_model'),
            document.getElementById('new_status')
        ]
    });

    // --- modify_user.html ---
    setupEditCancelLogic({
        editBtn: document.getElementById('edit-btn'),
        saveBtn: document.getElementById('save-btn'),
        cancelBtn: document.getElementById('cancel-btn'),
        backLnk: document.getElementById('back-link'),
        textFields: [
            document.getElementById('username-text'),
            document.getElementById('accesslevel-text'),
            document.getElementById('primarylab-text'),
            document.getElementById('userstatus-text')
        ],
        inputFields: [
            document.getElementById('new_username'),
            document.getElementById('new_access_level'),
            document.getElementById('new_primarylab'),
            document.getElementById('new_userstatus')
        ]
    });

    // --- modify_models.html ---
    setupEditCancelLogic({
        editBtn: document.getElementById('models-edit-btn'),
        saveBtn: document.getElementById('models-save-btn'),
        cancelBtn: document.getElementById('models-cancel-btn'),
        backLnk: document.getElementById('models-back-link'),
        textFields: [
            document.getElementById('model-text'),
            document.getElementById('manufacturer-text'),
            document.getElementById('class-text'),
            document.getElementById('modelActive-text'),
            document.getElementById('pmreq-daily-text'),
            document.getElementById('pmreq-weekly-text'),
            document.getElementById('pmreq-monthly-text'),
            document.getElementById('pmreq-quarterly-text'),
            document.getElementById('pmreq-annual-text')
        ],
        inputFields: [
            document.getElementById('new_model'),
            document.getElementById('new_manufacturer'),
            document.getElementById('new_equipmentclass'),
            document.getElementById('new_modelActive'),
            document.getElementById('pmreq-daily'),
            document.getElementById('pmreq-weekly'),
            document.getElementById('pmreq-monthly'),
            document.getElementById('pmreq-quarterly'),
            document.getElementById('pmreq-annual')
        ],
        extraOnEdit: function() {
            // Show PM task inputs and buttons
            document.querySelectorAll('.pmreq-daily-task-text').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.pmreq-daily-task-input').forEach(el => el.classList.remove('hidden'));
            document.querySelectorAll('.pmreq-weekly-task-text').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.pmreq-weekly-task-input').forEach(el => el.classList.remove('hidden'));
            document.querySelectorAll('.pmreq-monthly-task-text').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.pmreq-monthly-task-input').forEach(el => el.classList.remove('hidden'));
            document.querySelectorAll('.pmreq-quarterly-task-text').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.pmreq-quarterly-task-input').forEach(el => el.classList.remove('hidden'));
            document.querySelectorAll('.pmreq-annual-task-text').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.pmreq-annual-task-input').forEach(el => el.classList.remove('hidden'));
            document.getElementById('addFieldButton-daily').classList.remove('hidden');
            document.getElementById('addFieldButton-weekly').classList.remove('hidden');
            document.getElementById('addFieldButton-monthly').classList.remove('hidden');
            document.getElementById('addFieldButton-quarterly').classList.remove('hidden');
            document.getElementById('addFieldButton-annual').classList.remove('hidden');
        },
        extraOnCancel: function() {
            // Hide PM task inputs and buttons, show PM task texts
            document.querySelectorAll('.pmreq-daily-task-text').forEach(el => el.classList.remove('hidden'));
            document.querySelectorAll('.pmreq-daily-task-input').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.pmreq-weekly-task-text').forEach(el => el.classList.remove('hidden'));
            document.querySelectorAll('.pmreq-weekly-task-input').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.pmreq-monthly-task-text').forEach(el => el.classList.remove('hidden'));
            document.querySelectorAll('.pmreq-monthly-task-input').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.pmreq-quarterly-task-text').forEach(el => el.classList.remove('hidden'));
            document.querySelectorAll('.pmreq-quarterly-task-input').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.pmreq-annual-task-text').forEach(el => el.classList.remove('hidden'));
            document.querySelectorAll('.pmreq-annual-task-input').forEach(el => el.classList.add('hidden'));
            document.getElementById('addFieldButton-daily').classList.add('hidden');
            document.getElementById('addFieldButton-weekly').classList.add('hidden');
            document.getElementById('addFieldButton-monthly').classList.add('hidden');
            document.getElementById('addFieldButton-quarterly').classList.add('hidden');
            document.getElementById('addFieldButton-annual').classList.add('hidden');
            document.getElementById('inputContainer-daily').innerHTML = '';
            document.getElementById('inputContainer-weekly').innerHTML = '';
            document.getElementById('inputContainer-monthly').innerHTML = '';
            document.getElementById('inputContainer-quarterly').innerHTML = '';
            document.getElementById('inputContainer-annual').innerHTML = '';
        }
    });

    // Call for each PM type
    setupPMTaskInput('inputContainer-daily', 'addFieldButton-daily', 'pmreq-daily-task');
    setupPMTaskInput('inputContainer-weekly', 'addFieldButton-weekly', 'pmreq-weekly-task');
    setupPMTaskInput('inputContainer-monthly', 'addFieldButton-monthly', 'pmreq-monthly-task');
    setupPMTaskInput('inputContainer-quarterly', 'addFieldButton-quarterly', 'pmreq-quarterly-task');
    setupPMTaskInput('inputContainer-annual', 'addFieldButton-annual', 'pmreq-annual-task');

    const equipmentSearch = document.getElementById('equipment-search');
    if (equipmentSearch) {
        equipmentSearch.addEventListener('input', function() {
            filterTables(equipmentSearch.value, ['equipment-table']);
        });
    }
    const userSearch = document.getElementById('user-search');
    if (userSearch) {
        userSearch.addEventListener('input', function() {
            filterTables(userSearch.value, ['users-table']);
        });
    }

    const saveLabAccessBtn = document.getElementById('save-lab-access');
    if (saveLabAccessBtn) {
        saveLabAccessBtn.addEventListener('click', function() {
            const username = document.getElementById('modal-username').value;
            const formData = new FormData();
            formData.append('username', username);
            // Get all selected labs
            document.querySelectorAll('#lab-access-tbody input[type="checkbox"]:checked').forEach(cb => {
                formData.append('labs[]', cb.value);
                const accessLevel = cb.closest('tr').querySelector('select').value;
                formData.append('access_levels[]', accessLevel);
            });

            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            formData.append('csrf_token', csrfToken)
            
            fetch('/modify_user_labs', {
                method: 'POST',
                body: formData
            }).then(response => {
                const msg = document.getElementById('lab-access-success-message');
                if (response.ok) {
                    if (msg) msg.textContent = "Lab Access Updated!";
                    // Optionally clear the message after a few seconds:
                    setTimeout(() => { if (msg) msg.textContent = ""; }, 3000);
                    // Do NOT close the modal
                    // fetchUsers(document.getElementById('lablist').value); // Optionally refresh users
                } else {
                    if (msg) msg.textContent = "Failed to save";
                }
            });
        });
    }

    // Modal open logic
    [
        { btnClass: 'open-addequip-modal', openFn: openAddEquipModal },
        { btnClass: 'open-addequipmodel-modal', openFn: openAddEquipModelModal },
        { btnClass: 'open-modify-modal', openFn: openModifyModal },
        { btnClass: 'open-formsubmit-modal', openFn: openFormSubmitModal },
        { btnClass: 'open-user-modal', openFn: openUserModal },
        { btnClass: 'open-newuser-modal', openFn: openNewUserModal }
    ].forEach(({ btnClass, openFn }) => {
        document.querySelectorAll(`.${btnClass}`).forEach(btn => {
            btn.addEventListener('click', function() {
                // Gather data attributes for modal
                const data = {};
                Array.from(btn.attributes).forEach(attr => {
                    if (attr.name.startsWith('data-')) {
                        const key = attr.name.replace('data-', '').replace(/-([a-z])/g, g => g[1].toUpperCase());
                        data[key] = attr.value;
                    }
                });
                openFn(data);
            });
        });
    });

    // Form validation for add-equipment-form
    const addEquipmentForm = document.getElementById('add-equipment-form');
    if (addEquipmentForm) {
        addEquipmentForm.addEventListener('submit', function(event) {
            const labidSelect = document.getElementById('modal-labid-addequip');
            const modelSelect = document.getElementById('modal-model-addequip');
            const statusSelect = document.getElementById('modal-status-addequip');
            if (!labidSelect.value || labidSelect.value === 'default') {
                alert('Please select a LabID.');
                event.preventDefault();
            }
            if (!modelSelect.value || modelSelect.value === 'default') {
                alert('Please select a Model.');
                event.preventDefault();
            }
            if (!statusSelect.value || statusSelect.value === 'default') {
                alert('Please select a Status.');
                event.preventDefault();
            }
        });
    }

    // Form validation for new-user-form
    const NewUserForm = document.getElementById('new-user-form');
    if (NewUserForm) {
        NewUserForm.addEventListener('submit', function(event) {
            const accesslevelSelect = document.getElementById('modal-accesslevel-newuser');
            const primarylabSelect = document.getElementById('modal-primarylab-newuser');
            if (!accesslevelSelect.value || accesslevelSelect.value === 'default') {
                alert('Please select an Access Level.');
                event.preventDefault();
            }
            if (!primarylabSelect.value || primarylabSelect.value === 'default') {
                alert('Please select a Primary Lab.');
                event.preventDefault();
            }
        });
    }

    // Form validation for add-model-form
    const addModelForm = document.getElementById('add-model-form');
    if (addModelForm) {
        addModelForm.addEventListener('submit', function(event) {
            const classSelect = document.getElementById('modal-equipmentclass-addequipmodel');
            if (!classSelect.value || classSelect.value === 'default') {
                alert('Please select a Class.');
                event.preventDefault();
            }
        });
    }

    // Modal close/cancel logic
    [
        { btnId: 'close-modal', modalId: 'modify-equipment-modal' },
        { btnId: 'cancel-modal', modalId: 'modify-equipment-modal' },
        { btnId: 'close-modal-addequip', modalId: 'add-equipment-modal' },
        { btnId: 'cancel-modal-addequip', modalId: 'add-equipment-modal' },
        { btnId: 'close-modal-addequipmodel', modalId: 'add-model-modal' },
        { btnId: 'cancel-modal-addequipmodel', modalId: 'add-model-modal' },
        { btnId: 'close-modal-formsubmit', modalId: 'formsubmit-modal' },
        { btnId: 'cancel-modal-formsubmit', modalId: 'formsubmit-modal' },
        { btnId: 'close-modal-user', modalId: 'modify-user-modal' },
        { btnId: 'cancel-modal-user', modalId: 'modify-user-modal' },
        { btnId: 'close-modal-newuser', modalId: 'modify-newuser-modal' },
        { btnId: 'cancel-modal-newuser', modalId: 'modify-newuser-modal' }
    ].forEach(({ btnId, modalId }) => {
        const btn = document.getElementById(btnId);
        const modal = document.getElementById(modalId);
        if (btn && modal) {
            btn.onclick = function() {
                modal.style.display = 'none';
            };
        }
    });
});