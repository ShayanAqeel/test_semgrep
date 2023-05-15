import requests
import os
import json
import traceback
s a
import hashlib
import smtplib
import base64
from routes.dec_fun.session_tokens import SessionTokens
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from datetime import datetime
import email as email_lib
from routes.dec_fun.mongo_connection import Client_decryption, Client_Encryption, db_users, db_hris, db_data_asset, db_wg
from routes.dec_fun.errors_message import (
    insert_conflict,
    not_found,
    bad_request,
    server_error,
    no_integration_hris,
    failed_integration_hris,
    mergedev_error,
    mail_not_sent,
    username_email_org_exist
)
from routes.dec_fun.success_messages import (
    success_status,
    success_with_data,
    no_content
)
from routes.dec_fun.secret_info import HRIS_TOKEN, SENDGRID_API_KEY
from .constants_user import (
	ALL_MODULES,
	ALL_MODULES_MIT,
	CREATE_USER_MESSAGE,
    CREATE_USER_SUBJECT,
	EMAIL_FROM,
)
from routes.dec_fun.key_email_validator import (
    genrate_otp,
)
from .process_user import init_gamification
from routes.dec_fun.organization_webhooks import send_email
from .constants_hris import (
    MERGEDEV_INTEGRATIONS_URL,
    MERGEDEV_ACC_TOKEN_URL,
    MERGEDEV_LINK_TOKEN_URL,
    MERGEDEV_EMPLOYEMENTS_URL,
    MERGEDEV_PAYGROUPS_URL,
    MERGEDEV_LOCATIONS_URL,
    MERGEDEV_TEAMS_URL,
    MERGEDEV_RESYNC_URL,
    MERGEDEV_SYNC_STATUS_URL,
    MERGEDEV_EMPLOYEES_URL,
    MERGEDEV_EMPLOYEES_PAGE_URL,
    MERGEDEV_DELETE_ACCOUNT_URL,
    INVITATION_LINK,
    SUBJECT,
    FROM,
    TO,
    CONTENT_TYPE,
    TEXT_HTML,
    MAIL_BODY_INVITE,
    MAIL_BODY_DELETION,
    MAIL_BODY_ADMIN,
    CHROME_DRIVER,
    MERGEDEV_ADMIN
)


def process_get_hris_listing():
    """
    Get HRIS Platforms provided by mergedev
    """
    try:
        url = MERGEDEV_INTEGRATIONS_URL
        payload = ""

        headers = {
            'Authorization': HRIS_TOKEN
        }
        results = list()
        hris_results = list()
        while (True):
            response = requests.request(
                "GET", url, headers=headers, data=payload)
            if response.status_code == 200:
                resp = json.loads(response.content)
                results.extend(resp["results"])
                if (resp["next"] is None):
                    break
                else:
                    url = resp["next"]
            elif response.status_code == 204:
                return no_content()
            else:
                return bad_request("Failed")
        if len(results) > 0:
            for result in results:
                if (("hris" in result["categories"]) and not (
                        "adp" in result["slug"]) and not ("gusto" in result["slug"])):
                    hris_results.append(result)
            return success_with_data(hris_results)
        else:
            return no_content()
    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))


def generate_account_token(body):
    """
    Get temporary public token and store permanent account token in an encrypted form
    """
    try:
        r_link_token = body["link_token"]
        r_public_token = body["public_token"]
        r_namespace = body["namespace"]

        headers = {"Authorization": HRIS_TOKEN}

        account_token_url = MERGEDEV_ACC_TOKEN_URL.format(r_public_token)
        account_token_result = requests.get(account_token_url, headers=headers)
        if account_token_result.status_code == 200:
            account_token_resp = json.loads(account_token_result.content)
            if "account_token" in account_token_resp:
                token = account_token_resp["account_token"]
                name = account_token_resp["integration"]["name"]
                image = account_token_resp["integration"]["image"]
                user_hris_cred = db_hris["namespace_creds"].find_one(
                    {"namespace": r_namespace})
                change_dict={
                                "namespace": r_namespace,
                                "link-token": r_link_token,
                                "x-account-token": token,
                                "username_conf": "fname.lname",
                                "inactive_conf": "email",
                                "hr_system_name": name,
                                "hr_system_image": image,
                                "rsync_conf": "manual",
                                "default_conf": True,
                                "rsync_frequency": ""}
                change_dict_enc=Client_Encryption(db_hris["namespace_creds"], change_dict)
                if user_hris_cred:
                    db_hris["namespace_creds"].update_one(
                        {
                            "namespace": r_namespace},
                        {
                            "$set": change_dict_enc})
                else:
                    db_hris["namespace_creds"].insert_one(change_dict_enc)
                return success_status("Success")
            else:
                return failed_integration_hris()
        elif account_token_result.status_code == 204:
            return no_content()
        else:
            return failed_integration_hris()

    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))


def process_set_hris_config(body):
    """
    Update create user config
    """
    try:
        if "namespace" in body and "username_conf" in body and "inactive_conf" in body and "rsync_conf" in body:
            r_namespace = body["namespace"]
            if (not (get_x_account_token(r_namespace))):
                return no_integration_hris()
            user_hris_cred = db_hris["namespace_creds"].find_one(
                {"namespace": r_namespace})
            if user_hris_cred:

                frequency = ""
                if body["rsync_conf"] == "auto":
                    frequency = body["rsync_frequency"]
                db_hris["namespace_creds"].update_one({"namespace": r_namespace}, {"$set": {
                    "username_conf": body["username_conf"],
                    "inactive_conf": body["inactive_conf"],
                    "rsync_conf": body["rsync_conf"],
                    "rsync_frequency": frequency,
                    "default_conf": False
                }})
                return success_status("Success")
            else:
                return no_integration_hris()
        else:
            return bad_request("Invalid Parameters")

    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))


def process_get_hris_config(body):
    """
    get create user config
    """
    try:
        if "namespace" in body:
            r_namespace = body["namespace"]
            if (not (get_x_account_token(r_namespace))):
                return no_integration_hris()
            user_hris_cred = db_hris["namespace_creds"].find_one(
                {"namespace": r_namespace})
            if user_hris_cred:
                response = {
                    "username_conf": user_hris_cred["username_conf"],
                    "inactive_conf": user_hris_cred["inactive_conf"],
                    "rsync_conf": user_hris_cred["rsync_conf"],
                    "rsync_frequency": user_hris_cred["rsync_frequency"],
                    "default_conf": user_hris_cred["default_conf"]
                }
                return success_with_data(response)
            else:
                return no_integration_hris()
        else:
            return bad_request("Invalid Request Parameters")

    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))


def process_create_hris_link_token(body):
    """
    Returning HRIS Mergedev Link Token to start integration process
    """
    try:
        namespace = body["namespace"]
        user_obj = db_users["users_data"].find_one({"namespace": namespace})
        if not user_obj:
            return no_content()

        body = {
            "end_user_organization_name": user_obj["organization"],
            "end_user_email_address": user_obj["email"],
            "end_user_origin_id": namespace,
            "categories": ["hris"],
            "integration": body["slug"],
        }

        headers = {"Authorization": HRIS_TOKEN}

        link_token_url = MERGEDEV_LINK_TOKEN_URL
        link_token_result = requests.post(
            link_token_url, data=body, headers=headers)
        if link_token_result.status_code == 200:
            link_token_resp = json.loads(link_token_result.content)
            if "link_token" in link_token_resp:
                return success_with_data(link_token_resp["link_token"])
            else:
                return no_content()

        elif link_token_result.status_code == 204:
            return no_content()
        else:
            return mergedev_error()

    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))


def get_x_account_token(namespace):
    """
    Generic function for getting account token
    """
    try:
        cur = db_hris["namespace_creds"].find_one(
            {"namespace": namespace}, {"_id": 0, "x-account-token": 1})
        if not cur:
            return False
        cur_dec=Client_decryption(db_hris["namespace_creds"],cur)
        account_token = cur_dec["x-account-token"]
        return account_token
    except BaseException:
        return False


def employee_position_filter(employee, headers):
    """
    Make employee object from mergedev response
    """
    try:
        positions = list()
        if (employee["employments"] is not None):
            for empl in employee["employments"]:
                resp = requests.get(
                    MERGEDEV_EMPLOYEMENTS_URL.format(empl),
                    headers=headers)
                if (resp.status_code == 200):
                    j_resp = json.loads(resp.content)
                    positions.append(j_resp["job_title"])
        pay_group = ""
        if (employee["pay_group"] is not None):
            resp = requests.get(
                MERGEDEV_PAYGROUPS_URL.format(
                    employee["pay_group"]),
                headers=headers)
            if (resp.status_code == 200):
                j_resp = json.loads(resp.content)
                pay_group = j_resp["pay_group_name"]
        final_employee = {
            "employee_mergedev_id": employee["id"],
            "remote_id": employee["remote_id"],
            "first_name": employee["first_name"],
            "last_name": employee["last_name"],
            "work_email": employee["work_email"],
            "personal_email": employee["personal_email"],
            "employment_status": employee["employment_status"],
            "job_titles": positions,
            "pay_group": pay_group
        }
        return final_employee
    except BaseException:
        return False


def employee_obj_filter(employee, headers):
    """
    Make employee object from mergedev response
    """
    try:
        work_location = ""
        if (employee["work_location"] is not None):
            resp = requests.get(
                MERGEDEV_LOCATIONS_URL.format(
                    employee["work_location"]),
                headers=headers)
            if (resp.status_code == 200):
                j_resp = json.loads(resp.content)
                work_location = work_location + str(j_resp["street_1"]) + "," + str(j_resp["street_2"]) + "," + str(
                    j_resp["city"]) + "," + str(j_resp["state"]) + "," + str(j_resp["country"])
                work_location.replace("None", "")
        home_location = ""
        if (employee["home_location"] is not None):
            resp = requests.get(
                MERGEDEV_LOCATIONS_URL.format(
                    employee["home_location"]),
                headers=headers)
            if (resp.status_code == 200):
                j_resp = json.loads(resp.content)
                home_location = home_location + str(j_resp["street_1"]) + "," + str(j_resp["street_2"]) + "," + str(
                    j_resp["city"]) + "," + str(j_resp["state"]) + "," + str(j_resp["country"])
                home_location.replace("None", "")
        positions = list()
        if (employee["employments"] is not None):
            for empl in employee["employments"]:
                resp = requests.get(
                    MERGEDEV_EMPLOYEMENTS_URL.format(empl),
                    headers=headers)
                if (resp.status_code == 200):
                    j_resp = json.loads(resp.content)
                    positions.append(j_resp["job_title"])
        team = ""
        if (employee["team"] is not None):
            resp = requests.get(
                MERGEDEV_TEAMS_URL.format(
                    employee["team"]),
                headers=headers)
            if (resp.status_code == 200):
                j_resp = json.loads(resp.content)
                team = j_resp["name"]
        pay_group = ""
        if (employee["pay_group"] is not None):
            resp = requests.get(
                MERGEDEV_PAYGROUPS_URL.format(
                    employee["pay_group"]),
                headers=headers)
            if (resp.status_code == 200):
                j_resp = json.loads(resp.content)
                pay_group = j_resp["pay_group_name"]
        final_employee = {
            "employee_mergedev_id": employee["id"],
            "remote_id": employee["remote_id"],
            "first_name": employee["first_name"],
            "last_name": employee["last_name"],
            "work_email": employee["work_email"],
            "personal_email": employee["personal_email"],
            "employment_status": employee["employment_status"],
            "work_location": work_location.replace("None,", ""),
            "home_location": home_location.replace("None,", ""),
            "job_titles": positions,
            "team": team,
            "pay_group": pay_group,
            "confirmation_status": False
        }
        return final_employee
    except BaseException:
        return False


def process_retrieve_all_employees(body):
    """
    Retriece all employees present on organization's HR System
    """
    rsync_flag = False
    try:
        r_namespace = body["namespace"]
        if (not (get_x_account_token(r_namespace))):
            return no_integration_hris()
        user_hris_cred = db_hris["namespace_creds"].find_one(
            {"namespace": r_namespace})
        if user_hris_cred:
            if user_hris_cred["rsync_conf"] == "manual" and user_hris_cred["default_conf"] == False:
                rsync_flag = True
        cur = db_hris["{}.all_employees".format(
            r_namespace)].find({}, {"_id": 0})
        emp_results = list(cur)
        cur = db_hris["{}.all_employees".format(r_namespace)].find(
            {"confirmation_status": True})
        confirm_count = len(list(cur))
        return json.dumps({"status": True, "message": "Success", "confirmed_count": confirm_count,
                          "employees": emp_results, "rsync_flag": rsync_flag}), 200, {'ContentType': 'application/json'}
    except Exception as e:
        traceback.print_exc()
        return json.dumps({"status": False, "message": "Something went wrong.",
                          "rsync_flag": rsync_flag}), 500, {'ContentType': 'application/json'}


def check_resync_status(body):
    """
    Check whole object for any resync pending
    """
    ar_body = body["results"]
    for obj in ar_body:
        if (obj["status"] != "DONE"):
            return False
    return True

def store_db_all_employees(body):
    """
    Store Employees from Mergedev in DB
    """
    try:
        namespace = body["namespace"]
        account_token = get_x_account_token(namespace)
        if (account_token == False):
            return no_integration_hris()
        headers = {
            "Authorization": HRIS_TOKEN,
            "X-Account-Token": account_token
        }
        resync_url = MERGEDEV_RESYNC_URL
        status_url = MERGEDEV_SYNC_STATUS_URL
        resync_result = requests.post(resync_url, headers=headers)
        if (True):
            while (True):
                status_result = requests.get(status_url, headers=headers)
                if (status_result.status_code == 200):
                    status_resp = json.loads(status_result.content)
                    if (check_resync_status(status_resp)):
                        break

        employees_url = MERGEDEV_EMPLOYEES_URL
        while (True):
            employees_result = requests.get(employees_url, headers=headers)
            if employees_result.status_code == 200:
                employees_resp = json.loads(employees_result.content)
                if "results" in employees_resp:
                    results = employees_resp["results"]
                    for result in results:
                        result_obj = employee_obj_filter(result, headers)
                        if (result_obj == False):
                            return server_error("Something went wrong")
                        db_hris["{}.all_employees".format(namespace)].replace_one(
                            {"employee_mergedev_id": result["id"]}, result_obj, upsert=True)
                else:
                    return server_error("No employeed found in Mergedev")
                if (employees_resp["next"] is None):
                    return success_status("Success")
                else:
                    employees_url = MERGEDEV_EMPLOYEES_PAGE_URL.format(
                        employees_resp["next"])

            else:
                return mergedev_error()
    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))


def send_email_custom(
        sender_email,
        reciever_email,
        password,
        server,
        port,
        alert,
        mail_body):
    """
    Send email from user's custom configuration
    """
    SUBJECT_ALERT = alert
    EMAIL_FROM = sender_email
    EMAIL_LOGIN = reciever_email
    EMAIL_PASSWD = password
    SMTP_SERVER = server
    SMTP_PORT = port
    print(EMAIL_PASSWD)
    try:
        msg = email_lib.message.Message()
        msg[FROM] = EMAIL_FROM
        msg[TO] = EMAIL_LOGIN
        msg.add_header(CONTENT_TYPE, TEXT_HTML)
        msg[SUBJECT] = SUBJECT_ALERT
        msg.set_payload(mail_body)
        s = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(EMAIL_FROM, EMAIL_PASSWD)
        s.sendmail(msg[FROM], [msg[TO]], msg.as_string())
        s.quit()
        return True

    except Exception as e:
        traceback.print_exc()
        print("Exception in send_email: ", str(e))
        return False


def send_email_cytex(reciever_email, subject, mail_body):
    """
    Send Email from Cytex Team
    """
    message = {
        'personalizations': [
            {
                'to': [
                    {
                        'email': reciever_email
                    }
                ],
                'subject': subject
            }
        ],
        'from': {
            'email': "noreply.team@cytex.io"
        },
        'content': [
            {
                "type": "text/html",
                "value": "<html><head><meta charset='utf-8'><title></title></head><body>{}</body></html>".format(mail_body)
            }
        ]
    }
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        if int(response.status_code) in [201, 202, 200]:
            return True
        else:
            return False

    except Exception as e:
        traceback.print_exc()
        return False


def make_composite_id(username, email):
    """
    Build composite ID
    """
    try:
        composit_id = '.'.join([username, email])
        composit_id = hashlib.sha1(composit_id.encode('utf-8')).hexdigest()
        return composit_id
    except BaseException:
        return False


def check_username(namespace, composit_id):
    cursor = db_users["users_data"].find_one({"composit_id": composit_id})
    if cursor:
        return False
    else:
        cursor = db_hris["{}.invited_users".format(namespace)].find_one({
            "composit_id": composit_id})
        if (cursor):
            return False
        else:
            return True


def send_emails_to_ids(body):
    """
    Send Invitation emails to all confirmed employees
    """
    try:
        r_namespace = body["namespace"]
        r_employees = body["users"]
        admin_response = db_users["users_data"].find_one(
            {"namespace": r_namespace})
        r_organization = admin_response["organization"]
        smtp_conf_enc = db_users["smtp_cred"].find_one(
            {"namespace": r_namespace}, {"_id": 0})
        smtp_conf=Client_decryption(db_users["smtp_cred"], smtp_conf_enc)
        obj_conf_enc = db_hris["namespace_creds"].find_one(
            {"namespace": r_namespace}, {"_id": 0})
        obj_conf=Client_decryption(db_hris["namespace_creds"], obj_conf_enc)
        for employee in r_employees:
            user_exist = db_users["users_data"].find_one(
                {"employee_mergedev_id": employee["employee_mergedev_id"]})
            if user_exist:
                continue
            exists = db_hris['.'.join([r_namespace, "invited_employees"])].find_one(
                {"employee_mergedev_id": employee["employee_mergedev_id"]})
            if not exists:
                email = employee["email"]
                username = ""
                convention = obj_conf["username_conf"]
                if (convention == "fname.lname"):
                    username = "{}.{}".format(
                        employee["first_name"], employee["last_name"])
                elif (convention == "fname"):
                    username = "{}".format(employee["first_name"])
                elif (convention == "f.lname"):
                    username = "{}{}".format(
                        employee["first_name"][0], employee["last_name"])
                else:
                    return bad_request("Wrong convention Type")
                username = username.replace(" ", "")
                username = username.lower()
                count = 0
                while (True):
                    count = count + 1
                    composite_id = make_composite_id(username, email)
                    if (check_username(r_namespace, composite_id)):
                        break
                    else:
                        username = username + str(count)
            else:
                username = exists['username']
                email = exists['email']
                composite_id = exists['composit_id']
            link = INVITATION_LINK.format(
                username, r_organization, composite_id)
            if (smtp_conf):
                mail_body = MAIL_BODY_INVITE.format(
                    employee["first_name"], r_organization, link, r_organization)
                email_status = send_email_custom(
                    smtp_conf["masking_email"],
                    email,
                    smtp_conf["password"],
                    smtp_conf["email_server"],
                    smtp_conf["port"],
                    "Cytex Invitation",
                    mail_body)
            else:
                mail_body = MAIL_BODY_INVITE.format(
                    employee["first_name"], r_organization, link, "Cytex")
                email_status = send_email_cytex(
                    email, "Cytex Invitation", mail_body)
            employee["username"] = username
            employee["composit_id"] = composite_id

            if (email_status):
                employee["email_status"] = "Success"
                db_hris["{}.invited_employees".format(r_namespace)].replace_one(
                    {"employee_mergedev_id": employee["employee_mergedev_id"]}, employee, upsert=True)
            else:
                employee["email_status"] = "Fail"
                db_hris["{}.invited_employees".format(r_namespace)].replace_one(
                    {"employee_mergedev_id": employee["employee_mergedev_id"]}, employee, upsert=True)

        return success_status("Success")

    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))

def process_create_user(body):
    """
    process to create a new user by user sent an email
    """
    try:
        user_info = db_users["users_data"].find_one(
            {"namespace": body["namespace"], "composit_id": body["composit_id"]},
            {"_id": 0, "access": 1, "read_write": 1, "username": 1},
        )
        if not user_info:
            return username_email_org_exist("UNAUTHORIZED")
        if "UMCU" not in user_info["access"]:
            return bad_request("{} cannot create user".format(user_info["username"]))
        if not user_info["read_write"] == ["read", "write"]:
            return bad_request("{} cannot create user".format(user_info["username"]))
        username = body["username"].lower()
        email = body["email"].lower()
        user_exist = db_users["users_data"].find_one(
            {"username": username, "email": email}, {"_id": 0}
        )
        if user_exist:
            return insert_conflict("User already exists")

        new_composit_id = ".".join([username, email])
        new_composit_id = hashlib.sha1(new_composit_id.encode("utf-8")).hexdigest()
        user_exist = db_users["users_data"].find_one(
            {"composit_id": new_composit_id}, {"_id": 0}
        )
        if user_exist:
            return insert_conflict("User already exists")
        check_access_values = all(item in ALL_MODULES for item in body["access"])
        if not check_access_values:
            return bad_request("Module name is invalid")
        super_info = db_users["users_data"].find_one(
            {"namespace": body["namespace"], "role": "super_user"}, {"_id": 0}
        )
        if not super_info:
            return username_email_org_exist("UNAUTHORIZED")
        # Otp secret is use for 2FA
        otp_secret = genrate_otp()
        body = Client_Encryption(db_users["users_data"], body)
        db_users["users_data"].insert_one(
            {
                "composit_id": new_composit_id,
                "namespace": body["namespace"],
                "username": username,
                "password": body["password"],
                "first_name": body["first_name"],
                "last_name": body["last_name"],
                "email": email,
                "organization": super_info["organization"],
                "attempts": 0,
                "role": body["role"],
                "area": body["area"],
                "access": body["access"],
                "authentication": super_info["authentication"],
                "payment_status": super_info["payment_status"],
                "wg_status": body["enable_wireguard"],
                "read_write": body["read_write"],
                "active": True,
                "image": "",
                "otp_secret": otp_secret,
            }
        )
        # initialize Gamification
        check = init_gamification(body["namespace"], otp_secret, email, username)
        if not check:
            db_users["users_data"].delete_one({"composit_id": new_composit_id})
            return server_error(False)
        message = CREATE_USER_MESSAGE.format(body["first_name"])
        send_email(email, EMAIL_FROM, CREATE_USER_SUBJECT, message)
        return success_status("User created successfully")

    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))

def confirm_password(body):
    """
    Confirm user credentials
    """
    try:
        r_organization = body["organization"]
        r_username = body["username"]
        r_password = body["password"]
        r_user_composit_id = body["composit_id"]
        r_namespace = db_users["users_data"].find_one(
            {"organization": r_organization, "role": "super_user"})["namespace"]
        r_composit_id = db_users["users_data"].find_one(
            {"namespace": r_namespace, "role": "super_user"})["composit_id"]
        cur = db_hris["{}.invited_employees".format(r_namespace)].find_one(
            {"username": r_username}, {"_id": 0})
        emp_obj = cur
        emp_obj["password"] = r_password
        emp_obj["namespace"] = r_namespace
        emp_obj["username"] = r_username
        emp_obj["composit_id"] = r_composit_id
        emp_obj["read_write"] = ["read", "write"]
        try:
            process_create_user(emp_obj)
        except Exception as e:
            return bad_request("Something went wrong while creating the user")
        cur = db_users["users_data"].find_one(
            {"composit_id": r_user_composit_id})
        if (cur):
            emp_obj["composit_id"] = r_user_composit_id
            db_hris["{}.confirmed_employees".format(r_namespace)].replace_one(
                {"employee_mergedev_id": emp_obj["employee_mergedev_id"]}, emp_obj, upsert=True)
            db_hris["{}.all_employees".format(r_namespace)].update_one(
                {"employee_mergedev_id": emp_obj["employee_mergedev_id"]}, {"$set": {"confirmation_status": True}})
            db_hris["{}.invited_employees".format(r_namespace)].delete_one(
                {"employee_mergedev_id": emp_obj["employee_mergedev_id"]})
            db_data_asset['.'.join([r_namespace, "azure_data"])].update_one({"employee_mergedev_id": emp_obj["employee_mergedev_id"], "app_name": {
                "$exists": True, "$not": {"$size": 0}}}, {"$set": {"account_status": "Created", "creation_time": body['time'], "username": body["username"]}})
            return success_status("Password Updated Successfully")
        else:
            return no_content()
    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))


def check_user_confirmation(body):
    """
    Confirm user credentials
    """
    try:
        r_username = body["username"]
        if "reqid" in body:
            cur = db_users["users_data"].find_one(
                {"composit_id": body["reqid"]})
        else:
            cur = db_users["users_data"].find_one({"username": r_username})
        if (cur):
            return json.dumps({"status": True, "exists": True, "message": "User already exists"}), 200, {
                'ContentType': 'application/json'}
        else:
            return json.dumps({"status": True, "exists": False, "message": "User does not exist"}), 200, {
                'ContentType': 'application/json'}
    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))


def resync_mergedev(body):
    """
    Resync our db with mergedev db
    TODO:Crawler needs to be removed and replaced with /force-resync from mergedev APIs
    """
    try:
        namespace = body["namespace"]
        resync_url = MERGEDEV_RESYNC_URL
        status_url = MERGEDEV_SYNC_STATUS_URL
        account_token = get_x_account_token(namespace)
        if (account_token == False):
            return no_integration_hris()
        SESSION_TOKEN_OBJECT = SessionTokens()
        r_organization = db_users["users_data"].find_one(
            {"namespace": namespace})["organization"]
        headers = {
            "Authorization": HRIS_TOKEN,
            "X-Account-Token": account_token
        }
        #Crawl()  # run resync
        while (True):
            status_result = requests.get(status_url, headers=headers)
            if (status_result.status_code == 200):
                status_resp = json.loads(status_result.content)
                if (check_resync_status(status_resp)):
                    break
        obj_configs_enc = db_hris["namespace_creds"].find_one(
            {"namespace": namespace}, {"_id": 0})
        obj_configs=Client_decryption(db_hris["namespace_creds"], obj_configs_enc)
        smtp_configs_enc = db_users["smtp_cred"].find_one(
            {"namespace": namespace}, {"_id": 0})
        smtp_configs=Client_decryption(db_users["smtp_cred"], smtp_configs_enc)
        super_email = db_users["users_data"].find_one(
            {"namespace": namespace}, {"_id": 0})["email"]
        inactive_users = list()
        employees_url = MERGEDEV_EMPLOYEES_URL
        id_list = db_hris["{}.all_employees".format(namespace)].find(
            {}, {"_id": 0, "employee_mergedev_id": 1}).distinct("employee_mergedev_id")
        while (True):
            employees_result = requests.get(employees_url, headers=headers)
            if employees_result.status_code == 200:
                employees_resp = json.loads(employees_result.content)
                if "results" in employees_resp:
                    results = employees_resp["results"]
                    for result in results:
                        if (result["work_email"] == ""):
                            email = result["personal_email"]
                        else:
                            email = result["work_email"]
                        if (result["id"] in id_list):
                            id_list.remove(result["id"])
                        cur = db_hris["{}.all_employees".format(namespace)].find_one(
                            {"employee_mergedev_id": result["id"]})
                        if (cur):
                            
                            if (result["employment_status"] == "INACTIVE"):
                                inactive_users.append(result["first_name"])
                                mail_body = MAIL_BODY_DELETION.format(
                                    result["first_name"], r_organization, r_organization)
                                if (obj_configs["inactive_conf"] == "email"):
                                    if (smtp_configs):
                                        email_status = send_email_custom(
                                            smtp_configs["masking_email"],
                                            email,
                                            smtp_configs["password"],
                                            smtp_configs["email_server"],
                                            smtp_configs["port"],
                                            "Cytex Deactivation",
                                            mail_body)
                                    else:
                                        email_status = send_email_cytex(
                                            email, "Cytex User Deletion Alert", mail_body)
                                elif (obj_configs["inactive_conf"] == "delete&email"):
                                    confirmed_obj = db_hris["{}.confirmed_employees".format(
                                        namespace)].find_one({"employee_mergedev_id": result["id"]})
                                    if (confirmed_obj):
                                        composite_id = confirmed_obj["composit_id"]
                                        cur = db_users["users_data"].find_one(
                                            {"composit_id": composite_id})
                                        if (cur):
                                            db_hris["{}.invited_employees".format(namespace)].delete_one(
                                                {"employee_mergedev_id": result["id"]})
                                            user_object = db_users["users_data"].find_one(
                                                {"composit_id": composite_id})
                                            db_users["users_data"].delete_one(
                                                {"composit_id": composite_id})
                                            db_users['verification'].delete_one(
                                                {'username': user_object['username'], "composit_id": user_object['composit_id']})
                                            db_wg['wireguard_client_configs'].delete_one(
                                                {
                                                    'username': user_object['username'],
                                                    "composit_id": user_object['composit_id'],
                                                    "namespace": namespace})
                                            db_wg[".".join([namespace, "peers"])].delete_one(
                                                {'username': user_object['username'], "composit_id": user_object['composit_id'], "namespace": namespace})
                                            SESSION_TOKEN_OBJECT.delete_composit(
                                                user_object["composit_id"])
                                            db_hris["{}.all_employees".format(namespace)].update_one(
                                                {"employee_mergedev_id": result["id"]}, {"$set": {"confirmation_status": False}})
                                            if (smtp_configs):
                                                email_status = send_email_custom(
                                                    smtp_configs["masking_email"],
                                                    email,
                                                    smtp_configs["password"],
                                                    smtp_configs["email_server"],
                                                    smtp_configs["port"],
                                                    "Cytex Deactivation",
                                                    mail_body)
                                            else:
                                                email_status = send_email_cytex(
                                                    email, "Cytex User Deletion Alert", mail_body)
                            db_hris["{}.all_employees".format(namespace)].update_one({"employee_mergedev_id": result["id"]}, {
                                "$set": {"employment_status": result["employment_status"]}})
                        else:
                            result_obj = employee_obj_filter(result, headers)
                            db_hris["{}.all_employees".format(namespace)].replace_one(
                                {"employee_mergedev_id": result["id"]}, result_obj, upsert=True)

                else:
                    return bad_request("Failed to fetch employees")
                if (employees_resp["next"] is None):
                    if (len(id_list) > 0):
                        for emp_id in id_list:
                            result = db_hris["{}.all_employees".format(namespace)].find_one(
                                {"employee_mergedev_id": emp_id}, {"_id": 0})
                            inactive_users.append(result["first_name"])
                            if (result["work_email"] == ""):
                                email = result["personal_email"]
                            else:
                                email = result["work_email"]
                            mail_body = MAIL_BODY_DELETION.format(
                                result["first_name"], r_organization, r_organization)
                            db_hris["{}.all_employees".format(namespace)].update_one(
                                {"employee_mergedev_id": emp_id}, {"$set": {"employment_status": "INACTIVE"}})
                            if (obj_configs["inactive_conf"] == "email"):
                                if (smtp_configs):
                                    email_status = send_email_custom(
                                        smtp_configs["masking_email"],
                                        email,
                                        smtp_configs["password"],
                                        smtp_configs["email_server"],
                                        smtp_configs["port"],
                                        "Cytex Deactivation",
                                        mail_body)
                                else:
                                    email_status = send_email_cytex(
                                        email, "Cytex User Deletion Alert", mail_body)
                            elif (obj_configs["inactive_conf"] == "delete&email"):
                                confirmed_obj = db_hris["{}.confirmed_employees".format(
                                    namespace)].find_one({"employee_mergedev_id": result["employee_mergedev_id"]})
                                if (confirmed_obj):
                                    composite_id = confirmed_obj["composit_id"]
                                    cur = db_users["users_data"].find_one(
                                        {"composit_id": composite_id})
                                    if (cur):
                                        db_hris["{}.invited_employees".format(namespace)].delete_one(
                                            {"employee_mergedev_id": result["employee_mergedev_id"]})
                                        user_object = db_hris["users_data"].find_one(
                                            {"composit_id": composite_id})
                                        db_users["users_data"].delete_one(
                                            {"composit_id": composite_id})
                                        db_users['verification'].delete_one(
                                            {'username': user_object['username'], "composit_id": user_object['composit_id']})
                                        db_wg['wireguard_client_configs'].delete_one(
                                            {
                                                'username': user_object['username'],
                                                "composit_id": user_object['composit_id'],
                                                "namespace": namespace})
                                        db_wg[".".join([namespace, "peers"])].delete_one(
                                            {'username': user_object['username'], "composit_id": user_object['composit_id'], "namespace": namespace})
                                        SESSION_TOKEN_OBJECT.delete_composit(
                                            user_object["composit_id"])
                                        db_hris["{}.all_employees".format(namespace)].update_one(
                                            {"employee_mergedev_id": result["employee_mergedev_id"]}, {"$set": {"confirmation_status": False}})
                                        if (smtp_configs):
                                            email_status = send_email_custom(
                                                smtp_configs["masking_email"],
                                                email,
                                                smtp_configs["password"],
                                                smtp_configs["email_server"],
                                                smtp_configs["port"],
                                                "Cytex Deactivation",
                                                mail_body)
                                        else:
                                            email_status = send_email_cytex(
                                                email, "Cytex User Deletion Alert", mail_body)
                    current = datetime.now()
                    current = current.strftime("%d/%m/%y %H:%M:%S")
                    if (len(inactive_users) > 0):
                        users_str = ""
                        for u in inactive_users:
                            users_str = users_str + "<b>{}</b><br>".format(u)
                        mail_body = MAIL_BODY_ADMIN.format(users_str)
                        if (smtp_configs):
                            email_status = send_email_custom(
                                smtp_configs["masking_email"],
                                super_email,
                                smtp_configs["password"],
                                smtp_configs["email_server"],
                                smtp_configs["port"],
                                "Cytex Deactivation",
                                mail_body)
                        else:
                            email_status = send_email_cytex(
                                super_email, "Cytex User Deletion Alert", mail_body)
                    db_hris["namespace_creds"].update_one(
                        {"namespace": namespace}, {"$set": {"last_resync": current}})
                    return success_status("Success")
                else:
                    employees_url = MERGEDEV_EMPLOYEES_PAGE_URL.format(
                        employees_resp["next"])
            else:
                return server_error("Mergdev Connection failed")
    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))


def delete_integration(body):
    """
    Delete HRIS Integration
    """
    try:
        namespace = body["namespace"]
        account_token = get_x_account_token(namespace)
        if (account_token == False):
            return no_integration_hris()
        headers = {
            "Authorization": HRIS_TOKEN,
            "X-Account-Token": account_token
        }
        delete_url = MERGEDEV_DELETE_ACCOUNT_URL
        delete_result = requests.post(delete_url, headers=headers)
        if delete_result.status_code == 200:
            db_hris["namespace_creds"].delete_one({"namespace": namespace})
            db_hris["{}.all_employees".format(namespace)].drop()
            db_hris["{}.confirmed_employees".format(namespace)].drop()
            db_hris["{}.invited_employees".format(namespace)].delete_many(
                {"app_name": {"$exists": False}})
            return success_status("Integration Deleted")
        else:
            return server_error("Couldn't delete integration")
    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))


def current_integration(body):
    """
    Get Current HRIS Integration
    """
    try:
        namespace = body["namespace"]
        obj = db_hris["namespace_creds"].find_one(
            {"namespace": namespace}, {"_id": 0})
        if (obj):
            if (not ("hr_system_name" in obj)):
                return no_content()
            final_obj = {
                "name": obj["hr_system_name"],
                "image": obj["hr_system_image"]
            }
            return success_with_data(final_obj)
        else:
            return no_content()
    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))


def azureAD_get_user(body):
    """
    Get Azure AD Users stored in DB
    """
    try:
        collection = db_data_asset['.'.join(
            [body["namespace"], "azureAD_data"])]
        records = list(collection.find({}, {"_id": 0}))
        if not records:
            return no_content()
        for record in records:
            res = db_hris[".".join([body["namespace"], "invited_employees"])].find_one(
                {"employee_mergedev_id": record["employee_mergedev_id"]}, {"_id": 0})
            if not res:
                res = db_users['users_data'].find_one(
                    {"employee_mergedev_id": record["employee_mergedev_id"]}, {"_id": 0})
                res1 = db_data_asset['.'.join([res['namespace'], 'azureAD_data'])].find_one(
                    {"employee_mergedev_id": record["employee_mergedev_id"]}, {"_id": 0})
                if res1:
                    record['account_status'] = res1['account_status']
                    record['creation_time'] = res1['creation_time']
                record['username'] = res['username']

            else:
                record['username'] = res['username']
                record['account_status'] = res["account_status"]
                record['creation_time'] = res["creation_time"]

        return success_with_data(records)
    except Exception as e:
        traceback.print_exc()
        stack = traceback.extract_stack()
        (filename, line, procname, text) = stack[-1]
        return server_error(procname, str(line), str(e))

