import json

import requests

import frappe

from healthcare.regional.india.abdm.abdm_config import get_url

import uuid
from datetime import datetime,timezone


@frappe.whitelist()
def get_authorization_token():
	client_id, client_secret, auth_base_url = frappe.db.get_value(
		"ABDM Settings",
		{"company": frappe.defaults.get_user_default("Company"), "default": 1},
		["client_id", "client_secret", "auth_base_url"],
	)
	print(client_id,client_secret,auth_base_url)

	config = get_url("authorization")
	auth_base_url = auth_base_url.rstrip("/")
	url = auth_base_url + config.get("url")
	url = 'https://dev.abdm.gov.in/api/hiecm/gateway/v3/sessions'
	print("auth url =",url)
	payload = {
		"clientId": client_id, 
		"clientSecret": client_secret,
		"grantType":"client_credentials"
		}
	if not auth_base_url:
		frappe.throw(
			title="Not Configured",
			msg="Base URL not configured in ABDM Settings!",
		)

	req = frappe.new_doc("ABDM Request")
	req.request = json.dumps(payload, indent=4)
	req.url = url
	req.request_name = "Authorization Token"
	request_id=str(uuid.uuid4())
	timestamp=datetime.utcnow().isoformat()+'z'
	print('timestamp of auth token',timestamp)
	try:
		response = requests.request(
			method=config.get("method"),
			url=url,
			headers={
				"Content-Type": "application/json",
				"REQUEST-ID":request_id,
				"TIMESTAMP":timestamp,
				"X-CM-ID":"sbx"},
			data=json.dumps(payload),
		)
		print(response.raise_for_status)
		response.raise_for_status()
		response = response.json()
		req.response = json.dumps(response, indent=4)
		req.status = "Granted"
		req.insert(ignore_permissions=True)
		return response.get("accessToken"), response.get("tokenType")

	except Exception as e:
		try:
			req.response = json.dumps(response.json(), indent=4)
		except json.decoder.JSONDecodeError:
			req.response = response.text
		req.traceback = e
		req.status = "Revoked"
		req.insert(ignore_permissions=True)
		traceback = f"Remote URL {url}\nPayload: {payload}\nTraceback: {e}"
		frappe.log_error(message=traceback, title="Cant create session")
		print(23)
		return auth_base_url, None


@frappe.whitelist()
def abdm_request(payload, url_key, req_type, rec_headers=None, to_be_enc=None, patient_name=None):
	if payload and isinstance(payload, str):
		payload = json.loads(payload)

	if req_type == "Health ID":
		url_type = "health_id_base_url"

	base_url = frappe.db.get_value(
		"ABDM Settings",
		{"company": frappe.defaults.get_user_default("Company"), "default": 1},
		[url_type],
	)
	print("base url =",base_url)
	if not base_url:
		frappe.throw(title="Not Configured", msg="Base URL not configured in ABDM Settings!")		
	config = get_url(url_key)
	print("url key =",url_key)
	base_url = base_url.rstrip("/")
	url = base_url + config.get("url")
	# Check the abdm_config, if the data need to be encypted, encrypts message
	# Build payload with encrypted message
	print("payload = ",payload)
	print('b4 encr')
	if config.get("encrypted"):
		message = payload.get("to_encrypt")
		if url_key in ['create_abha_w_aadhaar','verify_abha_otp']:
			message = payload.get('authData',{}).get('otp',{}).get('to_encrypt')
		print('message = ',message)
		encrypted = get_encrypted_message(message)
		print('efter encrypt encrypted =',encrypted)
		if "encrypted_msg" in encrypted and encrypted["encrypted_msg"]:
			if url_key in ['create_abha_w_aadhaar','verify_abha_otp'] and 'to_encrypt' in payload['authData']['otp']:
				payload['authData']['otp'][to_be_enc] = payload['authData']['otp'].pop('to_encrypt')
				print(12)
				payload['authData']['otp'][to_be_enc] = encrypted['encrypted_msg']
				print(34)
			else:
				print(56)
				payload[to_be_enc] = payload.pop("to_encrypt")
				payload[to_be_enc] = encrypted["encrypted_msg"]
		print('payload after enc',payload)
	print('before get_authorozation_token')
	print("payload with encryption = ",payload)
	access_token, token_type = get_authorization_token()
	print(access_token)

	if not access_token:
		frappe.throw(
			title="Authorization Failed",
			msg="Access token generation for authorization failed, Please try again.",
		)

	authorization = ("Bearer " if token_type == "bearer" else "") + access_token
	request_id=str(uuid.uuid4())
	# timestamp=datetime.utcnow().isoformat()+'z'
	utcnow=datetime.now(timezone.utc)
	timestamp=utcnow.isoformat().replace('+00:00','Z')
	print('timestamp of abdm request',timestamp)
	headers = {
		"Content-Type": "application/json",
		"Accept": "application/json",
		"Authorization": authorization,
		"REQUEST-ID":request_id,
		"TIMESTAMP":timestamp,
	}
	if rec_headers:
		if isinstance(rec_headers, str):
			rec_headers = json.loads(rec_headers)
		headers.update(rec_headers)
	req = frappe.new_doc("ABDM Request")
	req.status = "Requested"
	# TODO: skip saving or encrypt the data saved
	req.request = json.dumps(payload, indent=4)
	req.url = url
	req.request_name = url_key
	print('url_key of abdm request',url_key)
	try:
		print('line 133 inside try block of before api call')
		response = requests.request(
			method=config.get("method"), 
			url=url, 
			headers=headers, 
			data=json.dumps(payload)
		)
		print('line 148')
		print(url)
		print('payload after api hit',payload)
		print('header after api call',headers)
		print(response.json)
		response.raise_for_status()
		if url_key == "get_card":
			pdf = response.content
			_file = frappe.get_doc(
				{
					"doctype": "File",
					"file_name": "abha_card{}.png".format(patient_name),
					"attached_to_doctype": "Patient",
					"attached_to_name": patient_name,
					"attached_to_field": "abha_card",
					"is_private": 0,
					"content": pdf,
				}
			)
			_file.save()
			frappe.db.commit()
			return _file
		req.response = json.dumps(response.json(), indent=4)
		req.status = "Granted"
		req.insert(ignore_permissions=True)
		return response.json()

	except Exception as e:
		req.traceback = e
		print("Exception block executed in abdm_request")
		# print(response.json)
		req.response = json.dumps(response.json(), indent=4)
		req.status = "Revoked"
		req.insert(ignore_permissions=True)
		traceback = f"Remote URL {url}\nPayload: {payload}\nTraceback: {e}"
		frappe.log_error(message=traceback, title="Cant complete API call")
		return response.json()


def get_encrypted_message(message):
	base_url = frappe.db.get_value(
		"ABDM Settings",
		{"company": frappe.defaults.get_user_default("Company"), "default": 1},
		["health_id_base_url"],
	)

	config = get_url("auth_cert")
	url = base_url + config.get("url")
	url='https://healthidsbx.abdm.gov.in/api/v1/auth/cert'
	req = frappe.new_doc("ABDM Request")
	print('req =',req)
	req.status = "Requested"
	req.url = url
	req.request_name = "auth_cert"
	print('cert url =',url)
	try:
		response = requests.request(
			method=config.get("method"), url=url, headers={"Content-Type": "application/json"}
		)

		print("response of auth_cert",response.text)
		response.raise_for_status()
		pub_key = response.text
		pub_key = (
			pub_key.replace("\n", "")
			.replace("-----BEGIN PUBLIC KEY-----", "")
			.replace("-----END PUBLIC KEY-----", "")
		)
		if pub_key:
			encrypted_msg = get_rsa_encrypted_message(message, pub_key)
			req.response = encrypted_msg
			req.status = "Granted"
		req.insert(ignore_permissions=True)
		encrypted = {"public_key": pub_key, "encrypted_msg": encrypted_msg}
		return encrypted

	except Exception as e:
		req.traceback = e
		req.response = json.dumps(response.json(), indent=4)
		req.status = "Revoked"
		req.insert(ignore_permissions=True)
		traceback = f"Remote URL {url}\nTraceback: {e}"
		frappe.log_error(message=traceback, title="Cant complete API call")
		return None


# def get_rsa_encrypted_message(message, pub_key):
# 	# TODO:- Use cryptography
# 	from base64 import b64decode, b64encode

# 	from Crypto.Cipher import PKCS1_v1_5
# 	from Crypto.PublicKey import RSA

# 	message = bytes(message, "utf-8")
# 	pubkey = b64decode(pub_key)
# 	rsa_key = RSA.importKey(pubkey)
# 	cipher = PKCS1_v1_5.new(rsa_key)
# 	ciphertext = cipher.encrypt(message)
# 	emsg = b64encode(ciphertext)
# 	encrypted_msg = emsg.decode("UTF-8")
# 	return encrypted_msg
def get_rsa_encrypted_message(message, pub_key):
	#TODO:- Use Cryptography
    from base64 import b64decode, b64encode
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Hash import SHA1

    message = bytes(message, "utf-8")
    
    pubkey = b64decode(pub_key)
    
    rsa_key = RSA.importKey(pubkey)
    
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA1)
    
    ciphertext = cipher.encrypt(message)

    emsg = b64encode(ciphertext)
    encrypted_msg = emsg.decode("UTF-8")
    
    return encrypted_msg


@frappe.whitelist()
def get_health_data(otp, txnId, auth_method):
	confirm_w_otp_payload = {"to_encrypt": otp, "txnId": txnId}
	if auth_method == "AADHAAR_OTP":
		url_key = "confirm_w_aadhaar_otp"
	elif auth_method == "MOBILE_OTP":
		url_key = "confirm_w_mobile_otp"
	# returns X-Token
	response = abdm_request(confirm_w_otp_payload, url_key, "Health ID", "", "otp")
	abha_url = ""
	if response and response.get("token"):
		abha_url = get_abha_card(response["token"])
		header = {"X-Token": "Bearer " + response["token"]}
		response = abdm_request("", "get_acc_info", "Health ID", header, "")
	return response, abha_url

@frappe.whitelist()
def get_health_data_details(token):
	header = {'X-Token':'Bearer'+token}
	patient_info_response = abdm_request('','get_patient_details','Health ID',header,'')
	if not patient_info_response:
		return {"error":"Failed to retrieve patient details"}
	abha_card_url = get_abha_card(token) if token else ''
	return {
		"ABHANumber": patient_info_response.get("ABHANumber", ""),
        "preferredAbhaAddress": patient_info_response.get("preferredAbhaAddress", ""),
        "mobile": patient_info_response.get("mobile", ""),
        "firstName": patient_info_response.get("firstName", ""),
        "middleName": patient_info_response.get("middleName", ""),
        "lastName": patient_info_response.get("lastName", ""),
        "yearOfBirth": patient_info_response.get("yearOfBirth", ""),
        "dayOfBirth": patient_info_response.get("dayOfBirth", ""),
        "monthOfBirth": patient_info_response.get("monthOfBirth", ""),
        "gender": patient_info_response.get("gender", ""),
        "address": patient_info_response.get("address", ""),
        "pincode": patient_info_response.get("pincode", ""),
        "profilePhoto": patient_info_response.get("profilePhoto", ""),
        "abha_card_url": abha_card_url,
	}
def get_abha_card(token):
	headers = {'X-Token': 'Bearer'+token}

	abha_card_response =abdm_request('','get_card','Health ID',headers,'')
	return abha_card_response if abha_card_response else None
# patient after_insert
def set_consent_attachment_details(doc, method=None):
	if frappe.db.exists(
		"ABDM Settings",
		{"company": frappe.defaults.get_user_default("Company"), "default": 1},
	):
		if doc.consent_for_aadhaar_use:
			file_name = frappe.db.get_value("File", {"file_url": doc.consent_for_aadhaar_use}, "name")
			if file_name:
				frappe.db.set_value(
					"File",
					file_name,
					{
						"attached_to_doctype": "Patient",
						"attached_to_name": doc.name,
						"attached_to_field": doc.consent_for_aadhaar_use,
					},
				)
		if doc.abha_card:
			abha_file_name = frappe.db.get_value(
				"File", {"file_url": doc.abha_card, "attached_to_name": None}, "name"
			)
			if abha_file_name:
				frappe.db.set_value(
					"File",
					abha_file_name,
					{
						"attached_to_doctype": "Patient",
						"attached_to_name": doc.name,
						"attached_to_field": doc.abha_card,
					},
				)


def get_abha_card(token):
	header = {"X-Token": "Bearer " + token}
	response = abdm_request("", "get_card", "Health ID", header, "")
	return response.get("file_url")
