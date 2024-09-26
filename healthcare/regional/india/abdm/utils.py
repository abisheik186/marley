import json

import requests

import frappe

from healthcare.regional.india.abdm.abdm_config import get_url

import uuid
from datetime import datetime


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
		print('message = ',message)
		encrypted = get_encrypted_message(message)
		print('efter encrypt')
		if "encrypted_msg" in encrypted and encrypted["encrypted_msg"]:
			payload[to_be_enc] = payload.pop("to_encrypt")
			payload[to_be_enc] = encrypted["encrypted_msg"]

	print('before get_authorozation_token')
	print("payload = ",payload)
	access_token, token_type = get_authorization_token()
	print(access_token)

	if not access_token:
		frappe.throw(
			title="Authorization Failed",
			msg="Access token generation for authorization failed, Please try again.",
		)

	authorization = ("Bearer " if token_type == "bearer" else "") + access_token
	request_id=str(uuid.uuid4())
	timestamp=datetime.utcnow().isoformat()+'z'
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
	try:
		print('line 133 inside try block of before api call')
		response = requests.request(
			method=config.get("method"), 
			url=url, headers=headers, 
			data=json.dumps(payload)
		)
		print('line 115')
		print(url)
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
		print(response.json)
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
	req = frappe.new_doc("ABDM Request")
	req.status = "Requested"
	req.url = url
	req.request_name = "auth_cert"
	try:
		response = requests.request(
			method=config.get("method"), url=url, headers={"Content-Type": "application/json"}
		)

		print("response of auth_cert",response)
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


def get_rsa_encrypted_message(message, pub_key):
	# TODO:- Use cryptography
	from base64 import b64decode, b64encode

	from Crypto.Cipher import PKCS1_v1_5
	from Crypto.PublicKey import RSA

	message = bytes(message, "utf-8")
	pubkey = b64decode(pub_key)
	rsa_key = RSA.importKey(pubkey)
	cipher = PKCS1_v1_5.new(rsa_key)
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