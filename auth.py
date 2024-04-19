from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from redis import Redis
import jwt
from datetime import datetime, timedelta
import os
import requests

app = Flask(__name__)
r = Redis(host=os.getenv('REDIS_HOST'), port=int(os.getenv('REDIS_PORT')), decode_responses=True)
url_io = "http://io:5000/io"

SECRET_KEY = 'ratonii_maleficius'

@app.route('/auth/register_company', methods=['PUT'])
def register_company():
	data = request.get_json()
	if 'email' not in data or 'password' not in data:
		return jsonify({'message': 'Invalid parameters'}), 401
	email = data.get('email')
	company_ids = r.smembers('comp_ids')  # Get all company ids
	if 'password' in data:
		data['password'] = generate_password_hash(data['password'], method='pbkdf2:sha256')
	for id in company_ids:
		if r.hget(id, 'email') == email:  # If the email matches, update the company
			r.hset(id, 'password', data['password'])
			return jsonify({'message': 'Company updated successfully'})
	return jsonify({'message': 'Company not found'}), 404

@app.route('/auth/login_company', methods=['POST'])
def login_company():
	data = request.get_json()
	if 'email' not in data or 'password' not in data:
		return jsonify({'message': 'Invalid parameters'}), 401
	email = data.get('email')
	password = data.get('password')

	# Get all company ids
	company_ids = r.smembers('comp_ids')

	# Check each company
	for id in company_ids:
		company_details = r.hgetall(id)
		if company_details['email'] == email and check_password_hash(company_details['password'], password):
			# Create a JWT token
			token = jwt.encode({
				'id': id,  # The id of the company is stored in the token
				'email': email,
				'type': 'company',  # The type of the user is 'company
				'exp': datetime.utcnow() + timedelta(hours=24)  # The token will expire after 24 hours
			}, SECRET_KEY, algorithm='HS256')
			return jsonify({'token': token})
	return jsonify({'message': 'Invalid email or password'}), 401

@app.route('/auth/register_admin', methods=['PUT'])
def register_admin():
	data = request.get_json()
	if r.hexists('admin', 'password'):
		return jsonify({'message': 'Not allowed'}), 403
	if 'name' not in data or 'password' not in data:
		return jsonify({'message': 'Invalid parameters'}), 401

	data = request.get_json()
	name = data.get('name')
	data['password'] = generate_password_hash(data['password'], method='pbkdf2:sha256')

	if r.hget('admin', 'name') == 'admin':  # If the name matches, update the admin
		r.hset('admin', mapping={
			'name': name,
			'password': data['password'],
			'id': 'admin_id_1'
		})
		return jsonify({'message': 'Admin updated successfully'})
	return jsonify({'message': 'Admin not found'}), 404

@app.route('/auth/login_admin', methods=['POST'])
def login_admin():
	data = request.get_json()
	if 'name' not in data or 'password' not in data:
		return jsonify({'message': 'Invalid parameters'}), 401
	name = data.get('name')
	password = data.get('password')

	# Get the admin's details from the database
	admin_details = r.hgetall('admin')

	# Check if the admin exists and the password is correct
	if admin_details and check_password_hash(admin_details['password'], password):
		# Create a JWT token
		token = jwt.encode({
			'id': admin_details['id'],
			'name': name,
			'type': 'admin',  # The type of the user is 'admin'
			'exp': datetime.utcnow() + timedelta(hours=24)  # The token will expire after 24 hours
		}, SECRET_KEY, algorithm='HS256')
		return jsonify({'token': token})
	return jsonify({'message': 'Invalid name or password'}), 401


@app.route('/auth/register_employee', methods=['PUT'])
def register_employee():
	data = request.get_json()
	if 'email' not in data or 'password' not in data:
		return jsonify({'message': 'Invalid parameters'}), 401
	email = data.get('email')
	employee_ids = r.smembers('emp_ids')
	data['password'] = generate_password_hash(data['password'], method='pbkdf2:sha256')

	for id in employee_ids:
		if r.hget(id, 'email') == email:  # If the email matches, update the employee
			r.hset(id, 'password', data['password'])
			return jsonify({'message': 'Employee updated successfully'})
	return jsonify({'message': 'Employee not found'}), 404

@app.route('/auth/login_employee', methods=['POST'])
def login_employee():
	data = request.get_json()
	if 'email' not in data or 'password' not in data:
		return jsonify({'message': 'Invalid parameters'}), 401
	email = data.get('email')
	password = data.get('password')

	# Get the employee's details from the database
	employee_ids = r.smembers('emp_ids')

	# Check if the employee exists and the password is correct
	for id in employee_ids:
		employee_details = r.hgetall(id)
		if employee_details['email'] == email and check_password_hash(employee_details['password'], password):
			# Create a JWT token
			token = jwt.encode({
				'id': id,  # The id of the employee is stored in the token
				'email': email,
				'type': 'employee',  # The type of the user is 'employee
				'exp': datetime.utcnow() + timedelta(hours=24)  # The token will expire after 24 hours
			}, SECRET_KEY, algorithm='HS256')
			return jsonify({'token': token})
	return jsonify({'message': 'Invalid email or password'}), 401


def verify_client_type(data, client_type, id):
	is_ok = False

	# Verify that the company still exists, and it doesn't happen that a company
	# we no longer have a contract with, but still has a valid token, to be able
	# to have access to our service.
	if data['type'] == 'company':
		url_io_comp = url_io + '/company/' + data['id']
		response = requests.get(url_io_comp, headers=request.headers, data=request.data)
		if response.status_code != 200:
			return False

	if data['type'] == 'employee':
		url_io_emp = url_io + '/employee/' + data['id']
		response = requests.get(url_io_emp, headers=request.headers, data=request.data)
		if response.status_code != 200:
			return False

	if client_type == 'all':
		return True

	if client_type == 'employee_only' and data['type'] == 'employee' and id == data['id']:
		return True

	if data['type'] == client_type:
		is_ok = True

	if client_type == 'company' and data['type'] == 'admin':
		return True

	if client_type == 'employee' and data['type'] == 'admin':
		return True

	if client_type == 'employee' and data['type'] == 'company':
		url_io_emp = url_io + '/employee/' + id
		response = requests.get(url_io_emp, headers=request.headers, data=request.data)
		employee_data = response.json()

		if employee_data['id_comp'] == data['id']:
			return True

	if not is_ok:
		return False

	if id == "None":
		return True
	else:
		if id != data['id']:
			return False

	return True

@app.route("/auth/decode_token", methods=["POST"])
def decode_token():
	payload = request.get_json()
	client_type = payload['client_type']
	if payload['id'] == 'None':
		id = 'None'
	else:
		id = payload['id']
	token = None
	if 'Authorization' in request.headers:
		token = request.headers['Authorization'].split(" ")[1]
	if not token:
		return jsonify({'message': 'Token is missing'}), 401
	try:
		data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
		verify = verify_client_type(data, client_type, id)
		if not verify:
			return jsonify({'message': 'Unauthorized client type'}), 401
		return jsonify(data), 200
	except:
		return jsonify({'message': 'Token is invalid', 'token': token}), 401


@app.route("/auth/change_password", methods=["POST"])
def change_password():
	data = request.get_json()

	if 'password' not in data:
		return jsonify({'message': 'Password is missing'}), 401

	password = generate_password_hash(data['password'], method='pbkdf2:sha256')

	if 'Authorization' in request.headers:
		token = request.headers['Authorization'].split(" ")[1]
	if not token:
		return jsonify({'message': 'Token is missing'}), 401

	try:
		data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
		if data['type'] == 'admin':
			r.hset('admin', mapping={
				'name': 'admin',
				'password': password,
				'id': 'admin_id_1'
			})

			new_token = jwt.encode({
				'id':'admin_id_1',
				'name': 'admin',
				'type': 'admin',  # The type of the user is 'admin'
				'exp': datetime.utcnow() + timedelta(hours=24)  # The token will expire after 24 hours
			}, SECRET_KEY, algorithm='HS256')
			return jsonify({'token': new_token})
		elif data['type'] == 'company':
			email = data.get('email')
			company_ids = r.smembers('comp_ids')

			for id in company_ids:
				if r.hget(id, 'email') == email:  # If the email matches, update the company
					r.hset(id, 'password', password)
					new_token = jwt.encode({
						'id': data['id'],
						'email': data['email'],
						'type': data['type'],  # The type of the user
						'exp': datetime.utcnow() + timedelta(hours=24)  # The token will expire after 24 hours
					}, SECRET_KEY, algorithm='HS256')
					return jsonify({'token': new_token})
			return jsonify({'message': 'Company not found'}), 404

		else:
			email = data.get('email')
			emp_ids = r.smembers('emp_ids')

			for id in emp_ids:
				if r.hget(id, 'email') == email:  # If the email matches, update the company
					r.hset(id, 'password', password)
					new_token = jwt.encode({
						'id': data['id'],
						'email': data['email'],
						'type': data['type'],  # The type of the user
						'exp': datetime.utcnow() + timedelta(hours=24)  # The token will expire after 24 hours
					}, SECRET_KEY, algorithm='HS256')
					return jsonify({'token': new_token})
			return jsonify({'message': 'Employee not found'}), 404

	except:
		return jsonify({'message': 'Token is invalid', 'token': token}), 401


if __name__ == '__main__':
	app.run(host='0.0.0.0', port=6000, debug=True)
