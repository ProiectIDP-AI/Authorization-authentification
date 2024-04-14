from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from redis import Redis
import jwt
from datetime import datetime, timedelta
import os

app = Flask(__name__)
r = Redis(host=os.getenv('REDIS_HOST'), port=int(os.getenv('REDIS_PORT')), decode_responses=True)

SECRET_KEY = 'ratonii_maleficius'

@app.route('/auth/register_company', methods=['PUT'])
def register_company():
    data = request.get_json()
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
                'email': email,
                'exp': datetime.utcnow() + timedelta(hours=24)  # The token will expire after 24 hours
            }, SECRET_KEY, algorithm='HS256')
            return jsonify({'token': token})
    return jsonify({'message': 'Invalid email or password'}), 401

@app.route('/auth/register_admin', methods=['PUT'])
def register_admin():
    if r.hexists('admin', 'password'):
        return jsonify({'message': 'Not allowed'}), 403

    data = request.get_json()
    name = data.get('name')
    if 'password' in data:
        data['password'] = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    if r.hget('admin', 'name') == 'admin':  # If the name matches, update the admin
        r.hset('admin', mapping={
            'name': name,
            'password': data['password'],
            'id': 0
        })
        return jsonify({'message': 'Admin updated successfully'})
    return jsonify({'message': 'Admin not found'}), 404

@app.route('/auth/login_admin', methods=['POST'])
def login_admin():
    data = request.get_json()
    name = data.get('name')
    password = data.get('password')
    
    # Get the admin's details from the database
    admin_details = r.hgetall('admin')
    
    # Check if the admin exists and the password is correct
    if admin_details and check_password_hash(admin_details['password'], password):
        # Create a JWT token
        token = jwt.encode({
            'name': name,
            'exp': datetime.utcnow() + timedelta(hours=24)  # The token will expire after 30 minutes
        }, SECRET_KEY, algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid name or password'}), 401


@app.route('/auth/register_employee', methods=['PUT'])
def register_employee():
    data = request.get_json()
    email = data.get('email')
    employee_ids = r.smembers('emp_ids')  # Get all employee ids
    if 'password' in data:
        data['password'] = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    for id in employee_ids:
        if r.hget(id, 'email') == email:  # If the email matches, update the employee
            r.hset(id, 'password', data['password'])
            return jsonify({'message': 'Employee updated successfully'})
    return jsonify({'message': 'Employee not found'}), 404

@app.route('/auth/login_employee', methods=['POST'])
def login_employee():
    data = request.get_json()
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
                'email': email,
                'exp': datetime.utcnow() + timedelta(hours=24)  # The token will expire after 24 hours
            }, SECRET_KEY, algorithm='HS256')
            return jsonify({'token': token})
    return jsonify({'message': 'Invalid email or password'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6000, debug=True)