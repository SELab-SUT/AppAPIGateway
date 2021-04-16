from flask import Flask, request
import requests
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask.json import jsonify
from http import HTTPStatus
from functools import wraps
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = '2b01ddd83c7b5778cb05d8f66d94c727'
ACCOUNT_SERVICE_URL = 'http://localhost:5000'

def as_response(response):
	return response.content, response.status_code, response.headers.items()

def token_required(func):
	@wraps(func)
	def run_with_username(*args, **kwargs):
		token = request.headers.get('x-access-token')
		if not token:
			return jsonify(message="No token is given"), HTTPStatus.UNAUTHORIZED
		try:
			username = jwt.decode(token, app.config.get('SECRET_KEY'), algorithms='HS256')['sub']
		except Exception as e:
			return jsonify(message=str(e)), HTTPStatus.UNAUTHORIZED
		return func(username, *args, **kwargs)

	return run_with_username


@app.route('/signup', methods=['POST'])
def signup():
	json = request.json
	password = json.pop('password', None)

	if not password:
		return jsonify(message='Password is not given'), HTTPStatus.BAD_REQUEST

	json['hashed_passwd'] = generate_password_hash(password)
	response = requests.post(ACCOUNT_SERVICE_URL + "/create_user", json=json)
	return as_response(response)


@app.route('/login', methods=['POST'])
def login():
	json = request.json
	username = json.get('username')
	password = json.get('password')
	if not username:
		return jsonify(message="Username is not given"), HTTPStatus.BAD_REQUEST
	if not password:
		return jsonify(message="Password is not given"), HTTPStatus.BAD_REQUEST
	ACCOUNT_GET_USER_URL = ACCOUNT_SERVICE_URL + f"/get_user/{username}"
	response = requests.get(ACCOUNT_GET_USER_URL)
	if response.status_code != HTTPStatus.OK:
		return as_response(response)

	found_user = response.json()['user']
	if check_password_hash(found_user['hashed_passwd'], password):
		payload = {
			'sub': username,
			'exp': datetime.datetime.now() + datetime.timedelta(days=1)
		}
		token = jwt.encode(payload, app.config.get('SECRET_KEY'), algorithm='HS256')
		return jsonify(message="Login Successful", jwt=token), HTTPStatus.OK
	return jsonify(message='Invalid Password'), HTTPStatus.UNAUTHORIZED


@app.route('/show_profile', methods=['GET'])
@token_required
def show_profile(username):
	ACCOUNT_GET_USER_URL = ACCOUNT_SERVICE_URL + f"/get_user/{username}"
	response = requests.get(ACCOUNT_GET_USER_URL)

	if response.status_code != HTTPStatus.OK:
		return as_response(response)

	found_user = response.json()['user']
	found_user.pop('hashed_passwd')

	return jsonify(user=found_user), HTTPStatus.OK

@app.route('/update_profile', methods=['POST'])
@token_required
def update_profile(username):
	ACCOUNT_MODIFY_USER_URL = ACCOUNT_SERVICE_URL + f"/modify_user/{username}"
	json = request.json
	response = requests.put(ACCOUNT_MODIFY_USER_URL, json=json)
	return as_response(response)


if __name__ == '__main__':
	app.run(port=80, debug=True)
