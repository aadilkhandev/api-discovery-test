from flask import Flask, Blueprint
import requests
import urllib.request

app = Flask(__name__)

# API blueprint with prefix
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')

@api_v1.route('/users', methods=['GET'])
def get_users():
    # External API call
    response = requests.get('https://jsonplaceholder.typicode.com/users')
    return response.json()

@api_v1.route('/users', methods=['POST'])
def create_user():
    # External API validation
    requests.post('https://api.validation-service.com/validate', json={})
    return {}

@api_v1.route('/users/<int:user_id>')
def get_user(user_id):
    return {"id": user_id}

# Another blueprint
admin_api = Blueprint('admin_api', __name__, url_prefix='/admin')

@admin_api.route('/stats')
def get_stats():
    # External metrics API
    with urllib.request.urlopen('https://metrics-api.com/stats') as response:
        data = response.read()
    return data

app.register_blueprint(api_v1)
app.register_blueprint(admin_api)