from pyramid.config import Configurator
from pyramid.view import view_config
import urllib.request

def main(global_config, **settings):
    config = Configurator(settings=settings)
    
    # Route configurations
    config.add_route('users', '/api/users')
    config.add_route('user_detail', '/api/users/{id}')
    config.add_route('posts', '/api/posts')
    
    return config.make_wsgi_app()

@view_config(route_name='users', request_method='GET')
def get_users(request):
    # External API call using urllib
    with urllib.request.urlopen('https://jsonplaceholder.typicode.com/users') as response:
        data = response.read()
    return {'users': data}

@view_config(route_name='user_detail', request_method='GET')
def get_user(request):
    user_id = request.matchdict['id']
    return {'user_id': user_id}

@view_config(route_name='posts', request_method='POST')
def create_post(request):
    return {'status': 'created'}