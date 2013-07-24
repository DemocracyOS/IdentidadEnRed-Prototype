
from urllib import urlencode
from webapp2_extras import auth

class User():
    def __init__(self):
        self.data = auth.get_auth().get_user_by_session()
    
    def nickname(self):
        return self.id()

    def id(self):
        return self.data['auth_ids'][0]

def get_current_user():
    return User() 

def create_login_url(prev):
    return "http://localhost:8080/pre_login?"+urlencode({"prev": prev})

def create_logout_url(prev):
    return "http://localhost:8080/pre_logout?"+urlencode({"prev": prev})