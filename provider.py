#!/usr/bin/python


import Cookie
import datetime
import logging
import os
import os.path
import pprint
import sys
import traceback
import urlparse
import logging

import webapp2, jinja2


from webapp2_extras import auth
from webapp2_extras import sessions
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

from google.appengine.ext.webapp import template
from google.appengine.ext import ndb
from google.appengine.api import datastore
from google.appengine.ext.webapp import template
from hashlib import md5

from openid.server import server as OpenIDServer
import store
import users


# the global openid server instance
oidserver = None

def digest(x):
  m = md5()
  m.update(x)
  return m.hexdigest()

def get_identity_url(request):
    user = users.get_current_user()
    if not user:
      return None
      
    parsed = urlparse.urlparse(request.uri)
    request_url_without_path = parsed[0] + '://' + parsed[1]
    
    return request_url_without_path + '/' + user.nickname()

def InitializeOpenId():
    global oidserver
    name = os.environ.get('SERVER_NAME', None)
    port = os.environ.get('SERVER_PORT', '80')
    op_endpoint = "http://%s%s/server" % (name, ":%s" % port if port != "80" else "") if name else None
    logging.info('op_endpoint: %s', op_endpoint)
    oidserver = OpenIDServer.Server(store.DatastoreStore(), op_endpoint=op_endpoint)
  
class OpenIDRequestHandler(webapp2.RequestHandler):
  """A base handler class with a couple OpenID-specific utilities."""

  def ArgsToDict(self):
    req = self.request
    return dict([(arg, req.get(arg)) for arg in req.arguments()])

  def HasCookie(self, trust_root):
    cookies = os.environ.get('HTTP_COOKIE', None)
    if cookies:
      morsel = Cookie.BaseCookie(cookies).get('openid_remembered_%s' % digest(trust_root))
      if morsel and morsel.value == 'yes':
        return True

    return False

  def GetOpenIdRequest(self):
    try:
      oidrequest = oidserver.decodeRequest(self.ArgsToDict())
      logging.debug('OpenID request: %s' % oidrequest)
      return oidrequest
    except:
      trace = ''.join(traceback.format_exception(*sys.exc_info()))
      self.ReportError('Error parsing OpenID request:\n%s' % trace)
      return False

  def Respond(self, oidresponse):
    logging.warning('Respond: oidresponse.request.mode ' + oidresponse.request.mode)

    if oidresponse.request.mode in ['checkid_immediate', 'checkid_setup']:
      user = users.get_current_user()
      if user:
        from openid.extensions.sreg import SRegRequest, SRegResponse
        sreg_req = SRegRequest.fromOpenIDRequest(oidresponse.request)
        if sreg_req.wereFieldsRequested():
          logging.info("sreg_req:%s", sreg_req.allRequestedFields())
          user_data = {'nickname':user.nickname(),
                       'email':user.email()}
          sreg_resp = SRegResponse.extractResponse(sreg_req, user_data)
          sreg_resp.toMessage(oidresponse.fields)        
    logging.info('Using response: %s' % oidresponse)
    encoded_response = oidserver.encodeResponse(oidresponse)

    for header, value in encoded_response.headers.items():
      self.response.headers[header] = str(value)

    if encoded_response.code in (301, 302):
      self.redirect(self.response.headers['location'])
    else:
      self.response.set_status(encoded_response.code)

    if encoded_response.body:
      logging.debug('Sending response body: %s' % encoded_response.body)
      self.response.out.write(encoded_response.body)
    else:
      self.response.out.write('')

  def Render(self, template_name, extra_values={}):
    parsed = urlparse.urlparse(self.request.uri)
    request_url_without_path = parsed[0] + '://' + parsed[1]
    request_url_without_params = request_url_without_path + parsed[2]

    self.response.headers.add_header(
      'X-XRDS-Location', request_url_without_path + '/xrds')

    values = {
      'request': self.request,
      'request_url_without_path': request_url_without_path,
      'request_url_without_params': request_url_without_params,
      'user': users.get_current_user(),
      'login_url': users.create_login_url(self.request.uri),
      'register_url':  'signup',
      'logout_url': users.create_logout_url('/'),
      'debug': self.request.get('deb'),
    }
    values.update(extra_values)
    cwd = os.path.dirname(__file__)
    path = os.path.join(cwd, 'templates', template_name + '.html')
    logging.debug(path)
    self.response.out.write(template.render(path, values))

  def ReportError(self, message):
    """Shows an error HTML page.

    Args:
      message: string
      A detailed error message.
    """
    args = pprint.pformat(self.ArgsToDict())
    self.Render('error', vars())
    logging.error(message)

  def store_login(self, oidrequest, kind):
    """Stores the details of an OpenID login in the datastore.

    Args:
      oidrequest: OpenIDRequest

      kind: string
      'remembered', 'confirmed', or 'declined'
    """
    assert kind in ['remembered', 'confirmed', 'declined']
    user = users.get_current_user()
    assert user

    login = datastore.Entity('Login')
    login['relying_party'] = oidrequest.trust_root
    login['time'] = datetime.datetime.now()
    login['kind'] = kind
    login['user'] = user.id()
    datastore.Put(login)

  def CheckUser(self):
    """Checks that the OpenID identity being asserted is owned by this user.

    Specifically, checks that the request URI's path is the user's nickname.

    Returns:
      True if the request's path is the user's nickname. Otherwise, False, and
      prints an error page.
    """
    args = self.ArgsToDict()

    user = users.get_current_user()
    if not user:
      # not logged in!
      return False
#    return True
    # check that the user is logging into their page, not someone else's.
    identity = args['openid.identity']
    parsed = urlparse.urlparse(identity)
    path = parsed[2]

    if identity == 'http://specs.openid.net/auth/2.0/identifier_select':
      return True

    if path[1:] != user.nickname():
      expected = parsed[0] + '://' + parsed[1] + '/' + user.nickname()
      logging.warning('Bad identity URL %s for user %s; expected %s, path:%s' % 
                      (identity, user.nickname(), expected, path))
      return False

    logging.debug('User %s matched identity %s' % (user.nickname(), identity))
    return True

  def ShowFrontPage(self):
    """Do an internal (non-302) redirect to the front page.

    Preserves the user agent's requested URL.
    """
    front_page = FrontPage()
    front_page.request = self.request
    front_page.response = self.response
    front_page.get()


class XRDS(OpenIDRequestHandler):
  def get(self):
    global oidserver
    self.response.headers['Content-Type'] = 'application/xrds+xml'
    self.response.out.write("""\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
<XRD>
  <Service priority="0">
    <Type>http://specs.openid.net/auth/2.0/server</Type>
    <Type>http://specs.openid.net/auth/2.0/signon</Type>
    <Type>http://openid.net/srv/ax/1.0</Type>
    <URI>%(op_endpoint)s</URI>
  </Service>
</XRD>
</xrds:XRDS>""" % {'op_endpoint':oidserver.op_endpoint})

class UserXRDS(OpenIDRequestHandler):
  def get(self):
    global oidserver
    self.response.headers['Content-Type'] = 'application/xrds+xml'
    self.response.out.write("""\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
<XRD>
  <Service priority="0">
    <Type>http://specs.openid.net/auth/2.0/signon</Type>
    <URI>%(op_endpoint)s</URI>
  </Service>
</XRD>
</xrds:XRDS>""" % {'op_endpoint':oidserver.op_endpoint})

class FrontPage(OpenIDRequestHandler):
  """Show the default OpenID page, with the last 10 logins for this user."""
  def get(self):
    logins = []

    user = users.get_current_user()
    if user:
      query = datastore.Query('Login')
      query['user ='] = user.id()
      query.Order(('time', datastore.Query.DESCENDING))
      logins = query.Get(10)

    self.Render('index', {"logins": logins, "user": user})


class OpenIDServerHandler(OpenIDRequestHandler):
  """Handles OpenID requests: associate, checkid_setup, checkid_immediate."""

  def get(self):
    """Handles GET requests."""
    login_url = users.create_login_url(self.request.uri)
    user = users.get_current_user()
    if user:
      logging.debug('User: %s' % user)
    else:
      logging.info('no user, redirect to login url')
      self.redirect(login_url)

    oidrequest = self.GetOpenIdRequest()
    postargs = oidrequest.message.toPostArgs() if oidrequest else {}
    
    if oidrequest is False:
      # there was an error, and GetOpenIdRequest displayed it. bail out.
      return
    elif oidrequest is None:
      # this is a request from a browser
      self.ShowFrontPage()
    elif oidrequest.mode in ['checkid_immediate', 'checkid_setup']:
      if self.HasCookie(oidrequest.trust_root) and user:
        logging.debug('Has cookie, confirming identity to ' + 
                      oidrequest.trust_root)
        self.store_login(oidrequest, 'remembered')
        self.Respond(oidrequest.answer(True, identity=get_identity_url(self.request)))
      elif oidrequest.immediate:
        self.store_login(oidrequest, 'declined')
        oidresponse = oidrequest.answer(False)
        self.Respond(oidresponse)
      else:
        if self.CheckUser():
          self.Render('prompt', vars())
        else:
          self.ShowFrontPage()

    elif oidrequest.mode in ['associate', 'check_authentication']:
      self.Respond(oidserver.handleRequest(oidrequest))

    else:
      self.ReportError('Unknown mode: %s' % oidrequest.mode)

  post = get


class FinishLogin(OpenIDRequestHandler):
  """Handle a POST response to the OpenID login prompt form."""
  def post(self):
    if not self.CheckUser():
      self.ShowFrontPage()
      return
      
    args = self.ArgsToDict()

    try:
      global oidserver
# mrk
      from openid.message import Message
      message = Message.fromPostArgs(args)
      oidrequest = OpenIDServer.CheckIDRequest.fromMessage(message, oidserver.op_endpoint)
    except:
      trace = ''.join(traceback.format_exception(*sys.exc_info()))
      self.ReportError('Error decoding login request:\n%s' % trace)
      return

    if args.has_key('yes'):
      logging.debug('Confirming identity to %s' % oidrequest.trust_root)
      if args.get('remember', '') == 'yes':
        logging.info('Setting cookie to remember openid login for two weeks')

        expires = datetime.datetime.now() + datetime.timedelta(weeks=2)
        expires_rfc822 = expires.strftime('%a, %d %b %Y %H:%M:%S +0000')
        self.response.headers.add_header(
          'Set-Cookie', 'openid_remembered_%s=yes; expires=%s' % (digest(oidrequest.trust_root), expires_rfc822))

      self.store_login(oidrequest, 'confirmed')
      answer = oidrequest.answer(True, identity=get_identity_url(self.request))
      logging.info('answer:%s', answer)
      self.Respond(answer)

    elif args.has_key('no'):
      logging.debug('Login denied, sending cancel to %s' % 
                    oidrequest.trust_root)
      self.store_login(oidrequest, 'declined')
      return self.Respond(oidrequest.answer(False))

    else:
      self.ReportError('Bad login request.')















def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('login'), abort=True)
    else:
      return handler(self, *args, **kwargs)

  return check_login

class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
    """Shortcut to access the auth instance as a property."""
    return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """Shortcut to access a subset of the user attributes that are stored
    in the session.

    The list of attributes to store in the session is specified in
      config['webapp2_extras.auth']['user_attributes'].
    :returns
      A dictionary with most user information
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """Shortcut to access the current logged in user.

    Unlike user_info, it fetches information from the persistence layer and
    returns an instance of the underlying model.

    :returns
      The instance of the user model associated to the logged in user.
    """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """Returns the implementation of the user model.

    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
    """    
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Shortcut to access the current session."""
      return self.session_store.get_session(backend="datastore")

  def render_template(self, view_filename, params=None):
    if not params:
      params = {}
    user = self.user_info
    params['user'] = user
    path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
    self.response.out.write(template.render(path, params))

  def display_message(self, message):
    """Utility function to display a template with a simple message."""
    params = {
      'message': message
    }
    self.render_template('message.html', params)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
      # Get a session store for this request.
      self.session_store = sessions.get_store(request=self.request)

      try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
      finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)

class MainHandler(BaseHandler):
  def get(self):
    self.render_template('home.html')

class SignupHandler(BaseHandler):
  def get(self):
    self.render_template('signup.html')

  def post(self):
    user_name = self.request.get('username')
    email = self.request.get('email')
    name = self.request.get('name')
    password = self.request.get('password')
    last_name = self.request.get('lastname')

    unique_properties = ['email_address']
    user_data = self.user_model.create_user(user_name,
      unique_properties,
      email_address=email, name=name, password_raw=password,
      last_name=last_name, verified=False)
    if not user_data[0]: #user_data is a tuple
      self.display_message('Unable to create user for email %s because of \
        duplicate keys %s' % (user_name, user_data[1]))
      return
    
    user = user_data[1]
    user_id = user.get_id()

    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='v', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Send an email to user in order to verify their address. \
          They will be able to do so by visiting <a href="{url}">{url}</a>'

    self.display_message(msg.format(url=verification_url))

class ForgotPasswordHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')

    user = self.user_model.get_by_auth_id(username)
    if not user:
      logging.info('Could not find any user entry for username %s', username)
      self._serve_page(not_found=True)
      return

    user_id = user.get_id()
    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='p', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Send an email to user in order to reset their password. \
          They will be able to do so by visiting <a href="{url}">{url}</a>'

    self.display_message(msg.format(url=verification_url))
  
  def _serve_page(self, not_found=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'not_found': not_found
    }
    self.render_template('forgot.html', params)


class VerificationHandler(BaseHandler):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']

    # it should be something more concise like
    # self.auth.get_user_by_token(user_id, signup_token
    # unfortunately the auth interface does not (yet) allow to manipulate
    # signup tokens concisely
    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token,
      'signup')

    if not user:
      logging.info('Could not find any user with id "%s" signup token "%s"',
        user_id, signup_token)
      self.abort(404)
    
    # store user data in the session
    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

    if verification_type == 'v':
      # remove signup token, we don't want users to come back with an old link
      self.user_model.delete_signup_token(user.get_id(), signup_token)

      if not user.verified:
        user.verified = True
        user.put()

      self.display_message('User email address has been verified.')
      return
    elif verification_type == 'p':
      # supply user to the page
      params = {
        'user': user,
        'token': signup_token
      }
      self.render_template('resetpassword.html', params)
    else:
      logging.info('verification type not supported')
      self.abort(404)

class SetPasswordHandler(BaseHandler):

  @user_required
  def post(self):
    password = self.request.get('password')
    old_token = self.request.get('t')

    if not password or password != self.request.get('confirm_password'):
      self.display_message('passwords do not match')
      return

    user = self.user
    user.set_password(password)
    user.put()

    # remove signup token, we don't want users to come back with an old link
    self.user_model.delete_signup_token(user.get_id(), old_token)
    
    self.display_message('Password updated')

class LoginHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')
    try:
      u = self.auth.get_user_by_password(username, password, remember=True,
        save_session=True)
      self.redirect(self.uri_for('home'))
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Login failed for user %s because of %s', username, type(e))
      self._serve_page(True)

  def _serve_page(self, failed=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'failed': failed
    }
    self.render_template('login.html', params)

class LogoutHandler(BaseHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('home'))

class AuthenticatedHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('authenticated.html')

config = {
  'webapp2_extras.auth': {
    'user_model': 'model.NetIdentity',
    'user_attributes': ['name', 'auth_ids']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'Que despierte la Red'
  }
}


InitializeOpenId()

app = webapp2.WSGIApplication([
    webapp2.Route('/', MainHandler, name='home'),
    webapp2.Route('/signup', SignupHandler),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
      handler=VerificationHandler, name='verification'),
    webapp2.Route('/password', SetPasswordHandler),
    webapp2.Route('/pre_login', LoginHandler, name='login'),
    webapp2.Route('/pre_logout', LogoutHandler, name='logout'),
    webapp2.Route('/forgot', ForgotPasswordHandler, name='forgot'),
    webapp2.Route('/authenticated', AuthenticatedHandler, name='authenticated'),
    webapp2.Route('/server', OpenIDServerHandler),
    webapp2.Route('/login', FinishLogin),
    webapp2.Route('/xrds', XRDS),
    webapp2.Route('/frontend', FrontPage),
    webapp2.Route('/[^/]*', UserXRDS),
], debug=True, config=config)

