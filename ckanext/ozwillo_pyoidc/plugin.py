import logging
from flask import Blueprint, Response

import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.plugins as plugins
from ckan import model
from ckan.common import session, g
from ckan.lib.helpers import flash_error
from ckan.logic.action.create import user_create, member_create
from ckan.plugins.toolkit import url_for, redirect_to, request, config, add_template_directory, add_public_directory, add_resource, get_action, c

import conf
from oidc import create_client, OIDCError

plugin_config_prefix = 'ckanext.ozwillo_pyoidc.'

log = logging.getLogger(__name__)
plugin_controller = __name__ + ':OpenidController'

def ozwillo_login():
    for item in plugins.PluginImplementations(plugins.IAuthenticator):
        item.login()

    log.info('Handling login of user %s' % session.get('user'))
    response = Response()
    for cookie in request.cookies:
        value = request.cookies.get(cookie)
        response.set_cookie(cookie, value, secure=True, httponly=True)
    if 'organization_id' in session:
        g_ = model.Group.get(session['organization_id'])
        client = Clients.get_client(g_)
        url, ht_args, state = client.create_authn_request(conf.ACR_VALUES)
        session['state'] = state
        session.save()
        if ht_args:
            request.headers.update(ht_args)
        # Redirect URI should not include language info init.
        # Returns: `invalid_request: Invalid parameter value: redirect_uri`
        url = url.replace('en%2F','').replace('en/', '')
        return redirect_to(url)
    else:
        return redirect_to('/')

    extra_vars = {}
    if g.user:
        return base.render(u'user/logout_first.html', extra_vars)

    came_from = request.params.get(u'came_from')
    if not came_from:
        came_from = h.url_for(u'user.logged_in')
    g.login_handler = h.url_for(
        _get_repoze_handler(u'login_handler_path'), came_from=came_from)
    return base.render(u'user/login.html', extra_vars)


def _get_repoze_handler(handler_name):
    u'''Returns the URL that repoze.who will respond to and perform a
    login or logout.'''
    return getattr(request.environ[u'repoze.who.plugins'][u'friendlyform'],
                   handler_name)


blueprint = Blueprint('ozwillo-pyoidc', __name__)
blueprint.add_url_rule(rule=u'/user/login', view_func=ozwillo_login)

class Clients(object):

    @classmethod
    def get_client(cls, g):
        params = conf.CLIENT.copy()
        params['srv_discovery_url'] = config.get('%s.ozwillo_discovery_url' % __name__)
        params['client_registration'].update({
            'client_id': g._extras['client_id'].value,
            'client_secret': g._extras['client_secret'].value,
            'redirect_uris': [url_for(host=request.host,
                                      controller=plugin_controller,
                                      action='callback',
                                      id=g.name,
                                      qualified=True)]
        })
        return create_client(**params)


class OzwilloPyoidcPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IRoutes)
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IBlueprint)

    def before_map(self, map):
        map.connect('/organization/{id:.*}/sso',
                    controller=plugin_controller,
                    action='sso')
        map.connect('/organization/{id:.*}/callback',
                    controller=plugin_controller,
                    action='callback')
        map.connect('/user/slo',
                    controller=plugin_controller,
                    action='slo')
        map.redirect('/organization/{id:.*}/logout', '/user/_logout')

        return map

    def after_map(self, map):
        return map

    def identify(self):
        user = session.get('user')
        if user and not getattr(c, 'userobj', None):
            userobj = model.User.get(user)
            c.user = userobj.name
            c.userobj = userobj

    # IBlueprint
    def get_blueprint(self):
        return blueprint

    def logout(self):
        log.info('Logging out user: %s' % session.get('user'))
        response = Response()
        session['user'] = None
        session.save()
        g = model.Group.get(session['organization_id'])
        for cookie in request.cookies:
            response.delete_cookie(cookie)
        if g:
            org_url = url_for(host=request.host,
                              controller='organization',
                              action='read',
                              id=g.name,
                              qualified=True)
            redirect_to(str(org_url))
        else:
            redirect_to('/')


class OpenidController(base.BaseController):

    def sso(self, id):
        log.info('SSO for organization "%s"' % id)
        session['organization_id'] = id
        session.save()
        log.info('redirecting to login page')
        login_url = url_for(controller='user',
                            action='login')
        redirect_to(login_url)

    def callback(self):
        g = model.Group.get(session['organization_id'])
        client = Clients.get_client(g)
        org_url = str(url_for(controller="organization",
                              action='read',
                              id=g.name))
        try:
            userinfo, app_admin, app_user, access_token, id_token \
                = client.callback(session['state'], request.GET)
            session['access_token'] = access_token
            session['id_token'] = id_token
            session.save()
        except OIDCError, e:
            flash_error('Login failed')
            redirect_to(org_url, qualified=True)
        locale = None
        log.info('Received userinfo: %s' % userinfo)

        if 'locale' in userinfo:
            locale = userinfo.get('locale', '')
            if '-' in locale:
                locale, country = locale.split('-')

        org_url = str(url_for(org_url, locale=locale, qualified=True))
        if 'sub' in userinfo:

            userobj = model.User.get(userinfo['sub'])
            if not userobj:
                user_dict = {'id': userinfo['sub'],
                             'name': userinfo['sub'].replace('-', ''),
                             'email': userinfo['email'],
                             'password': userinfo['sub']
                             }
                context = {'ignore_auth': True, 'model': model,
                           'session': model.Session}
                user_create(context, user_dict)
                userobj = model.User.get(userinfo['sub'])

        if app_admin or app_user:
            member_dict = {
                'id': g.id,
                'object': userinfo['sub'],
                'object_type': 'user',
                'capacity': 'admin',
            }

            member_create_context = {
                'model': model,
                'user': userobj.name,
                'ignore_auth': True,
                'session': session
            }

            member_create(member_create_context, member_dict)

            if 'given_name' in userinfo:
                userobj.fullname = userinfo['given_name']
            if 'family_name' in userinfo:
                userobj.fullname += ' ' + userinfo['family_name']
            userobj.save()

            if 'nickname' in userinfo:
                userobj.name = userinfo['nickname']
            try:
                userobj.save()
            except Exception, e:
                log.warning('Error while saving user name: %s' % e)

            session['user'] = userobj.id
            session.save()

        redirect_to(org_url)


    def slo(self):
        """
        Revokes the delivered access token. Logs out the user
        """

        if not request.referer or request.host not in request.referer:
            redirect_to('/')

        g = model.Group.get(session['organization_id'])
        org_url = url_for(host=request.host,
                          controller='organization',
                          action='read',
                          id=g.name,
                          qualified=True)
        org_url = str(org_url)

        if c.user:
            client = Clients.get_client(g)
            logout_url = client.end_session_endpoint

            redirect_uri = org_url + '/logout'

            # revoke the access token
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            data = 'token=' + session.get('access_token')
            data += '&token_type_hint=access_token'
            client.http_request(client.revocation_endpoint, 'POST',
                                data=data, headers=headers)

            # redirect to IDP logout
            logout_url += '?id_token_hint=%s&' % session.get('id_token')
            logout_url += 'post_logout_redirect_uri=%s' % redirect_uri
            redirect_to(str(logout_url))
        redirect_to(org_url)
