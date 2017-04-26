import logging
from routes import redirect_to, url_for

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckan.common import session, c, request, response
from ckan import model
from ckan.logic.action.create import user_create, member_create
import ckan.lib.base as base
from ckan.lib.helpers import flash_error

from pylons import config

import conf
from oidc import create_client, OIDCError

plugin_config_prefix = 'ckanext.ozwillo_pyoidc.'

log = logging.getLogger(__name__)
plugin_controller = __name__ + ':OpenidController'


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
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes)
    plugins.implements(plugins.IAuthenticator, inherit=True)

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
        if user and not toolkit.c.userobj:
            userobj = model.User.get(user)
            toolkit.c.user = userobj.name
            toolkit.c.userobj = userobj

    def login(self):
        for cookie in request.cookies:
            value = request.cookies.get(cookie)
            response.set_cookie(cookie, value, secure=True, httponly=True)

        if 'organization_id' in session:
            g = model.Group.get(session['organization_id'])
            client = Clients.get_client(g)
            url, ht_args, state = client.create_authn_request(conf.ACR_VALUES)
            session['state'] = state
            session.save()
            if ht_args:
                toolkit.request.headers.update(ht_args)
            redirect_to(url)
        else:
            redirect_to('/')

    def logout(self):
        log.info('Logging out user: %s' % session['user'])
        session['user'] = None
        session.save()
        g = model.Group.get(session['organization_id'])
        for cookie in request.cookies:
            response.delete_cookie(cookie)
        if g:
            org_url = toolkit.url_for(host=request.host,
                                      controller='organization',
                                      action='read',
                                      id=g.name,
                                      qualified=True)

            redirect_to(str(org_url))
        else:
            redirect_to('/')

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'ozwillo_pyoidc')

class OpenidController(base.BaseController):

    def sso(self, id):
        log.info('SSO for organization "%s"' % id)
        session['organization_id'] = id
        session.save()
        log.info('redirecting to login page')
        login_url = toolkit.url_for(host=request.host,
                                    controller='user',
                                    action='login',
                                    qualified=True)
        redirect_to(login_url)

    def callback(self):
        g = model.Group.get(session['organization_id'])
        client = Clients.get_client(g)
        org_url = str(toolkit.url_for(controller="organization",
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

        org_url = str(toolkit.url_for(org_url, locale=locale, qualified=True))
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

        if toolkit.c.user:
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
