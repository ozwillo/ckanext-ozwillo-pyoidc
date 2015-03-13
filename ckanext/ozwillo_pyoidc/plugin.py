import logging
from routes import redirect_to, url_for

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckan.common import session, c, request, response
from ckan import model
from ckan.logic.action.create import user_create, member_create
import ckan.lib.base as base

from pylons import config

import conf
from oidc import create_client

plugin_config_prefix = 'ckanext.ozwillo_pyoidc.'

log = logging.getLogger(__name__)
plugin_controller = __name__ + ':OpenidController'

_CLIENTS = {}

class Clients(object):

    @classmethod
    def get(cls, g):
        global _CLIENTS
        if g.id in _CLIENTS:
            return _CLIENTS.get(g.id)
        client = cls().get_client(g)
        _CLIENTS.update({g.id: client})
        return client

    def get_client(self, g):
        params = conf.CLIENT.copy()
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
        map.connect('/logout', controller=plugin_controller,
                    action='logout')
        map.connect('/user/slo',
                    controller=plugin_controller,
                    action='slo',
                    conditions={'method': ['POST']})
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
            client = Clients.get(g)
            url, ht_args = client.create_authn_request(conf.ACR_VALUES)
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
        client = Clients.get(g)
        userinfo = client.callback(request.GET)
        locale = None
        log.info('Received userinfo: %s' % userinfo)

        if 'locale' in userinfo:
            locale = userinfo.get('locale', '')
            if '-' in locale:
                locale, country = locale.split('-')

        org_url = str(toolkit.url_for(host=request.host,
                                      controller="organization",
                                      action='read',
                                      id=g.name,
                                      locale=locale,
                                      qualified=True))
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
                if client.app_admin or client.app_user:
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

            if 'nickname' in userinfo:
                userobj.name = userinfo['nickname']
            try:
                userobj.save()
            except Exception, e:
                log.warning('Error while saving user name: %s' % e)

            if 'given_name' in userinfo:
                userobj.fullname = userinfo['given_name']
            if 'family_name' in userinfo:
                userobj.fullname += ' ' + userinfo['family_name']
            userobj.save()
            session['user'] = userobj.id
            session.save()

        redirect_to(org_url)

    def logout(self):
        toolkit.c.slo_url = toolkit.url_for(host=request.host,
                                            controller=plugin_controller,
                                            action="slo",
                                            qualified=True)
        return base.render('logout_confirm.html')

    def slo(self):
        """
        Revokes the delivered access token. Logs out the user
        """
        g = model.Group.get(session['organization_id'])
        org_url = toolkit.url_for(host=request.host,
                                  controller='organization',
                                  action='read',
                                  id=g.name,
                                  qualified=True)
        org_url = str(org_url)

        if toolkit.c.user and request.method == 'POST':
            client = Clients.get(g)
            logout_url = client.end_session_endpoint

            redirect_uri = org_url + '/logout'

            if not hasattr(client, 'access_token'):
                self.sso(g.name)

            # revoke the access token
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            data = 'token=' + client.access_token
            data += '&token_type_hint=access_token'
            client.http_request(client.revocation_endpoint, 'POST',
                                data=data, headers=headers)

            # redirect to IDP logout
            logout_url += '?id_token_hint=%s&' % client.id_token
            logout_url += 'post_logout_redirect_uri=%s' % redirect_uri
            redirect_to(str(logout_url))
        redirect_to(org_url)
