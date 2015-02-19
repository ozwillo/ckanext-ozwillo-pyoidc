import logging
import conf

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckan.common import session, c, request
from ckan import model
import ckan.lib.base as base

from pylons import config, request

import conf
from oidc import create_client

plugin_config_prefix = 'ckanext.ozwillo_pyoidc.'

log = logging.getLogger(__name__)
plugin_controller = 'ckanext.ozwillo_pyoidc.plugin:OpenidController'

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
            'redirect_uris': [toolkit.url_for(host=request.host,
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
        if 'organization_id' in session:
            g = model.Group.get(session['organization_id'])
            client = Clients.get(g)
            url, ht_args = client.create_authn_request(session, conf.ACR_VALUES)
            if ht_args:
                toolkit.request.headers.update(ht_args)
            toolkit.redirect_to(url)
        else:
            toolkit.redirect_to('/')

    def logout(self):
        session['user'] = None
        try:
            g = model.Group.get(session['organization_id'])
        except:
            toolkit.redirect_to('/')
        else:
            session['organization_id'] = None
            session.save()

            org_url = toolkit.url_for(host=request.host,
                                      controller='organization',
                                      action='read',
                                      id=g.name,
                                      qualified=True)

            toolkit.redirect_to(org_url)

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
        toolkit.redirect_to(login_url)

    def callback(self):
        g = model.Group.get(session['organization_id'])
        client = Clients.get(g)
        userinfo = client.callback(request.GET)
        log.info('Received userinfo: %s' % userinfo)
        userobj = model.User.get(userinfo['sub'])
        if userobj:
            userobj.name = userinfo['nickname']
            userobj.email = userinfo['email']
            if 'given_name' in userinfo:
                userobj.fullname = userinfo['given_name']
            if 'family_name' in userinfo:
                userobj.fullname += userinfo['family_name']
            userobj.save()
            session['user'] = userobj.id
            session.save()

        org_url = toolkit.url_for(host=request.host,
                                  controller="organization",
                                  action='read',
                                  id=g.name,
                                  qualified=True)
        toolkit.redirect_to(org_url)

    def slo(self):
        """
        Revokes the delivered access token. Logs out the user
        """
        g = model.Group.get(session['organization_id'])
        client = Clients.get(g)
        logout_url = client.end_session_endpoint
        org_url = toolkit.url_for(host=request.host,
                                  controller='organization',
                                  action='read',
                                  id=g.name,
                                  qualified=True)
        redirect_uri = org_url + '/logout'

        # revoke the access token
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = 'token=%s&token_type_hint=access_token' % client.access_token
        client.http_request(client.revocation_endpoint, 'POST',
                            data=data, headers=headers)

        # redirect to IDP logout
        logout_url += '?id_token_hint=%s&' % client.id_token
        logout_url += 'post_logout_redirect_uri=%s' % redirect_uri
        toolkit.redirect_to(str(logout_url))
