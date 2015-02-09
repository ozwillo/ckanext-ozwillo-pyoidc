import logging
import conf

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckan.common import session, c, request
from ckan import model
import ckan.lib.base as base

from pylons import config, request

from oidc import OIDCClients

plugin_config_prefix = 'ckanext.ozwillo_pyoidc.'

log = logging.getLogger(__name__)
plugin_controller = 'ckanext.ozwillo_pyoidc.plugin:OpenidController'

CLIENT = None

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
        global CLIENT
        if 'organization_id' in session:
            g = model.Group.get(session['organization_id'])
            conf.CLIENTS['ozwillo']['client_registration'].update({
                'client_id': g._extras['client_id'].value,
                'client_secret': g._extras['client_secret'].value,
                'redirect_uris': [toolkit.url_for(host=request.host,
                                                  controller=plugin_controller,
                                                  action='callback',
                                                  id=g.name,
                                                  qualified=True)]
                })
            log.info('registration info for organization "%s" set' % g.name)
            CLIENT = OIDCClients(conf)['ozwillo']
            url, ht_args = CLIENT.create_authn_request(session, conf.ACR_VALUES)
            if ht_args:
                toolkit.request.headers.update(ht_args)
            toolkit.redirect_to(url)
        else:
            toolkit.redirect_to('/')

    def logout(self):
        # revoke all auth tokens
        # redirect to logout in ozwillo
        # revoke_endpoint = 'https://portal.ozwillo-preprod.eu/a/revoke'
        # toolkit.redirect('/user/_logout')
        pass

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
        global CLIENT
        if CLIENT:
            userinfo = CLIENT.callback(request.GET)
            log.info('Received userinfo: %s' % userinfo)
            userobj = model.User.get(userinfo['nickname'])
            if userobj:
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
                                      id=session['organization_id'],
                                      qualified=True)
            toolkit.redirect_to(org_url)
