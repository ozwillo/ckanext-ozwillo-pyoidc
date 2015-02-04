import logging

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckan.common import session
import ckan.lib.base as base

from pylons import config, request

from oidc import OIDCClients

import conf

from oic.oic import Client, AuthorizationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

plugin_config_prefix = 'ckanext.ozwillo_pyoidc.'

log = logging.getLogger(__name__)

Client = OIDCClients(conf)['ozwillo']

def openid_callback(context, data):
    print context
    print data

class OzwilloPyoidcPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    def __init__(self, name=None):
        self.client = Client

    def before_map(self, map):
        map.redirect('/organization/{id:.*}/sso', '/user/login')
        map.connect('/openid/callback',
                    controller='ckanext.ozwillo_pyoidc.plugin:OpenidController',
                    action='openid_callback')
        return map

    def after_map(self, map):
        return map

    def identify(self):
        # must set toolkit.c.user
        pass

    def login(self):
        url, ht_args = self.client.create_authn_request(session, conf.ACR_VALUES)
        if ht_args:
            toolkit.request.headers.update(ht_args)
        toolkit.redirect_to(url)

    def logout(self):
        # revoke all auth tokens
        # redirect to logout in ozwillo
        revoke_endpoint = 'https://portal.ozwillo-preprod.eu/a/revoke'
        toolkit.redirect('/user/_logout')

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'ozwillo_pyoidc')

class OpenidController(base.BaseController):

    def openid_callback(self):
        userinfo = Client.callback(request.GET)
        return "userinfo: %s" % userinfo
