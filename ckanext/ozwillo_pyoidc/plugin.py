import logging
from flask import Response

import ckan.plugins as plugins
from ckan import model
from ckan.common import session, g
from ckan.plugins.toolkit import url_for, redirect_to, request, c

import conf
from oidc import create_client, OIDCError
from blueprints import ozwillo

plugin_config_prefix = 'ckanext.ozwillo_pyoidc.'

log = logging.getLogger(__name__)
plugin_controller = __name__ + ':OpenidController'


class OzwilloPyoidcPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IRoutes)
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IBlueprint)

    def before_map(self, map):
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
        return ozwillo

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
