import logging
from flask import Blueprint, Response

import ckan.lib.helpers as h
import ckan.plugins as plugins
from ckan import model
from ckan.common import session, g
from ckan.lib.helpers import flash_error
from ckan.logic.action.create import user_create, member_create
from ckan.plugins.toolkit import url_for, redirect_to, request, config, add_template_directory, add_public_directory, add_resource, get_action, c

import conf
from oidc import create_client, OIDCError

log = logging.getLogger(__name__)
ozwillo = Blueprint('ozwillo-pyoidc', __name__)


class Clients(object):

    @classmethod
    def get_client(cls, g_):
        params = conf.CLIENT.copy()
        params['srv_discovery_url'] = config.get(
	    'ckanext.ozwillo_pyoidc.plugin.ozwillo_discovery_url')
        params['client_registration'].update({
            'client_id': g_._extras['client_id'].value,
            'client_secret': g_._extras['client_secret'].value,
            'redirect_uris': [url_for('ozwillo-pyoidc.callback',
                                      id=g_.name,
                                      _external=True)]
        })
        return create_client(**params)


def ozwillo_login():
    for cookie in request.cookies:
        value = request.cookies.get(cookie)
        Response().set_cookie(cookie, value, secure=True, httponly=True)
    if 'organization_id' in session:
        g_ = model.Group.get(session['organization_id'])
        client = Clients.get_client(g_)
        url, ht_args, state = client.create_authn_request(conf.ACR_VALUES)
        session['state'] = state
        session['from_login'] = True
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


ozwillo.add_url_rule(rule=u'/user/login', view_func=ozwillo_login)


def sso(id):
    log.info('SSO for organization "%s"' % id)
    session['organization_id'] = id
    session.save()
    log.info('redirecting to login page')
    login_url = url_for('ozwillo-pyoidc.ozwillo_login')
    return ozwillo_login()

ozwillo.add_url_rule(rule=u'/organization/<id>/sso', view_func=sso)


def callback(id):
    # Blueprints act strangely after user is logged in once. It will skip
    # SSO and user/login when trying to log in from different account and
    # directly get here. This is a workaround to force login user if not
    # redirected from loging page (as it sets important values in session)
    if not session.get('from_login'):
        return sso(id)
    session['from_login'] = False
    g_ = model.Group.get(session.get('organization_id', id))
    client = Clients.get_client(g_)
    org_url = str(url_for(controller="organization",
                          action='read',
                          id=g_.name))
    try:
        # Grab state from query parameter if session does not have it
        session['state'] = session.get('state', request.params.get('state'))
        userinfo, app_admin, app_user, access_token, id_token \
            = client.callback(session['state'], request.args)
        session['access_token'] = access_token
        session['id_token'] = id_token
        session.save()
    except OIDCError, e:
        flash_error('Login failed')
        return redirect_to(org_url, qualified=True)

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
            'id': g_.id,
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

    return redirect_to(org_url)

ozwillo.add_url_rule(rule=u'/organization/<id>/callback', view_func=callback)

def slo():
    """
    Revokes the delivered access token. Logs out the user
    """
    if not request.referrer or request.host not in request.referrer:
        return redirect_to('/')

    log.info('Preparing to logging out: %s' % c.user)

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

        # revoke the access token (https://doc.ozwillo.com/#1-revoke-known-tokens)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = 'token=' + session.get('access_token')
        data += '&token_type_hint=access_token'
        client.http_request(client.revocation_endpoint, 'POST',
                            data=data, headers=headers)

        # Invalidate the local session (https://doc.ozwillo.com/#2-invalidate-the-applications-local-session)
        session.invalidate()
        c.user = None
        c.userobj = None
        response = Response()
        for cookie in request.cookies:
            response.delete_cookie(cookie)

        # redirect to IDP logout (https://doc.ozwillo.com/#3-single-sign-out)
        logout_url += '?id_token_hint=%s&' % session.get('id_token')
        logout_url += 'post_logout_redirect_uri=%s' % redirect_uri

        log.info('Redirecting user to: %s' % logout_url)

        return redirect_to(str(logout_url))
    return redirect_to(org_url)


ozwillo.add_url_rule(rule=u'/user/slo', view_func=slo)
