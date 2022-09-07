import logging
from flask import Blueprint, Response

import ckan.lib.helpers as h
import ckan.plugins as plugins
from ckan import model
from ckan.common import session, g
from ckan.lib.helpers import flash_error
from ckan.logic.action.create import user_create, member_create
from ckan.plugins.toolkit import url_for, redirect_to, request, config, add_template_directory, add_public_directory, add_resource, get_action, c

from . import conf
from .oidc import create_client, OIDCError

log = logging.getLogger(__name__)
ozwillo = Blueprint('ozwillo-pyoidc', __name__)


class Clients(object):

    @classmethod
    def get_client(cls, g_):
        '''
        Returns an Ozwillo OpenID Connect client.
        Raises KeyError if the provided organization is missing client_id or
        client_secret or non existing organization
        '''
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
    '''
    Called by sso(). Sets response cookies, loads the organization logged into
    from session-provided id (and if it doesn't exist, instead of failing right
    away uses the first of ozwillo_global_login_organization_names as default,
    so ex. /dummy_org/sso can be used as a global login url in the theme),
    creates OID client from client_id/secret of session-provided organization,
    saves its state and redirects to its callback
    '''
    for cookie in request.cookies:
        value = request.cookies.get(cookie)
        Response().set_cookie(cookie, value, secure=True, httponly=True)

    if 'organization_id' in session:
        log.info('ozwillo_login org=%s', session['organization_id'])
        g_ = model.Group.get(session['organization_id'])
        # NB. if unknown organization (g_ is None), next line raises AttributeError,
        # which is caught above if not is_login_to_org, and otherwise should not
        # happen because login to org button is only available on existing orgs.

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


def get_global_login_organization_names():
    '''
    Returns the names / ids of the organizations to be successively tried when
    doing a global (not org) login, as configured in
    ozwillo_global_login_organization_names
    '''
    s = config.get('ckanext.ozwillo_pyoidc.plugin.ozwillo_global_login_organization_names')
    if s:
        org_names = s.split()
        if len(org_names) != 0:
            return org_names

    return None

def try_sso_next_login_org(id):
    '''
    Tries to sso to the organizationa whose id is after the provided one in
    their ozwillo_global_login_organization_names order if configured, and if it
    fails recursively tries to the one after that and so on.
    '''
    log.info('try_sso_next_login_org id=%s', id)
    login_org_ids = get_global_login_organization_names()
    if login_org_ids and len(login_org_ids) != 0 :
        # let's try to log in the next org used for login :
        # (so to be able to login, a user has only to be member of any of those
        # rather than of a specific one)
        login_org_index = login_org_ids.index(id) if id in login_org_ids else 0
        if login_org_index + 1 < len(login_org_ids):
            next_id = login_org_ids[login_org_index + 1]
            try:
                return sso(next_id)
            except (KeyError, OIDCError, AttributeError) as e:
                return try_sso_next_login_org(next_id)
    return None

def sso(id):
    '''
    Logs in to the organization with the given id, and if it fails (KeyError
    because of missing client_id in organization extra fields, as a patch to the
    case when it has been erased by mistake such as using the default custom
    form fields) to the next one in the ozwillo_global_login_organization_names
    property if configured
    '''
    log.info('SSO for organization "%s"' % id)
    session['organization_id'] = id
    session.save()
    log.info('redirecting to login page')
    login_url = url_for('ozwillo-pyoidc.ozwillo_login')
    try:
        return ozwillo_login()
    except KeyError as e:
        log.info('sso KeyError, probably missing client_id ? error : %s %s', e.args[0], e)
        sso_ok = try_sso_next_login_org(id)
        if sso_ok:
            return sso_ok

ozwillo.add_url_rule(rule=u'/organization/<id>/sso', view_func=sso)


def login_to_org(id):
    '''
    Used by the "Log in to Organization" button on the organization page, in
    order to add the membership of the user to this organization if it has been
    defined in the portal but the icon in the portal not yet clicked on.
    So does a login to the organization with the provided id, with the same
    process as /sso, with the differences that, if it fails :
    - it does not try to log in to any other organization whose id is listed in
    the ozwillo_global_login_organization_names configuration property
    - will display (in callback()) "not a member" rather than "Login failed".
    '''
    log.info('Login to organization "%s"' % id)
    # let's mark the next processing as being a log in to organization
    # rather than a login using the global login button :
    session['is_login_to_org'] = True
    session.save()
    return sso(id)

ozwillo.add_url_rule(rule=u'/organization/<id>/login_to_org', view_func=login_to_org)


def callback(id):
    '''
    OID callback.
    If it fails (OIDCError), if the session has NOT been marked as been in the
    context of a login_to_org() call (rather than only an sso() one), tries to
    sso() to the organization with the next id in the order of the
    ozwillo_global_login_organization_names property if configured (by calling
    try_sso_next_login_org()) ; else displays a specific message ("not member
    of this org", rather than "Login Failed")
    '''

    # Blueprint act strangely after user is logged in once. It will skip
    # SSO and user/login when trying to log in from different account and
    # directly get here. This is a workaround to force login user if not
    # redirected from loging page (as it sets important values in session)
    if not session.get('from_login'):
        return sso(id)

    from_login = session['from_login']
    session['from_login'] = False
    org_id = session.get('organization_id', id)
    org_url = str(url_for(controller="organization",
                          action='read',
                          id=org_id))

    g_ = model.Group.get(org_id)
    client = None
    error = None
    if g_:
        client = Clients.get_client(g_)
        try:
            # Grab state from query parameter if session does not have it
            session['state'] = session.get('state', request.params.get('state'))
            userinfo, app_admin, app_user, access_token, id_token \
                = client.callback(session['state'], request.args)
            session['access_token'] = access_token
            session['id_token'] = id_token
            session.save()
        except OIDCError as e:
            error = OIDCError

    if not g_ or error:
        is_login_to_org = 'is_login_to_org' in session and session['is_login_to_org']
        log.info('callback - unknown organization or OIDCError: g_=%s, OIDCError=%s, is_login_to_org=%s, session=%s', g_, error, is_login_to_org, session)
         # reinit for next time :
        session['is_login_to_org'] = False
        session.save()

        if not is_login_to_org:
            sso_ok = try_sso_next_login_org(id)
            if sso_ok:
                return sso_ok

        # displaying error messages on IHM :

        login_failed_message = "Connexion échouée. Vous n'êtes pas membre d'une des organisations permettant l'usage du bouton de connexion global (" + ", ".join(get_global_login_organization_names()) + "). Demandez à la personne qui vous a invitée, ou utilisez le bouton de connexion à l'organisation présent sur une organisation dont vous êtes membre."
        if not g_:
            flash_error(login_failed_message if not is_login_to_org else "Organisation inexistante")

        # there has been an OIDCError :
        flash_error(login_failed_message if not is_login_to_org else "Vous n'êtes pas membre de cette organisation")

        return redirect_to(org_url if is_login_to_org else str(url_for(controller="organization",
                                                                          action='read',
                                                                          id=get_global_login_organization_names()[0])), qualified=True)

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
        except Exception as e:
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
        id_token = session.get('id_token')
        session.invalidate()
        c.user = None
        c.userobj = None
        response = Response()
        for cookie in request.cookies:
            response.delete_cookie(cookie)

        # redirect to IDP logout (https://doc.ozwillo.com/#3-single-sign-out)
        logout_url += '?id_token_hint=%s&' % id_token
        logout_url += 'post_logout_redirect_uri=%s' % redirect_uri

        log.info('Redirecting user to: %s' % logout_url)

        return redirect_to(str(logout_url))
    return redirect_to(org_url)


ozwillo.add_url_rule(rule=u'/user/slo', view_func=slo)
