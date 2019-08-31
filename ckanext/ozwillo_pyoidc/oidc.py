from oic.exception import MissingAttribute
from oic import oic, rndstr
from oic.oauth2 import ErrorResponse
from oic.oic import ProviderConfigurationResponse, AuthorizationResponse
from oic.oic import RegistrationResponse
from oic.oic import AuthorizationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

import logging

logger = logging.getLogger(__name__)

import conf

class OIDCError(Exception):
    pass


class Client(oic.Client):
    def __init__(self, client_id=None, client_secret=None, ca_certs=None,
                 client_prefs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, behaviour=None):
        oic.Client.__init__(self, client_id, client_secret, ca_certs,
                            client_prefs, client_authn_method,
                            keyjar, verify_ssl)
        if behaviour:
            self.behaviour = behaviour

    def create_authn_request(self, acr_value=None):
        state = rndstr()
        nonce = rndstr()
        request_args = {
            "response_type": self.behaviour["response_type"],
            "scope": self.behaviour["scope"],
            "state": state,
            "nonce": nonce,
            "redirect_uri": self.registration_response["redirect_uris"][0]
        }

        if acr_value is not None:
            request_args["acr_values"] = acr_value

        cis = self.construct_AuthorizationRequest(request_args=request_args)
        logger.debug("request: %s" % cis)

        url, body, ht_args, cis = self.uri_and_body(AuthorizationRequest, cis,
                                                    method="GET",
                                                    request_args=request_args)

        logger.debug("body: %s" % body)
        logger.info("URL: %s" % url)
        logger.debug("ht_args: %s" % ht_args)

        return str(url), ht_args, state

    def callback(self, state, response):
        """
        This is the method that should be called when an AuthN response has been
        received from the OP.
        """
        authresp = self.parse_response(AuthorizationResponse, response,
                                       sformat="dict", keyjar=self.keyjar)
        app_admin = False
        app_user = False
        try:
            if state != authresp['state']:
                raise OIDCError("Invalid state %s." % authresp["state"])
        except AttributeError:
            raise OIDCError("access denied")

        if isinstance(authresp, ErrorResponse):
            raise OIDCError("Access denied")

        try:
            self.id_token[authresp["state"]] = authresp["id_token"]
        except KeyError:
            pass

        if self.behaviour["response_type"] == "code":
            # get the access token
            try:
                args = {
                    "grant_type": "authorization_code",
                    "code": authresp["code"],
                    "redirect_uri": self.registration_response[
                        "redirect_uris"][0],
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }

                atresp = self.do_access_token_request(
                    scope="openid", state=authresp["state"], request_args=args,
                    authn_method=self.registration_response["token_endpoint_auth_method"])
                id_token = atresp['id_token']
                app_admin = 'app_admin' in id_token and id_token['app_admin']
                app_user = 'app_user' in id_token  and id_token['app_user']
            except Exception as err:
                logger.error("%s" % err)
                raise

            if isinstance(atresp, ErrorResponse):
                raise OIDCError("Invalid response %s." % atresp["error"])

        inforesp = self.do_user_info_request(state=authresp["state"],
                                             behavior='use_authorization_header')

        if isinstance(inforesp, ErrorResponse):
            raise OIDCError("Invalid response %s." % inforesp["error"])

        userinfo = inforesp.to_dict()

        logger.debug("UserInfo: %s" % inforesp)

        return userinfo, app_admin, app_user, self.access_token, self.id_token

def create_client(**kwargs):
    """
    kwargs = config.CLIENT.iteritems
    """
    _key_set = set(kwargs.keys())
    args = {}
    for param in ["verify_ssl", "client_id", "client_secret"]:
        try:
            args[param] = kwargs[param]
        except KeyError:
            try:
                args[param] = kwargs['client_registration'][param]
            except KeyError:
                pass
        else:
            _key_set.discard(param)

    client = Client(client_authn_method=CLIENT_AUTHN_METHOD,
                    behaviour=kwargs["behaviour"],
                    verify_ssl=conf.VERIFY_SSL, **args)

    # The behaviour parameter is not significant for the election process
    _key_set.discard("behaviour")
    # I do not understand how this was ever working without discarding this
    # Below is not a case where _key_set includes "registration_response"
    _key_set.discard("registration_response")
    for param in ["allow"]:
        try:
            setattr(client, param, kwargs[param])
        except KeyError:
            pass
        else:
            _key_set.discard(param)

    if _key_set == set(["client_info"]):  # Everything dynamic
        # There has to be a userid
        if not userid:
            raise MissingAttribute("Missing userid specification")

        # Find the service that provides information about the OP
        issuer = client.wf.discovery_query(userid)
        # Gather OP information
        _ = client.provider_config(issuer)
        # register the client
        _ = client.register(client.provider_info["registration_endpoint"],
                            **kwargs["client_info"])
    elif _key_set == set(["client_info", "srv_discovery_url"]):
        # Ship the webfinger part
        # Gather OP information
        _ = client.provider_config(kwargs["srv_discovery_url"])
        # register the client
        _ = client.register(client.provider_info["registration_endpoint"],
                            **kwargs["client_info"])
    elif _key_set == set(["provider_info", "client_info"]):
        client.handle_provider_config(
            ProviderConfigurationResponse(**kwargs["provider_info"]),
            kwargs["provider_info"]["issuer"])
        _ = client.register(client.provider_info["registration_endpoint"],
                            **kwargs["client_info"])
    elif _key_set == set(["provider_info", "client_registration"]):
        client.handle_provider_config(
            ProviderConfigurationResponse(**kwargs["provider_info"]),
            kwargs["provider_info"]["issuer"])
        client.store_registration_info(RegistrationResponse(
            **kwargs["client_registration"]))
    elif _key_set == set(["srv_discovery_url", "client_registration"]):
        _ = client.provider_config(kwargs["srv_discovery_url"])
        client.store_registration_info(RegistrationResponse(
            **kwargs["client_registration"]))
    else:
        raise Exception("Configuration error ?")

    return client
