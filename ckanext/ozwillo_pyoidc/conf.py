PORT = 8666
#BASE = "https://lingon.ladok.umu.se:" + str(PORT) + "/"
BASE = "http://ckan.dev.entrouvert.org"


# If BASE is https these has to be specified
SERVER_CERT = "certs/server.crt"
SERVER_KEY = "certs/server.key"
CA_BUNDLE = None

VERIFY_SSL = False

# information used when registering the client, this may be the same for all OPs

ME = {
    "application_type": "web",
    "application_name": "idpproxy",
    "contacts": ["ops@example.com"],
    "redirect_uris": ["%sauthz_cb" % BASE],
    "post_logout_redirect_uris": ["%slogout" % BASE],
    "response_types": ["code"]
}

BEHAVIOUR = {
    "response_type": "code",
    "scope": ["openid", "profile", "email", "address", "phone"],
}

ACR_VALUES = ["SAML"]

# The keys in this dictionary are the OPs short userfriendly name
# not the issuer (iss) name.

CLIENTS = {
    # The ones that support webfinger, OP discovery and client registration
    # This is the default, any client that is not listed here is expected to
    # support dynamic discovery and registration.
    # Supports OP information lookup but not client registration
    "ozwillo": {
        "srv_discovery_url": "https://accounts.ozwillo-preprod.eu/",
        "client_registration": {
            "client_id": None,
            "client_secret": None,
            "redirect_uris": [],
        },
        "behaviour": {
            "response_type": "code",
            "scope": ["openid", "profile", "email"]
        },
        "allow": {
            "issuer_mismatch": True
        }
    }
}
