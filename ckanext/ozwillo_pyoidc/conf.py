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

ACR_VALUES = None

CLIENT = {
    "srv_discovery_url": "https://accounts.ozwillo-preprod.eu/",
    "client_registration": {
        "client_id": None,
        "client_secret": None,
        "redirect_uris": [],
    },
    "behaviour": {
        "response_type": "code",
        "scope": ["openid", "profile"]
    },
    "allow": {
        "issuer_mismatch": True
    }
}
