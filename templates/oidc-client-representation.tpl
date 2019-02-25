{
    "clientId": "{{ clientid }}",
    "secret": "{{ oidc_client_secret }}",
    "protocol": "openid-connect",
    "publicClient": false,
    "clientAuthenticatorType": "client-secret",
    "redirectUris": [
        "{{ client_https_url }}{{ oidc_redirect_uri }}"
    ]
}
