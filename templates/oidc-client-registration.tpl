{
    "client_name": "{{ clientid }}",
    "redirect_uris": [
        "{{ client_https_url }}{{ oidc_redirect_uri }}"
        {% if oidc_logout_uri %}
        ,"{{ client_https_url }}{{ oidc_logout_uri }}",
        {% endif %}
    ]
}
