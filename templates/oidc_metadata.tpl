{
  "application_type":"web",
  "redirect_uris":
    [
    {% for uris in redirect_uris %}
     "{{ http_url }}{{ uris }}"{% if not loop.last %}, {% endif %}
     {% endfor %}
    ]
  {% if client_uri %}
  ,"client_uri": "{{ http_url }}{{ client_uri }}"
  {% endif %}
}
