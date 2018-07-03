{
  "application_type":"web",
  "redirect_uris":
    {% for location in protected_locations %}
    ["{{ http_url }}{{ location }}/redirect_uri",
    {% endfor %}
     "{{ http_url }}/{{ app_name }}/logged_out.html"],
  "client_name": "{{ mellon_entity_id }}",
  {% if client_uri %}
  "client_uri": "{{ client_uri }}",
  {% endif %}
}
