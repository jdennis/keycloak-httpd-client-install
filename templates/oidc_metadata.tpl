{% for location in protected_locations %}
{
  "application_type":"web",
  "redirect_uris":
    ["{{ http_url }}{{ location }}/redirect_uri",
     "{{ http_url }}/{{ app_name }}/logged_out.html"],
  "client_name": "{{ mellon_entity_id }}"
}
{% endfor %}
