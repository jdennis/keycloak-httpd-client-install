<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  entityID="{{ mellon_entity_id }}">
 <SPSSODescriptor
   AuthnRequestsSigned="true"
   WantAssertionsSigned="true"
   protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
   <KeyDescriptor use="signing">
     <ds:KeyInfo>
       <ds:X509Data>
         <ds:X509Certificate>{{ sp_signing_cert }}</ds:X509Certificate>
       </ds:X509Data>
     </ds:KeyInfo>
   </KeyDescriptor>
   <KeyDescriptor use="encryption">
     <ds:KeyInfo>
       <ds:X509Data>
         <ds:X509Certificate>{{ sp_encryption_cert }}</ds:X509Certificate>
       </ds:X509Data>
     </ds:KeyInfo>
   </KeyDescriptor>
   <SingleLogoutService
     Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
     Location="{{ mellon_http_url }}{{ mellon_endpoint_path }}/logout" />
   <SingleLogoutService
     Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
     Location="{{ mellon_http_url }}{{ mellon_endpoint_path }}/logout" />
   <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
   <AssertionConsumerService
     index="0"
     isDefault="true"
     Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
     Location="{{ mellon_http_url }}{{ mellon_endpoint_path }}/postResponse" />
   <AssertionConsumerService
     index="1"
     Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
     Location="{{ mellon_http_url }}{{ mellon_endpoint_path }}/artifactResponse" />
   <AssertionConsumerService
     index="2"
     Binding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS"
     Location="{{ mellon_http_url }}{{ mellon_endpoint_path }}/paosResponse" />
 </SPSSODescriptor>
  {% if mellon_organization_name or mellon_organization_display_name or mellon_organization_url %}
  <Organization>
    {% if mellon_organization_name %}
    <OrganizationName>{{ mellon_organization_name }}</OrganizationName>
    {% endif %}
    {% if organization__display_name %}
    <OrganizationDisplayName>{{ mellon_organization_name }}</OrganizationDisplayName>
    {% endif %}
    {% if mellon_organization_url %}
    <OrganizationURL>{{ mellon_organization_url }}</OrganizationURL>
    {% endif %}
  </Organization>
  {% endif %}
</EntityDescriptor>
