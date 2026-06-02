FROM osixia/openldap:1.5.0


COPY people.ldif    /container/service/slapd/assets/config/bootstrap/ldif/10-people.ldif
COPY groups.ldif    /container/service/slapd/assets/config/bootstrap/ldif/20-groups.ldif
COPY acl.ldif       /container/service/slapd/assets/config/bootstrap/ldif/30-acl.ldif

EXPOSE 389 636

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
