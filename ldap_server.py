from ldap3 import Server, Connection, ALL, HASHED_MD5
import hashlib

class LdapService:
    def __init__(self, admin_pwd):
        self.LDAP_ADMIN_PWD = admin_pwd
        self.ldap_server = Server('your_ldap_server')  # Replace with LDAP server details
        self.ldap_admin_dn = 'cn=admin,dc=example,dc=com'  # Replace with LDAP admin DN

    def login(self, username, password):
        # Constructing the DN (Distinguished Name) of the user
        user_dn = f"uid={username},{self.LDAP_OU},{self.LDAP_GROUP}"

        try:
            # Initializing LDAP connection
            ldap_connection = ldap.initialize(self.LDAP_SERVER)
            ldap_connection.simple_bind_s(self.LDAP_ADMIN_DN, self.LDAP_ADMIN_PWD)

            # Attempting authentication
            ldap_connection.bind_s(user_dn, password)

            # If authentication succeeds, perform a search to retrieve user data
            results = ldap_connection.search_s(user_dn, ldap.SCOPE_BASE)
            
            return results

        except ldap.LDAPError as e:
            return f"Authentication failed: {e}"

        finally:
            if ldap_connection:
                ldap_connection.unbind()

    def register(self, user):
        # Constructing the DN (Distinguished Name) of the user
        user_dn = f"uid={user['username']},{self.LDAP_OU},{self.LDAP_GROUP}"

        try:
            # Initializing LDAP connection
            ldap_connection = ldap.initialize(self.LDAP_SERVER)
            ldap_connection.simple_bind_s(self.LDAP_ADMIN_DN, self.LDAP_ADMIN_PWD)

            # Constructing LDAP attributes for the user entry
            attributes = [
                ('objectClass', [b'inetOrgPerson', b'posixAccount']),
                ('uid', [user['username'].encode('utf-8')]),
                ('cn', [user['full_name'].encode('utf-8')]),
                ('sn', [user['last_name'].encode('utf-8')]),
                ('givenName', [user['first_name'].encode('utf-8')]),
                ('userPassword', [ldap_salted_md5(user['password']).encode('utf-8')]),
            ]

            # Adding the user entry to the LDAP directory
            ldap_connection.add_s(user_dn, attributes)

            return None  # Operation successful, no errors

        except ldap.LDAPError as e:
            return f"User registration failed: {e}"

        finally:
            if ldap_connection:
                ldap_connection.unbind()

# Example usage:
# ldap_service = LdapService(admin_pwd="<your_admin_pwd>")
# user_data = {
#     'username': 'newuser',
#     'full_name': 'New User',
#     'first_name': 'New',
#     'last_name': 'User',
#     'password': 'password123',
# }
# result = ldap_service.register(user_data)
# print(result)
