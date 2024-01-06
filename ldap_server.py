import ldap
import hashlib
import sys
from base64 import b64encode

class LdapService():

    ldap_server = "ldap://192.168.56.3:389"
    ldap_ou = "ssirp"
    ldap_group = "ssirp"

    LDAP_ADMIN_DN = "cn=admin,dc=securediscord,dc=tn"
    LDAP_ADMIN_PWD = ""

    def __init__(self, admin_pwd):
        self.LDAP_ADMIN_PWD = admin_pwd

    def login(self, username, password):
        self.username = username
        self.password = password

        # organization user's domain
        user_dn = f"cn={username},cn={self.ldap_group},ou={self.ldap_ou},dc=securediscord,dc=tn"
        print(user_dn)

        # base domain
        LDAP_BASE_DN = f"cn={self.ldap_group},ou={self.ldap_ou},dc=securediscord,dc=tn"


        # starting connection
        ldap_client = ldap.initialize(self.ldap_server)

        search_filter = f"cn={username}"
        
        try:
            # if authentication successful, get the full user data
            ldap_client.bind_s(user_dn, self.password)
            result = ldap_client.search_s(
                LDAP_BASE_DN, ldap.SCOPE_SUBTREE, search_filter)
            
            ldap_client.unbind_s()
            print(result)
            return None
        
        except ldap.INVALID_CREDENTIALS:
            ldap_client.unbind()
            print("Wrong username or password..")
            return "Wrong username or password.."
        
        except ldap.SERVER_DOWN:
            print("Server is down at the moment, please try again later!")
            return "Server is down at the moment, please try again later!"
        
        except ldap.LDAPError:
            ldap_client.unbind_s()
            print("Authentication error!")
            return "Authentication error!"

    def register(self, user):
        # base domain
        LDAP_BASE_DN = "cn=" + self.ldap_group + \
            ",ou=" + self.ldap_ou + ",dc=securediscord,dc=tn"

        # home base
        HOME_BASE = "/home/users"

        # new user domain
        dn = 'cn=' + user['username'] + ',' + LDAP_BASE_DN
        home_dir = HOME_BASE + '/' + user['username']
        gid = user['group_id']

        # encoding password using md5 hash function
        hashed_pwd = hashlib.sha256(user['password'].encode("UTF-8")).hexdigest()

        entry = []
        entry.extend([
            ('objectClass', [b'inetOrgPerson', b'posixAccount', b'top']),
            ('uid', user['username'].encode("UTF-8")),
            ('givenname', user['username'].encode("UTF-8")),
            ('sn', user['username'].encode("UTF-8")),
            ('mail', user['email'].encode("UTF-8")),
            ('uidNumber', user['uid'].encode("UTF-8")),
            ('gidNumber', str(gid).encode("UTF-8")),
            ('loginShell', [b'/bin/sh']),
            ('homeDirectory', home_dir.encode("UTF-8")),
            ('userPassword', [hashed_pwd.encode("UTF-8")])
        ])

        # connect to host with admin
        ldap_conn = ldap.initialize(self.ldap_server)
        ldap_conn.simple_bind_s(self.LDAP_ADMIN_DN, self.LDAP_ADMIN_PWD)

        try:
            # add entry in the directory
            ldap_conn.add_s(dn, entry)
            print("Registration successful")
            return None
        
        except ldap.LDAPError as e:
            print(f"Registration failed: {e}")
            return str(e)
        
        finally:
            # disconnect and free memory
            ldap_conn.unbind_s()

# Test case
# CONNECTION WILL ONLY WORK WHEN THE SERVER IS UP
# TODO change admin password
s = LdapService(admin_pwd="tekup") # <ur_admin_pwd>

# s.login(username="ala", password="1234")
user_obj = {
    'username': 'guest',
    'password': '0000',
    'email': 'u@gmail.com',
    'gender': 'male',
    'group_id': 500,
    'uid': '1600222'
}
# s.register(user_obj)
