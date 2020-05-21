#!/usr/bin/env python
# --------------------------------------------------------------------------------------- #
global directory, ka
import sys, os
from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakAuthenticationError
import json
import requests
import argparse

class KCHelper:
  def __init__(self,
    kc_api='https://example.com',
    kc_admin='admin',
    kc_admin_pw='guess',
    user='guess',
    user_pw='guess',
    kc_realm='master',
    user_realm='dev',
    default_pw='put one you lile',
    default_roles = ["uma_authorization","author","offline_access"],
    admin_roles = ["admin"],
    user_roles = ["USER"]):

    self.default_pw = default_pw
    self.kc_api = kc_api
    self.user_realm = user_realm
    self.user = user
    self.user_pw = user_pw
    self.kc_realm = kc_realm
    self.kc_admin = kc_admin
    self.kc_admin_pw = kc_admin_pw
    # Since validating SSL, make sure to export REQUESTS_CA_BUNDLE=<PATH_TO_ROOTCA.CRT> (export REQUESTS_CA_BUNDLE=$(pwd)/rootca.crt)
    # self.ka=self.get_keycload_admin()
    self.ka = self.get_keycload_admin()
    self.default_roles = default_roles
    self.admin_roles = admin_roles
    self.user_roles = user_roles
    self.default_users = ["anaconda"]
    self.default_groups = []
    self.kc_auth_header = self.get_kc_auth_header()

  def get_keycload_admin(self,realm=None):

     ka = KeycloakAdmin(server_url=f"{self.kc_api}/auth/", username=self.kc_admin, password=self.kc_admin_pw, realm_name=self.kc_realm, verify=True)
     ka.realm_name=self.user_realm
     return ka

  def get_kc_auth_header (self):
    url = f"{self.kc_api}/auth/realms/{self.kc_realm}/protocol/openid-connect/token"
    print(f"Getting token from {url}")
    data = {
      'grant_type': 'password',
      'username': self.kc_admin,
      'password': self.kc_admin_pw,
      'client_id': 'admin-cli',
    }
    resp = requests.post(url, data=data)
    assert resp.status_code == 200
    token =  resp.json()['access_token']
    return { 'Authorization' : 'Bearer {token}'.format(token=token)}

  def set_default_passwords(self):
    self.ka.realm_name=self.kc_realm
    master_id = self.ka.get_user_id(self.kc_admin)
    self.ka.set_user_password(user_id=master_id, password=self.default_pw,temporary=False)

    self.ka.realm_name=self.user_realm
    user_id = self.ka.get_user_id(self.user)
    self.ka.set_user_password(user_id=user_id, password=self.default_pw,temporary=False)


  def add_users(self, users, email_domain='anaconda'):
    if isinstance(users,str): users = users.split()
    print (f"{users} {type(users)}")

    for user in users:
      new_user = self.ka.create_user(
       dict(email=user + "@" + email_domain, username=user, enabled=True, firstName=user, lastName=user,
         credentials=[{"value": self.default_pw, "type": "password", }]),
       )


  def add_groups(self, groups,parent_group_id = None):
    if isinstance(groups,str): groups=groups.split()

    for group in groups:
      group_id = self.get_gid_for_group(group)
      if len(group_id) == 0:
        self.ka.create_group(dict(name=group), parent=parent_group_id )
      else:
        print ("Already There")


  def get_gid_for_group(self,group):
     try:
       group_id = [ gid['id'] for gid in self.ka.get_groups() if (gid["name"]==group)][0]
     except:
       print ("Group {} does not exist".format(group))
       return ""
     else:
       return group_id

  def add_user_to_group(self,user,group_path):
     user_id = self.ka.get_user_id(user)
     group_id = self.ka.get_group_by_path(group_path,True)
     print (f"{user}={user_id} {group_path}={group_id}")
     if group_id is not None:
       group_id = group_id['id']
       if (len(group_id ) > 0 and len(user_id)) > 0:
         self.ka.group_user_add(user_id,group_id)
     else:
      print (f"no such group {group}")

  def add_all_users_to_all_groups(self):
      i: int = 0
      kc_users = self.ka.get_users()
      kc_groups =self.ka.get_groups()

      for kc_user in kc_users:
        group_id = [g['id'] for g in kc_groups if g['name'].lower() == kc_user['username'].lower()]
        if len(group_id) > 0:
            self.ka.group_user_add(kc_user['id'], group_id[0])

  def delete_users_and_groups(self):
    [self.ka.delete_user(u['id']) for u in self.ka.get_users() if u['username'] not in self.default_users]
    [self.ka.delete_group(g['id']) for g in self.ka.get_groups() if g['name']
     not in self.default_groups ]

  def import_org(self,src):

    import yaml
    from os import path

    if (type(src) == dict):
      org=src
    elif (type(src) == str and path.exists(src)):
      with open(src,"r") as file:
        org = yaml.load(file, Loader=yaml.FullLoader)
    else:
      print ("need a filename or a dictionary with users and groups")
      return

    print ("importing from {}".format(org))


    def walk_tree(parent, children, tree_path = ""):
      # print ("debug p: {} t:{} c: {}".format(p,type(cs),cs))
      if isinstance(children, list):
        for leaf_or_branch in children:
          if isinstance(leaf_or_branch, str):  # leaf = user
            print ("adding usr {} ".format(leaf_or_branch))
            self.add_users(leaf_or_branch)
            if parent != "root":
              print("adding usr {} to group {} path {} ".format(leaf_or_branch, parent, tree_path))
              self.add_user_to_group(leaf_or_branch,tree_path)
            else:
              walk_tree(parent, leaf_or_branch, tree_path )   # another branch = group
          elif isinstance(children, (tuple, dict)):
            for child, grand_children in children.items():
              print("adding group {} path {} ".format(child,tree_path + "/" + child))
              parent_group_id = self.ka.get_group_by_path(tree_path,True)
              if parent_group_id is not None:
                parent_group_id=parent_group_id['id']
              print ("adding group {} with parent_group_id {}".format(child, parent_group_id))
              self.add_groups(child,parent_group_id)
              walk_tree(child, grand_children, tree_path +"/" + child)
          else:
            print("should raise an error")

    for k, v in org.items():
      # print("add group {}".format(k))  # add root group
      walk_tree(k, v) # not adding root..

  def kcadm(self, method = "get", url = None, payload = None , validate = True):
    rsp={}
    if url is None: url = self.user_realm
    my_url = f"{self.kc_api}/auth/admin/realms/{url}"
    print (f"my_url = {my_url}")
    # print (f"headers={self.kc_auth_header}, url={my_url}")
    if method == "get":
      rsp = requests.get(my_url, headers = self.kc_auth_header, verify = validate)
    elif method == "post":
      rsp = requests.post(my_url, json = payload, headers = self.kc_auth_header, verify = validate)
    elif method == "put":
      rsp = requests.put(my_url, json = payload, headers = self.kc_auth_header , verify = validate)
    elif method == "del":
      pass

    if type(rsp) == requests.models.Response:
      print (rsp.status_code)
      try:
        frsp = json.loads(rsp.content)
      except:
        frsp = rsp
      return frsp
    else:
      print ("no requests object was returned")
    return rsp

  def set_default_roles(self):
      rsp = self.kcadm()
      print (" default roles before: {}".format(rsp['defaultRoles']))
      rsp['defaultRoles'] = self.default_roles
      self.kcadm("put",payload=rsp)
      rsp_a = self.kcadm()
      print (" default roles after: {}".format(rsp_a['defaultRoles']))


  def add_roles_to_group(self,group,roles):
    roles_pl = [ i for i in self.ka.get_realm_roles() if i['name'] in roles]
    gid = self.get_gid_for_group(group)
    if len(gid) > 0 and len (roles_pl) > 0:
      c = self.kcadm("post",f"{self.user_realm}/groups/{gid}/role-mappings/realm",roles_pl)
    else:
      print ("group or roles are missing")


 # replace with this... https://github.com/redacted/XKCD-password-generator
def get_random_password(length=10):
  import string, os
  chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
  password = ''
  for i in range(length):
    password += chars[ord(os.urandom(1)) % len(chars)]
  return password

def set_default_passwords(args):
  if args.default_pw is None:
      if "default_pw" not in conf:
          default_pw = get_random_password()
      else : default_pw=conf["default_pw"]
  print (f"password: {default_pw}")

  kch=KCHelper(kc_api=conf["server"].rstrip("/"),
               kc_admin_pw=conf["kc_admin_pw"],
               user=conf["ate_user"],
               default_pw=default_pw)

  kch.set_default_passwords()
  conf["kc_admin_pw"] = conf["user_pw"] = default_pw
  print (f"export KC_ADMIN_PW={default_pw}")
  print (f"export USER_PW={default_pw}")

def add_users(args):
    print ("adding se users ")
    if args.users is None:
        users = "admin"
    else:
        if isinstance(args.users,list):
            users = args.users
        elif isinstance(args.users,str):
            users = args.users.split(" ")

    kch=KCHelper(kc_api=conf["server"].rstrip("/"),
            kc_admin_pw=conf["default_pw"],
            default_pw=conf["default_pw"],
            user=conf["ate_user"])
    kch.set_default_roles()
    kch.add_users(users)
    kch.add_groups("admins users testers")
    kch.add_user_to_group("admin","/admins")
    for user in users:
      kch.add_user_to_group(user,"/users")
    kch.add_roles_to_group("admins","admin")
    kch.add_roles_to_group("users","USER")

def get_credentials(env="fqdn server default_pw kc_admin kc_admin_pw ate_user ate_user_pw".split()):
    for var in env:
        if os.getenv(var.upper()) is not None: conf[var.lower()] = os.getenv(var.upper())
    return conf

if __name__ == "__main__":

    conf = {}
    FQDN = 'example.com'
    conf["server"] = f"http://{FQDN}"
    conf["ate_user"] = 'user'
    conf["ate_user_pw"] = 'password'
    conf["ate_realm"] = "dev"
    conf["kc_admin "]= 'admin'
    conf["kc_admin_pw"] = 'password'
    conf["kc_realm"] = "master"

    conf ["directory"] = f"{FQDN}-users.yaml"
    conf["email_domain"] = 'anaconda.com'
    conf["default_roles"] = "author uma_authorization offline_access".split()
    conf["admin_roles"] = "admin"
    conf["user_roles"] = "USER"



    conf = get_credentials()
    import argparse

    parser = argparse.ArgumentParser(description='Reset passwords and add users via cli')
    subparsers = parser.add_subparsers(title = "sub commands", description = "reset-passwords or add-users")

    paeser_reset_passwords = subparsers.add_parser("reset-passwords",  help = 'With no args, changes kc_admin/ate_user password to default_pw (env variables)')
    paeser_reset_passwords.add_argument('--default_pw',help='password to use')
    paeser_reset_passwords.set_defaults(func=set_default_passwords)

    parser_add_users = subparsers.add_parser("add-users",  help ='With no args, add hassam, rachel and eden to TE users')
    parser_add_users.add_argument('--users',help='users seperated by space')
    parser_add_users.set_defaults(func=add_users)
    args = parser.parse_args()
    args.func(args)

