import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class device(object):
    def __init__(self, router_ip, username, password):
        self.router_ip = router_ip
        self.username = username
        self.password = password

# Get authentication token
# Returns token
    def token(self):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/auth/token-services"
        api_auth = (self.username, self.password)
        api_headers = {'Content-Type':'application/json'}
        try:
            get_token = requests.post(url=api_url, auth=api_auth, headers=api_headers, verify=False)
            if get_token.status_code == 200:
                token_data = json.loads(get_token.text)['token-id']
                return token_data
        except get_token.status_code != 200:
            if get_token.status_code == 401 | get_token.status_code == 403:
                message = "Error authenticating with device."
                return message
            elif get_token.status_code != 200:
                message = "Error initiating connection with device."
                return message


class acl(device):
    def __init__(self, router_ip, router_token):
        #device.__init__(self, router_ip)
        self.router_ip = router_ip
        self.router_token = router_token
        # self.router_port = router_port

    def get(self, acl_id):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id 
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token}
        #acl_get = print(api_url, api_headers)
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False)
        output_acl_get = acl_get.text
        return output_acl_get

    def get_all(self):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl" 
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token}
        #acl_get = print(api_url, api_headers)
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False)
        output_acl_get_all = acl_get.text
        return output_acl_get_all

    def configure(self, acl_sequence, acl_protocol, acl_src_ip, acl_dst_ip, acl_action, srcport='', srcop='eq', srcport_end='', dstport='eq', dstop='',  dstport_end=''):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl"
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        payload = {
            "kind": "object#acl",
            "rules": [
                {
                    "sequence" : acl_sequence,
                    "protocol": acl_protocol,
                    "source": acl_src_ip,
                    "destination": acl_dst_ip,
                    "action": acl_action,
                    # "l4-options" : {
                    #     "src-port-start" : "ftp",
                    #     "src-port-op" : "eq",
                    #     "dest-port-start" : "ftp",
                    #     "dest-port-op": "eq"
                    # }
                }
                ]
            }
        acl_config = requests.post(url=api_url, headers=api_headers, json=payload, verify=False)
        if acl_config.status_code == 200 :
            output_acl_config = acl_config.text
            return output_acl_config
        else:
            message = 'error'
            return message

# work in progress, needs to add append function
    def add_existing(self, acl_id, acl_sequence, acl_protocol, acl_src_ip, acl_dst_ip, acl_action, srcport='', srcop='eq', srcport_end='', dstport='', dstop='eq',  dstport_end=''):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False)
        existing_rules = json.loads(acl_get.text)['rules']
        #existing_rules.append(payload)
        new_rule = {
                        "sequence" : acl_sequence,
                        "protocol": acl_protocol,
                        "source": acl_src_ip,
                        "destination": acl_dst_ip,
                        "action": acl_action,
        }

        srcport_options = {
            "src-port-start" : srcport,
            "src-port-op" : srcop,
        }

        srcport_end_options = {
            "src-port-end" : srcport_end,
        }

        dstport_options = {
            "dest-port-start" : dstport,
            "dest-port-op" : dstop
        }

        dstport_end_options = {
            "dest-port-end" : dstport_end,
        }

        option_payload = {}
        
        port_payload = { "l4-options" : option_payload }

        if len(srcport) >= 1:
            if srcop == "eq":
                if len(srcport_end) < 1:
                    option_payload.update(srcport_options)
                    new_rule.update(port_payload)
                elif len(srcport_end) >= 1:
                    option_payload.update(srcport_options)
                    option_payload.update(srcport_end_options)
                    new_rule.update(port_payload)
        elif len(srcport) < 1:
            pass
            
        if len(dstport) >= 1:
            if dstop == "eq":
                if len(dstport_end) < 1 :
                    option_payload.update(dstport_options)
                    new_rule.update(port_payload)
                elif len(dstport_end) >= 1 :
                    option_payload.update(dstport_options)
                    option_payload.update(dstport_end_options)
                    new_rule.update(port_payload)
        elif len(dstport) < 1 :
            pass

        # if len(srcport) | len(srcport) + len(srcport_end) > 1:
        #     new_rule.update(port_options)
        
        # Add new rule into the payload
        existing_rules.append(new_rule)

        payload = {
            "kind": "object#acl",
            "rules": existing_rules
            }

        #x=json.dumps(payload)
        # print (payload)
        #print(x)

        acl_config = requests.put(url=api_url, headers=api_headers, json=payload, verify=False)
        output_acl_config = acl_config.text
        return output_acl_config

    def remove_existing(self, acl_id, acl_sequence):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        acl_get = requests.get(url=api_url, headers=api_headers, verify=False)
        full_response = json.loads(acl_get.text)
        existing_rules = json.loads(acl_get.text)['rules']

        new_rule = [x for x in existing_rules if not (int(acl_sequence) == x.get('sequence'))]  
        print(new_rule)
        print(len(new_rule))

        print(len(existing_rules))

        payload = {
            "kind": "object#acl",
            "rules": new_rule
            }

        #x=json.dumps(payload)
        #print ('here is your payload')
        #print (x)
        #print(x)
        print(payload)

        acl_config = requests.put(url=api_url, headers=api_headers, json=payload, verify=False)
        output_acl_config = acl_config.text
        return output_acl_config
   
    def modify(self, acl_id, acl_sequence, acl_protocol, acl_src_ip, acl_dst_ip, acl_action):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token }
        payload = {
            "kind": "object#acl",
            "rules": [
                {
                    "sequence" : acl_sequence,
                    "protocol": acl_protocol,
                    "source": acl_src_ip,
                    "destination": acl_dst_ip,
                    "action": acl_action,
                }
                ]
            }
        acl_config = requests.put(url=api_url, headers=api_headers, json=payload, verify=False)
        output_acl_config = acl_config.text
        return output_acl_config

    def delete(self, acl_id):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/acl/" + acl_id 
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token}
        acl_del = requests.delete(url=api_url, headers=api_headers, verify=False)
        output_acl_del = acl_del.text
        return output_acl_del

class interface(device):
    def __init__(self, router_ip, router_token):
        self.router_ip = router_ip
        self.router_token = router_token

    def get_all(self):
        api_url = "https://" + self.router_ip + ":55443" + "/api/v1/interfaces"
        api_headers={ 'Content-Type': 'application/json', 'X-auth-token': self.router_token}
        int_get = requests.get(url=api_url, headers=api_headers, verify=False)
        output_int_get_all = int_get.text
        return output_int_get_all

    def configure(self, router_interface, interface_ip_address, interface_netmask, *interface_status):
        print (router_interface, interface_ip_address, interface_status)

    def link_status(self, router_interface, interface_status):
        print (router_interface, interface_status)
