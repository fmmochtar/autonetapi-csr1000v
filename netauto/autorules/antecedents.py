import requests
import time
import json

#from .pycsrmgmt import *

#list_of_attackers = []
#acl_list = []

# This is the main class

class analyze(object):
    def __init__(self, entropy_value, entropy_threshold, source_ip, destination_ip, destination_port, attack_total, attack_threshold, list_of_attackers, acl_list):
        self.entropy_value = entropy_value
        self.entropy_threshold = entropy_threshold
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.attack_total = attack_total
        self.attack_threshold = attack_threshold
        self.list_of_attackers = list_of_attackers
        self.acl_list = acl_list

    # Rules starts here

    def assert_rule0(self):
        if (self.source_ip in self.list_of_attackers and self.destination_ip in self.acl_list) or (self.source_ip in self.acl_list):
            return True
        else:
            return False
    def assert_rule1(self):
        if self.entropy_value < self.entropy_threshold:
            return True
        else:
            return False
    def assert_rule2(self):
        if self.source_ip in self.list_of_attackers and max(len(self.source_ip in self.list_of_attackers)) >= self.attack_threshold:
            return True
        else:
            return False
