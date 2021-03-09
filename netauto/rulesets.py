import requests
import json
from .pycsrmgmt import api

class facts(object):
    def __init__(self):
        self.datetime = ''
        self.source_ip = ''
        self.dest_ip =''
        self.dest_port = ''
        self.flag = ''
        self.entropy = ''
        self.attack_type = ''
        self.num_accumulated_attack = ''

    # Rule sets here
    def analyze(self):
        if self.attack_type == 'dos' or 'ddos':
            if self.num_accumulated_attack > 1:
                print('block-all')
            elif self.num_accumulated_attack <= 1:
                print('block-single-host')
        elif self.attack_type == 'sqli':
            print('block-all')




