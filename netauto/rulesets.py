from .autorules import analyzer

class rule_action(object):
    def __init__(self, entropy_value, entropy_threshold, source_ip, destination_ip, destination_port, attack_total, attack_threshold, list_of_attackers, list_of_victims, acl_list, source_flag=''):
        self.entropy_value = entropy_value
        self.entropy_threshold = entropy_threshold
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.attack_total = attack_total
        self.attack_threshold = attack_threshold
        self.list_of_attackers = list_of_attackers
        self.list_of_victims = list_of_victims
        self.acl_list = acl_list
        #self.source_flag = source_flag

    def run(self):
        fact_check = analyzer.analyze(self.entropy_value, self.entropy_threshold, 
                        self.source_ip, self.destination_ip, self.destination_port, 
                        self.attack_total, self.attack_threshold, 
                        self.list_of_attackers, self.list_of_victims, 
                        self.acl_list)

        # Action based on levels
        action_level3 = 'block-server'
        action_level2 = 'block-all'
        action_level1 = 'block-single'
        action_level0 = 'ignore'

        # Define the rules
        R1 = fact_check.assert_rule0()
        R2 = fact_check.assert_rule1()
        R3 = fact_check.assert_rule2()
        R4 = fact_check.assert_rule3()

        # ----------------------------- 
        # - This is the rule
        #------------------------------
        if (R2 and R3) == True:
            return action_level2
        elif (R2) == True:
            return action_level1
        else:
            return action_level0
