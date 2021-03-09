from autorules import antecedents

list_attackers = ['192.168.1.6', '192.168.1.6', '192.168.1.7', '192.168.1.6', '192.168.1.6']
acl_list = ['192.168.1.6', '192.168,1.7']

#list_attackers = []
#acl_list = []

fact_check = antecedents.analyze(1.3, 2.2, '192.168.1.6', '192.168.1.33', '80', 2, 3, list_attackers, acl_list)

action_level0 = 'ignore'
action_level1 = 'block-single'
action_level2 = 'block-all'

print(sum([x in '192.168.1.6' for x in list_attackers ]))

a = fact_check.assert_rule0()
b = fact_check.assert_rule1()
c = fact_check.assert_rule2()

print (a)

if a == True:
    print ('attacker-exists-in-acl')

if (a and b) == True:
    if c == True:
        print(action_level2)
    else:
        print(action_level1)
#
#if (a and b and c) == True:
#    print ('block-all')


#x = analyzer.inference.assert_rule0()
#y = analyzer.inference.assert_rule1()
#print(bool(x))
#print(bool(y))