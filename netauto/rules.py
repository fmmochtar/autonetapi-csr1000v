from .autorules import antecedents

list_attackers = ['192.168.1.6', '192.168.1.6', '192.168.1.7']
acl_list = ['192.168.1.6', '192.168,1.7']

#list_attackers = []
#acl_list = []

fact_check = antecedents.analyze(3.3, 2.2, '192.168.1.6', '192.168.1.33', '80', 2, 3, list_attackers, acl_list)

x = fact_check.assert_rule0()
y = fact_check.assert_rule1()

if y ==  True:
    print('hory shet')

#x = analyzer.inference.assert_rule0()
#y = analyzer.inference.assert_rule1()
print(bool(x))
print(bool(y))