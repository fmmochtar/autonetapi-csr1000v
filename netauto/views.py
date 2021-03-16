from django.shortcuts import render, redirect, get_object_or_404, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User, Group
from django.core.files.storage import FileSystemStorage
from django.http import JsonResponse
#from .forms import Scripts
from .models import Device, Log, AccessControlID, AttackLog
import requests
import urllib3
import json
from datetime import datetime
from .decorators import superadmin_only
from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
#from rest_framework import permissions
from .serializers import UserSerializer, GroupSerializer, DeviceSerializer, AttackLogSerializer
from .pycsrmgmt import api
from .rulesets import *
#from .autorules import antecedents
#import .rules as rules
# import csrestapi.auth
# import csrestapi.api

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FILE_TYPE = ['txt', 'conf']

# Check if the user is superadmin or not.

def check_superadmin(request, *args, **kwargs):
    if request.user.groups.all()[0].name == 'superadmin':
        return True
    else:
        return False

# Getting the token of the device

# Before the views, let's put the class needed for DRF here
class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAuthenticated]

class DeviceViewSet(viewsets.ModelViewSet):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    #permission_classes = [permissions.IsAuthenticated]

    #def list(self, request):
    #    pass

#@api_view(['GET', 'POST'])
class AttackLogViewSet(viewsets.ModelViewSet):
    queryset = AttackLog.objects.all()
    serializer_class =  AttackLogSerializer

    #def list(self, request):
    #    pass

    # This is the alerting API
    #@action(detail=True, methods=['post'])
    def create(self, request):

        serializer = AttackLogSerializer(data=request.data)
        if serializer.is_valid() == True:

            attacker_ip = serializer.data['source_ip']
            victim_ip = serializer.data['dst_ip']
            victim_port = serializer.data['dst_port']

            try:
                auto_devices = Device.objects.all().filter(auto_mitigate=True)
                attacker_list = AttackLog.objects.all().filter(source_ip=attacker_ip)
                victim_list = AttackLog.objects.all().filter(dst_ip=victim_ip)

                #print(len(attacker_list))
                attacker_attempts = len(attacker_list)

                #attacker_list_send = list(attacker_list)

                #for c in attacker_list:
                #    attacker_list_send.append(attacker_list.source_ip)

                print(attacker_ip)
                for i in auto_devices:
                    token = api.device(i.ip_address, i.username, i.password).token()
                    print('token is ' + token)
                    #token = get_token()
                    get_acl = api.acl(i.ip_address, token).get(i.default_acl_id)
                    json_data = json.loads(get_acl.replace("\"acl-id\":", "\"acl_id\":"))
                    acl_rule_id_list = []
                    acl_rule_src_list = []
                    if json_data['rules']:
                        for x in range(len(json_data['rules'])):
                            acl_rule_id_list.append(json_data['rules'][x]['sequence'])
                            acl_rule_src_list.append(json_data['rules'][x]['source'])
                    print(acl_rule_id_list)
                    print(acl_rule_src_list)
                    print(i.default_acl_id)
                    #print(attacker_list_send)
                    
                    #print('[csr-api] if the attack successfully mitigated, then any output from api should appear here')
                    #print(block_with_acl)

                    # Inference engine starts here
                    #rule_action(entropy_value,entropy_threshold,source_ip, destination_ip, destination_port, attack_total, attack_threshold, list_of_attackers, victim_list, acl_list)
                    inference = rule_action(1.0, 1.2, attacker_ip, victim_ip, victim_port, attacker_attempts, 3, [], victim_list, acl_rule_src_list)
                    block_action = inference.run()
                    print(block_action)

                    for ex in (list(range(30,1000))):
                        if ex in acl_rule_id_list:
                            print('occupied')
                        else:
                            if block_action == 'block-all':
                                block_with_acl = api.acl(i.ip_address, token).add_existing(i.default_acl_id, ex, 'all', attacker_ip, 'any', 'deny')
                                print (block_with_acl)
                                #log = AttackLog(time=datetime.now(), source_ip=attacker_ip, dst_ip=victim_ip, dst_port=victim_port, status='block-all')
                                #log.save()
                                break #return Response({'status': 'post'}, status=status.HTTP_200_OK)
                            elif block_action == 'block-single':
                                block_with_acl = api.acl(i.ip_address, token).add_existing(i.default_acl_id, ex, 'all', attacker_ip, victim_ip, 'deny')
                                print (block_with_acl)
                                #log = AttackLog(time=datetime.now(), source_ip=attacker_ip, dst_ip=victim_ip, dst_port=victim_port, status='block-single')
                                #log.save()
                                break# return Response({'status': 'post'}, status=status.HTTP_200_OK)
                            elif block_action == 'ignore':
                                return Response({'status': 'post'}, status=status.HTTP_200_OK)
                                break # pass
                            else:
                                break #pass
                            break
                if block_action != 'ignore':
                    log = AttackLog(time=datetime.now(), source_ip=attacker_ip, dst_ip=victim_ip, dst_port=victim_port, status=block_action)
                    log.save()
                else:
                    pass
                return Response({'status': 'post'}, status=status.HTTP_200_OK)
            except Exception as e:
                print('Error: ' + str(e))
                return Response({'status': 'error'}, status=status.HTTP_200_OK)

# Start of the app views.

@login_required
def home(request):
    total_devices = Device.objects.all()
    last_event = Log.objects.all().order_by('-id')[:10]
    context = {
        'total_devices' : len(total_devices),
        'last_event': last_event,
        'superadmin' : check_superadmin(request),
    }

    return render(request, 'netauto/home.html', context)

@login_required
def devices(request):
    all_devices = Device.objects.all()

    context = {
        'all_devices' : all_devices,
        'superadmin' : check_superadmin(request),
    }
    return render(request, 'netauto/devices.html', context)

@login_required
def show_interfaces(request):
    if request.method == "POST":
        head = 'List of available interfaces'
        selected_device_id = request.POST['router']
        dev = get_object_or_404(Device, pk=selected_device_id)
        try:
            def get_token():
                token = api.device(dev.ip_address, dev.username, dev.password).token()
                return token
            def get_int_data(token):
                get_interfaces = api.interface(dev.ip_address, token).get_all()
                #interfaces = json.loads(get_interfaces['items'][x]['if-name'])
                json_data = json.loads(get_interfaces.replace("-", "_"))
                #print(json.dumps(json_data, indent=4, separators=(',', ': ')))
                if json_data['items']:
                    return ('bisa', json_data['items'])
                else:
                    return ('gabisa', json_data['detail'])

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            token = get_token()
            get_data = get_int_data(token)

            # Put the CLI Command
            #get_int_data(token)
            if get_data[0] == "bisa":
                log = Log(target=dev.ip_address, action="Get interfaces list", status="Successful", time= datetime.now(), user=request.user.username, messages="No Error")
                log.save()
            else:
                log = Log(target=dev.ip_address, action="Get interfaces list", status="Error", time= datetime.now(), user=request.user.username, messages="Invalid Cisco Command")
                log.save()
        except Exception as e:
            log = Log(target=dev.ip_address, action="Get interfaces list", status="Error", time= datetime.now(), user=request.user.username, messages="Failed establishing connection to device or requirements not match")
            log.save()
        context = {
            'head' : head,
            'int_data' : get_data[1],
        }
        return render(request, 'netauto/device_show_interface.html', context)
    else:
        head = 'List of available interfaces'
        all_devices = Device.objects.all()
        context = {
            'all_devices' : all_devices,
            'head' : head,
            'superadmin' : check_superadmin(request),
        }
        return render(request, 'netauto/device_select_interface.html', context)

@login_required
def show_acl(request):
    selected_devices = request.POST.getlist('device')
    for x in selected_devices:
        dev = get_object_or_404(Device, pk=x)
        token = api.device(dev.ip_address, dev.username, dev.password).token()
    if request.method == "POST":
        head = 'List of registered ACL'
        selected_device_id = request.POST['router']
        dev = get_object_or_404(Device, pk=selected_device_id)
        try:
            def get_token():
                token = api.device(dev.ip_address, dev.username, dev.password).token()
                return token
            def get_acl_data(token):
                get_acl = api.acl(dev.ip_address, token).get_all()
                json_data =json.loads(get_acl.replace("\"acl-id\":", "\"acl_id\":"))
                acl_id_list = []
                acl_rule_list = []
                if json_data['items']:
                    for x in range(len(json_data['items'])):
                        acl_id_list.append(json_data['items'][x])
                        acl_rule_list.append(json_data['items'][x]['rules'])
                    return ('bisa', acl_id_list, acl_rule_list)
                # elif json_data['detail']:
                #     return ('gabisa', json_data['detail'])
                else:
                    return ('gabisa', 'null')

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            #token = get_token()
            token = api.device(dev.ip_address, dev.username, dev.password).token()

            # Put the CLI Command
            get_acl_data(token)
            if get_acl_data(token)[0] == "bisa":
                log = Log(target=dev.ip_address, action="Get ACL list", status="Successful", time= datetime.now(), user=request.user.username, messages="No Error")
                log.save()
            else:
                log = Log(target=dev.ip_address, action="Get ACL list", status="Error", time= datetime.now(), user=request.user.username, messages="Failed to get data, or no ACL exists yet.")
                log.save()
        except Exception as e:
            log = Log(target=dev.ip_address, action="Get ACL list", status="Error", time= datetime.now(), user=request.user.username, messages="Failed establishing connection to device or requirements not match")
            log.save()
        get_the_data = get_acl_data(token)
        context = {
            'head' : head,
            'acl_list' : get_the_data[1],
        }
        print(get_acl_data(token)[1])
        return render(request, 'netauto/acl_table.html', context)
    else:
        head = 'Show ACL lists'
        all_devices = Device.objects.all()
        context = {
            'all_devices' : all_devices,
            'head' : head,
            'superadmin' : check_superadmin(request),
        }
        return render(request, 'netauto/device_select_acl.html', context)


# Device selection page
@login_required
def manage_acl_0(request):
    if request.method == "POST":
        head = 'List of registered ACL'
        selected_device_id = request.POST['router']
        dev = get_object_or_404(Device, pk=selected_device_id)

        return redirect('/show/acl/'+selected_device_id+'/')
        #return render(request, 'netauto/acl_table.html', context)
    else:
        head = 'Show ACL lists'
        all_devices = Device.objects.all()
        context = {
            'all_devices' : all_devices,
            'head' : head,
            'superadmin' : check_superadmin(request),
        }
        return render(request, 'netauto/device_select_acl.html', context)
    #return redirect()

# ACL ID selection page
@login_required
def manage_acl_1(request, router_id):
    selected_device_id = router_id
    dev = get_object_or_404(Device, pk=selected_device_id)
    #selected_acl_id = acl_id
    #x = (dev)
    #return HttpResponse(x)
    if request.method == "POST":
        head = 'List of registered ACL'
        selected_device_id = request.POST['router']
        dev = get_object_or_404(Device, pk=selected_device_id)
        try:
            def get_token():
                token = api.device(dev.ip_address, dev.username, dev.password).token()
                return token
            def get_acl_data(token):
                get_acl = api.acl(dev.ip_address, token).get_all()
                json_data =json.loads(get_acl.replace("-id\":", "\"_id\":"))
                acl_id_list = []
                #acl_rule_list = []
                if json_data['items']:
                    for x in range(len(json_data['items'])):
                        acl_id_list.append(json_data['items'][x])
                        #acl_rule_list.append(json_data['items'][x]['rules'])
                    return ('bisa', acl_id_list)
                # elif json_data['detail']:
                #     return ('gabisa', json_data['detail'])
                else:
                    return ('gabisa', 'null')

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            #token = get_token()
            token = api.device(dev.ip_address, dev.username, dev.password).token()

            # Put the CLI Command
            get_acl_data(token)
            if get_acl_data(token)[0] == "bisa":
                pass
            else:
                pass
        except Exception as e:
            pass
        get_the_data = get_acl_data(token)
        context = {
            'head' : head,
            'acl_list' : get_the_data[1],
        }
        #print(get_acl_data(token)[1])
        return redirect('/show/acl/'+selected_device_id+'/')
        #return render(request, 'netauto/acl_table.html', context)
    if request.method == "GET":
        head = 'List of registered ACL rule'
        #selected_device_id = request.POST['router']
        #selected_acl_id = request.POST['acl_id']
        #acl_select = get_object_or_404(AccessControlID, pk=selected_acl_id)
        #print(acl_select.objects.select_related)
        #dev = get_object_or_404(Device, pk=selected_device_id)
        try:
            def get_token():
                token = api.device(dev.ip_address, dev.username, dev.password).token()
                return token
            def get_acl_data(token):
                get_acl = api.acl(dev.ip_address, token).get_all()
                json_data = json.loads(get_acl.replace("\"acl-id\":", "\"acl_id\":"))
                acl_id_list = []
                acl_rule_list = []
                if json_data['items']:
                    for x in range(len(json_data['items'])):
                        acl_id_list.append(json_data['items'][x])
                        acl_rule_list.append(json_data['items'][x]['rules'])
                    return ('bisa', acl_id_list, acl_rule_list)
                # elif json_data['detail']:
                #     return ('gabisa', json_data['detail'])
                else:
                    return ('gabisa', 'null')

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            #token = get_token()
            token = api.device(dev.ip_address, dev.username, dev.password).token()

            # Put the CLI Command
            get_acl_data(token)

        except Exception as e:
            pass
        token = get_token()
        get_the_data = get_acl_data(token)
        context = {
            'head' : head,
            'acl_list' : get_the_data[1],
        }
        print(get_acl_data(token)[1])
        return render(request, 'netauto/acl_table.html', context)
    else:
        return redirect('/show/acl/')

@login_required
def manage_acl_2(request, router_id, acl_id):

    if request.method == "POST":
        if 'delete' in request.POST.getlist('action'):
            selected_device_id = router_id
            selected_acl_id = acl_id
            dev = get_object_or_404(Device, pk=selected_device_id)
            selected_rule = request.POST.getlist('acl_rule')
            print (request.POST)

            for x in selected_rule:    
                try:
                    dev = get_object_or_404(Device, pk=selected_device_id)

                    # get token
                    get_token = api.device(dev.ip_address, dev.username, dev.password).token()
                    # delete acl rule
                    post_del_rules = api.acl(dev.ip_address, get_token).remove_existing(selected_acl_id, x)
                    #get_post_data = post_del_rules['items']
                    #print(get_post_data)

                    # Put new interface.
                    if post_del_rules:
                        log = Log(target=dev.ip_address, action="Delete ACL rule", status="Successful", time= datetime.now(), user=request.user.username, messages='No Error')
                        log.save()
                    else:
                        log = Log(target=dev.ip_address, action="Delete ACL rule", status="Error", time= datetime.now(), user=request.user.username, messages='An error occured')
                        log.save()
                except Exception as e:
                    log = Log(target=dev.ip_address, action="Delete ACL rule", status="Error", time= datetime.now(), user=request.user.username, messages="Failed establishing connection to device or requirements not match")
                    log.save()
            return redirect('home')
        else:
            return redirect(request.META['HTTP_REFERER'])

    elif request.method == "GET":
        head = 'List of registered ACL rule'
        selected_device_id = router_id
        dev = get_object_or_404(Device, pk=selected_device_id)
        selected_acl_id = acl_id

        try:
            def get_token():
                token = api.device(dev.ip_address, dev.username, dev.password).token()
                return token
            def get_acl_data(token):
                get_acl = api.acl(dev.ip_address, token).get(selected_acl_id)
                json_data = json.loads(get_acl)
                #acl_id_list = []
                acl_rule_list = []
                #acl_rule_list = json_data['rules']
                if 'error-code' in json_data:
                    return ('gabisa', json_data['error-message'])
                elif 'rules' in json_data:
                    for x in range(len(json_data['rules'])):
                        acl_rule_list.append(json_data['rules'][x])
                    return ('bisa', acl_rule_list)
                else:
                    return ('gabisa', 'null')
            def get_acl_interfaces(token):
                acl_int = api.acl(dev.ip_address, token).get_interfaces(selected_acl_id)
                json_data = json.loads(acl_int.replace("-id\":", "_id\":"))
                list_int = []
                if json_data['items']:
                    for x in range(len(json_data['items'])):
                        list_int.append(json_data['items'][x])
                    return ('bisa', list_int)
                elif 'error-code' in json_data:
                    return ('gabisa', json_data['error-message'])
                
                # elif json_data['detail']:
                #     return ('gabisa', json_data['detail'])
                else:
                    return ('gabisa', 'null')

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            #token = get_token()
            token = api.device(dev.ip_address, dev.username, dev.password).token()

            # Put the CLI Command
            get_payload = get_acl_data(token)
            if get_payload[0] == "bisa":
                pass
            else:
                return redirect('manage_acl_1', selected_device_id)
        except Exception as e:
            pass
            #return redirect('manage_acl_0')
        token = get_token()
        get_the_data = get_acl_data(token)
        acl_int_payload = get_acl_interfaces(token)
        context = {
            'head' : head,
            'acl_list' : get_the_data[1],
            'int_list' : acl_int_payload[1]
        }
        print(get_acl_data(token)[1])
        #return render(request, 'netauto/acl_rules_table.html', context)
        return render(request, 'netauto/acl_rules_table_check.html', context)
    else:
        return redirect('delete_acl_rule_0')

    #selected_acl_rule = acl_rule
    #x = (dev, acl_id)
    #return HttpResponse(x)
    #return render(request, 'netauto/device_select_acl_rule.html', context)

@login_required
@superadmin_only
def add_ip(request):
    if request.method == "POST":
        selected_device_id = request.POST.getlist('device')
        for x in selected_device_id:    
            try:
                dev = get_object_or_404(Device, pk=x)
                interface = request.POST['interface'+x]
                new_ip_addr = request.POST['ip_address'+x]
                new_subnetmask = request.POST['subnetmask'+x]
                def get_token():
                    url = 'https://%s:55443/api/v1/auth/token-services' % dev.ip_address
                    auth = (dev.username, dev.password) 
                    headers = {'Content-Type':'application/json'}
                    response = requests.post(url, auth=auth, headers=headers, verify=False)
                    json_data = json.loads(response.text)
                    token = json_data['token-id']
                    return token

                def put_interface(token, interface):
                    url = 'https://%s:55443/api/v1/interfaces/%s' % (dev.ip_address, interface)
                    headers={ 'Content-Type': 'application/json', 'X-auth-token': token}

                    payload = {
                        'type':'ethernet',
                        'if-name':interface,
                        'ip-address': new_ip_addr,
                        'subnet-mask': new_subnetmask,
                        'description': 'Configured via AUTONETAPI'
                        }

                    response = requests.put(url, headers=headers, json=payload, verify=False)
                    if response.status_code >= 400:
                        message = json.loads(response.text)['error-message']
                    else:
                        message = 'Success'
                    return message

                # Disable unverified HTTPS request warnings.
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

                # Get token.
                token = get_token()

                # Put new interface.
                put_interface(token, interface)
                if put_interface(token,interface) == "Success":
                    log = Log(target=dev.ip_address, action="Modify IP Address", status="Successful", time= datetime.now(), user=request.user.username, messages='No Error')
                    log.save()
                else:
                    log = Log(target=dev.ip_address, action="Modify IP Address", status="Error", time= datetime.now(), user=request.user.username, messages=put_interface(token,interface))
                    log.save()
            except Exception as e:
                log = Log(target=dev.ip_address, action="Modify IP Address", status="Error", time= datetime.now(), user=request.user.username, messages="Failed establishing connection to device or requirements not match")
                log.save()
        return redirect('home')
    else:
        all_devices = Device.objects.all()
        context = {
            'all_devices' : all_devices,
            'superadmin' : check_superadmin(request),
        }
        return render(request, 'netauto/add_ip.html', context)

@login_required
def show_config(request):
    if request.method == "POST":
        head = 'The Configuration Result'
        cisco_command = request.POST['cisco_command']
        selected_device_id = request.POST['router']
        dev = get_object_or_404(Device, pk=selected_device_id)
        try:
            def get_token():
                url = 'https://%s:55443/api/v1/auth/token-services' % dev.ip_address
                auth = (dev.username, dev.password) 
                headers = {'Content-Type':'application/json'}
                response = requests.post(url, auth=auth, headers=headers, verify=False)
                json_data = json.loads(response.text)
                token = json_data['token-id']
                return token
            def send_cli(token):
                url = 'https://%s:55443/api/v1/global/cli' % dev.ip_address
                headers = {'Content-Type':'application/json','X-auth-token': token}
                payload = {
                    "exec" : cisco_command
                }
                response = requests.put(url, headers=headers, json=payload, verify=False)
                json_data = json.loads(response.text)
                #print(json.dumps(json_data, indent=4, separators=(',', ': ')))
                if response.status_code >= 400:
                    return (json_data['detail'], 'gabisa')
                else:
                    return (json_data['results'], 'bisa')

            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            token = get_token()

            # Put the CLI Command
            send_cli(token)
            if send_cli(token)[1] == "bisa":
                log = Log(target=dev.ip_address, action="Validate Configuration", status="Successful", time= datetime.now(), user=request.user.username, messages="No Error")
                log.save()
            else:
                log = Log(target=dev.ip_address, action="Validate Configuration", status="Error", time= datetime.now(), user=request.user.username, messages="Invalid Cisco Command")
                log.save()
        except Exception as e:
            log = Log(target=dev.ip_address, action="Validate Configuration", status="Error", time= datetime.now(), user=request.user.username, messages="Failed establishing connection to device or requirements not match")
            log.save()
        context = {
            'head' : head,
            'status' : send_cli(token)[0],
        }
        return render(request, 'netauto/result.html', context)
    else:
        head = 'Validate your configuration'
        all_devices = Device.objects.all()
        context = {
            'all_devices' : all_devices,
            'head' : head,
            'superadmin' : check_superadmin(request),
        }
        return render(request, 'netauto/validate.html', context)

@login_required
def syslog(request):
    if request.method == "POST":
        selected_device_id = request.POST['router']
        dev = get_object_or_404(Device, pk=selected_device_id)
        try:
            def get_token():
                url = 'https://%s:55443/api/v1/auth/token-services' % dev.ip_address
                auth = (dev.username, dev.password) 
                headers = {'Content-Type':'application/json'}
                response = requests.post(url, auth=auth, headers=headers, verify=False)
                json_data = json.loads(response.text)
                token = json_data['token-id']
                return token
            def get_syslog(token):
                url = 'https://%s:55443/api/v1/global/syslog' % dev.ip_address
                headers = {'Accept':'application/json', 'X-auth-token':token} 
                response = requests.get(url, headers=headers, verify=False)
                json_data = json.loads(response.text)
                syslog = json_data['messages']
                return syslog
            # Disable unverified HTTPS request warnings.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            # Get token.
            token = get_token()

            get_syslog(token)
            log = Log(target=dev.ip_address, action="Export Syslog", status="Successful", time= datetime.now(), user=request.user.username, messages="No Error")
            log.save()
        except Exception as e:
            log = Log(target=dev.ip_address, action="Export Syslog", status="Error", time= datetime.now(), user=request.user.username, messages="Failed establishing connection to device or requirements not match")
            log.save()
        
        filename_date = str(datetime.now())
        filename = "syslog_"+ str(dev.ip_address) +"_"+ filename_date + ".txt"
        content = get_syslog(token)
        response = HttpResponse(content, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename={0}'.format(filename)
        return response
    else:
        all_devices = Device.objects.all()
        context = {
            'all_devices': all_devices,
            'superadmin' : check_superadmin(request),
        }
        return render(request, 'netauto/syslog.html', context)

@login_required
@superadmin_only
def custom(request):
    all_devices = Device.objects.all()
    if request.method == "POST" and request.FILES['myScript']:
        myScript = request.FILES['myScript']
        fs = FileSystemStorage()
        scriptName = fs.save(myScript.name, myScript)
        uploaded_file_url = fs.url(scriptName)
        file_type = uploaded_file_url.split('.')[-1]
        file_type = file_type.lower()
        if file_type not in FILE_TYPE:
            fs.delete(myScript.name)
            return render(request, 'netauto/500.html')
        else:
            with open(uploaded_file_url) as f:
                handler = f.read().strip()
            cisco_command = {
                'config' : handler
            }
            selected_device_id = request.POST['router']
            dev = get_object_or_404(Device, pk=selected_device_id)
            try:
                def get_token():
                    url = 'https://%s:55443/api/v1/auth/token-services' % dev.ip_address
                    auth = (dev.username, dev.password) 
                    headers = {'Content-Type':'application/json'}
                    response = requests.post(url, auth=auth, headers=headers, verify=False)
                    json_data = json.loads(response.text)
                    token = json_data['token-id']
                    return token
                def send_cli(token):
                    url = 'https://%s:55443/api/v1/global/cli' % dev.ip_address
                    headers = {'Content-Type':'application/json','X-auth-token': token}
                    response = requests.put(url, headers=headers, json=cisco_command, verify=False)
                    json_data = json.loads(response.text)
                    #print(json.dumps(json_data, indent=4, separators=(',', ': ')))
                    if response.status_code >= 400:
                        return (json_data['detail'], 'gabisa')
                    else:
                        return ('bisa')

                # Disable unverified HTTPS request warnings.
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

                # Get token.
                token = get_token()

                # Put the CLI Command
                send_cli(token)
                if send_cli(token) == "gabisa":
                    log = Log(target=dev.ip_address, action="Custom Configuration", status="Error", time= datetime.now(), user=request.user.username, messages="Invalid Script")
                    log.save()
                else:
                    log = Log(target=dev.ip_address, action="Custom Configuration", status="Successful", time= datetime.now(), user=request.user.username, messages="No Error")
                    log.save()
            except Exception as e:
                error_false = "Expecting value: line 1 column 1 (char 0)"
                if error_false not in str(e):
                    log = Log(target=dev.ip_address, action="Custom Configuration", status="Error", time= datetime.now(), user=request.user.username, messages="Failed establishing connection to device or requirements not match")
                else:
                    log = Log(target=dev.ip_address, action="Custom Configuration", status="Successful", time= datetime.now(), user=request.user.username, messages="No Error")
                log.save()

            fs.delete(myScript.name)
            return redirect('home')
    else:
        context = {
            'all_devices': all_devices,
            'superadmin' : check_superadmin(request),
        }
        return render(request, 'netauto/custom.html', context)

@login_required
def log(request):
    logs = Log.objects.all().order_by('-id')
    context = {
        'logs': logs,
        'superadmin' : check_superadmin(request),
    }
    return render(request, 'netauto/log.html', context)



def handler403(request):
    return render(request, 'netauto/403.html')
def handler404(request, exception):
    return render(request, 'netauto/404.html')
def handler500(request):
    return render(request, 'netauto/500.html')

