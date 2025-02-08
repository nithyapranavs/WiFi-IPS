from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
#from django.conf import settings

from . import helper
#import os
import toml
import hashlib

USERNAME = "admin"
PASSWORD = '21232f297a57a5a743894a0e4a801fc3'

# Create your views here.
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        password = hashlib.md5(password.encode()).hexdigest()

        if username == USERNAME and password == PASSWORD:
            request.session['is_logged_in'] = True
            return redirect('/home')  # Redirect to home page after login
        else:
            messages.error(request, 'Invalid username or password')

    return render(request, 'main/login.html')

def logout_view(request):
    request.session.flush()  # Clears all session data
    return redirect('login')

def settings(request):
    config = toml.load("main/static/config/prevent.toml")
    attacks = [
        'deauth',
        'mitm', 
        'capture_handshake',
        'dos_attack'
    ]
    
    items = [[attack, config['attack'][attack]] for attack in attacks]

    whitelist = helper.get_mac("main/static/config/whitelist.txt")
    blacklist = helper.get_mac("main/static/config/blacklist.txt")
    print(whitelist, blacklist)

    context = {
        'items': items,
        'whitelist': whitelist,
        'blacklist': blacklist
    }
    if request.method == 'POST':
        if 'toggle' in request.POST:
            item_name = request.POST.get('toggle')
            # Toggle the item's status
            for item in items:
                if item[0] == item_name:
                    config['attack'][item_name] = not config['attack'][item_name]
                    with open('main/static/config/prevent.toml', 'w') as config_file:
                        toml.dump(config, config_file)
                    break

        elif request.POST.get('action') == 'whitelist':
            mac_address = request.POST.get('whitelist_mac')
            if mac_address and mac_address not in whitelist:
                whitelist.append(mac_address)
                with open("main/static/config/whitelist.txt",'a') as file:
                    file.write(mac_address+'\n')

        # Check if a MAC address was added to the blacklist
        elif request.POST.get('action') == 'blacklist':
            mac_address = request.POST.get('blacklist_mac')
            if mac_address and mac_address not in blacklist:
                blacklist.append(mac_address)

        elif request.POST.get('remove_action') == 'remove_whitelist':
            mac_address = request.POST.get('remove_whitelist_mac')
            if mac_address in whitelist:
                whitelist.remove(mac_address)
                with open("main/static/config/whitelist.txt",'w') as file:
                    file.writelines(whitelist)

        # Handle removing from blacklist
        elif request.POST.get('remove_action') == 'remove_blacklist':
            mac_address = request.POST.get('remove_blacklist_mac')
            if mac_address in blacklist:
                blacklist.remove(mac_address)
                with open("main/static/config/blacklist.txt",'w') as file:
                    file.writelines(blacklist)
        #return render(request, 'main/settings.html', context)
        return redirect("settings")
    return render(request, 'main/settings.html', context)

def attack_logs(request):
    attack_types = ['evil twin', 'mitm', 'SSID confussion']  # Example attack types
    selected_attack = request.GET.get('attack_type', 'SQL Injection')  # Default to 'SQL Injection'
    
    # Dummy log data for example purposes
    logs = {
        'evil twin':  helper.get_log('main/static/logs/evil-twin.csv')
        ,
        'mitm': helper.get_log('main/static/logs/mitm.csv'),
        'SSID confussion': []
    }
    context = {
        'attack_types': attack_types,
        'selected_attack': selected_attack,
        'logs': logs.get(selected_attack, [])
    }
    return render(request, 'main/logs.html', context)

def index(response):

    #context = {
    #    'product_count': product_count,
    #    'order_count': order_count,
    #    'customer_count': customer_count,
    #}
    context = {}
    return render(response, 'main/index.html', context)

def detection_views(request):
    # Example data

    csv_path = "main/static/logs/detections.csv"
    table_data = helper.get_log(csv_path)



    context = {
        'table_data': table_data
    }
    
    return render(request, 'main/detection.html', context)

def prevention_views(request):
    # Example data
    
    csv_path = "main/static/logs/preventions.csv"
    table_data = helper.get_log(csv_path)

    context = {
        'table_data': table_data
    }
    
    return render(request, 'main/prevention.html', context)

def clients_connected(request):
    # Example data
    table_data = [
         ['Nithya Pranav',   '14:8d:da:6b:ae:29 '],
         ['Sourabh',  '13:6d:da:6b:ae:31 '],
    ]
    
    context = {
        'table_data': table_data
    }
    
    return render(request, 'main/client_connected.html', context)
