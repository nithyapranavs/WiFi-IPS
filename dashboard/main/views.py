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

# --- toggle preventions ---
def set_deauth(status):
    value = 1 if status == 1 else 0
    hostapd_config_file = "/etc/hostapd/hostapd.conf"
    lines = []

    with open(hostapd_config_file, 'r') as file:
        for line in file:
            if line.startswith('ieee80211w='):
                lines.append(f'ieee80211w={value}\n')
            else:
                lines.append(line)

    with open(hostapd_config_file, 'w') as file:
        file.writelines(lines)

# --- end of toggles

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
    '''attacks = [
        'deauth',
        'mitm', 
        'capture_handshake',
        'dos_attack'
    ]'''
    attacks = ['deauth']
    
    items = [[attack, config['attack'][attack]] for attack in attacks]
    context = {'items': items}
    attack_toggle = {
        'deauth': set_deauth,
    }

    if request.method == 'POST':
        if 'toggle' in request.POST:
            item_name = request.POST.get('toggle')
            # Toggle the item's status
            for item in items:
                if item[0] == item_name:
                    new_status = not config['attack'][item_name]
                    config['attack'][item_name] = new_status
                    with open('main/static/config/prevent.toml', 'w') as config_file:
                        toml.dump(config, config_file)

                    if item_name in attack_toggle:
                        attack_toggle[item_name](new_status)
                    break

        #return render(request, 'main/settings.html', context)
        return redirect("settings")
    return render(request, 'main/settings.html', context)

def attack_logs(request):
    attack_types = ['deauth', 'rogue_ap']  # Example attack types
    selected_attack = request.GET.get('attack_type', 'deauth')  # Default to 'deauth'
    
    # Dummy log data for example purposes
    logs = {
        'deauth':  helper.get_log('main/static/logs/deauth.csv')
        ,
        'rogue_ap': helper.get_log('main/static/logs/rogue_ap.csv'),
    }
    #print(logs)
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
