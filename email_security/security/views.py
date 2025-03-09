import os

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
import requests

# logger = logging.getLogger(__name__)
VIRUSTOTAL_API_KEY = "a30a8744f9b3335ed04aa713de5fd3c0543e6da03053f7210689ff25667d4e47"
VIRUSTOTAL_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"}

# Home Page
def home(request):
    return render(request, 'security/home.html')


# ✅ Check IP in VirusTotal
def check_ip(request):
    ip = request.POST.get('ip', '').strip()
    if not ip:
        return JsonResponse({"error": "No IP provided"}, status=400)

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    try:
        response = requests.get(url, headers=VIRUSTOTAL_HEADERS, timeout=10)
        if response.status_code == 403:
            return JsonResponse({"error": "VirusTotal API Key is invalid or blocked (403 Forbidden)"}, status=403)

        data = response.json()
        
        # ✅ Extract only useful information
        summary = {
            "ip": ip,
            "reputation": data["data"]["attributes"].get("reputation", "N/A"),
            "malicious": data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0),
            "suspicious": data["data"]["attributes"]["last_analysis_stats"].get("suspicious", 0),
            "harmless": data["data"]["attributes"]["last_analysis_stats"].get("harmless", 0),
            "country": data["data"]["attributes"].get("country", "Unknown"),
            "network": data["data"]["attributes"].get("network", "Unknown"),
            "last_analysis_results": data["data"]["attributes"].get("last_analysis_results", {}),
        }

        return JsonResponse(summary)
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal API Error: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)

# ✅ Check Hash in VirusTotal
def check_hash(request):
    hash_value = request.POST.get('hash', '').strip()
    if not hash_value:
        return JsonResponse({"error": "No Hash provided"}, status=400)

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

    try:
        response = requests.get(url, headers=VIRUSTOTAL_HEADERS, timeout=10)
        if response.status_code == 403:
            return JsonResponse({"error": "VirusTotal API Key is invalid or blocked (403 Forbidden)"}, status=403)

        data = response.json()
        
        summary = {
            "hash": hash_value,
            "reputation": data["data"]["attributes"].get("reputation", "N/A"),
            "malicious": data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0),
            "suspicious": data["data"]["attributes"]["last_analysis_stats"].get("suspicious", 0),
            "harmless": data["data"]["attributes"]["last_analysis_stats"].get("harmless", 0),
            "last_analysis_results": data["data"]["attributes"].get("last_analysis_results", {}),
        }

        return JsonResponse(summary)
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal API Error: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)

# ✅ Check Domain in VirusTotal
def check_domain(request):
    domain = request.POST.get('domain', '').strip()
    if not domain:
        return JsonResponse({"error": "No Domain provided"}, status=400)

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    try:
        response = requests.get(url, headers=VIRUSTOTAL_HEADERS, timeout=10)
        if response.status_code == 403:
            return JsonResponse({"error": "VirusTotal API Key is invalid or blocked (403 Forbidden)"}, status=403)

        data = response.json()
        
        summary = {
            "domain": domain,
            "reputation": data["data"]["attributes"].get("reputation", "N/A"),
            "malicious": data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0),
            "suspicious": data["data"]["attributes"]["last_analysis_stats"].get("suspicious", 0),
            "harmless": data["data"]["attributes"]["last_analysis_stats"].get("harmless", 0),
            "last_analysis_results": data["data"]["attributes"].get("last_analysis_results", {}),
        }

        return JsonResponse(summary)
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal API Error: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)


# import os

# from django.shortcuts import render, redirect
# from django.http import JsonResponse
# from django.contrib.auth.decorators import login_required
# from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.models import User
# import requests
# import subprocess


# # Home Page
# def home(request):
#     return render(request, 'security/home.html')

# # # Login View
# # def user_login(request):
# #     if request.method == 'POST':
# #         username = request.POST['username']
# #         password = request.POST['password']
# #         user = authenticate(request, username=username, password=password)
# #         if user:
# #             login(request, user)
# #             return redirect('dashboard')
# #         else:
# #             return render(request, 'security/login.html', {'error': 'Invalid Credentials'})
# #     return render(request, 'security/login.html')

# def user_login(request):
#     # ✅ If the user is already logged in, redirect to dashboard
#     if request.user.is_authenticated:
#         return redirect('dashboard')

#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         user = authenticate(request, username=username, password=password)
#         if user:
#             login(request, user)
#             return redirect('dashboard')
#         else:
#             return render(request, 'security/login.html', {'error': 'Invalid Credentials'})

#     return render(request, 'security/login.html')

# # Logout View
# def user_logout(request):
#     logout(request)
#     return redirect('home')

# # Dashboard View
# @login_required
# def dashboard(request):
#     return render(request, 'security/dashboard.html')

# # Spam & Malware Filtering (Using SpamAssassin API)
# @login_required
# def check_spam(request):
#     email_content = request.POST.get('email_content', '')
#     process = subprocess.Popen(['spamc'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
#     result, _ = process.communicate(email_content.encode())
#     return JsonResponse({'result': result.decode()})

# # Phishing Protection (Using Phishious API)
# @login_required
# def check_phishing(request):
#     email_url = request.POST.get('email_url', '')
#     response = requests.get(f'https://phishious.caniphish.com/api/analyze?url={email_url}')
#     return JsonResponse(response.json())

# # Threat Intelligence (Using MISP API)
# @login_required
# def check_threats(request):
#     misp_url = "https://misp-instance/api/attributes/restSearch"  # Replace with actual MISP API
#     headers = {'Authorization': 'your-misp-api-key', 'Accept': 'application/json'}
#     response = requests.get(misp_url, headers=headers)
#     return JsonResponse(response.json())

# # Email Authentication (SPF, DKIM, DMARC Validation)
# @login_required
# def check_email_auth(request):
#     domain = request.POST.get('domain', '')
#     spf_result = subprocess.getoutput(f'dig txt {domain} | grep spf')
#     dkim_result = subprocess.getoutput(f'dig txt {domain} | grep dkim')
#     dmarc_result = subprocess.getoutput(f'dig txt _dmarc.{domain}')
#     return JsonResponse({'SPF': spf_result, 'DKIM': dkim_result, 'DMARC': dmarc_result})

# # Encryption Management (OpenPGP)
# @login_required
# def encrypt_email(request):
#     email_content = request.POST.get('email_content', '')
#     key_id = "recipient-key-id"  # Replace with recipient’s PGP key ID
#     process = subprocess.Popen(["gpg", "--encrypt", "--recipient", key_id], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
#     encrypted_msg, _ = process.communicate(email_content.encode())
#     return JsonResponse({'encrypted_message': encrypted_msg.decode()})
