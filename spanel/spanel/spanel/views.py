from django.shortcuts import render, redirect
from django.http import JsonResponse
import pyrebase
import json
from django.contrib import auth
from django.views.decorators.csrf import csrf_exempt

config = {
    'apiKey': "AIzaSyC31AZ2puxhW1f3r-_DAZeXDd-8UNwEkvk",
    'authDomain': "spanel-3f7b4.firebaseapp.com",
    'databaseURL': "https://spanel-3f7b4-default-rtdb.firebaseio.com/",
    'projectId': "spanel-3f7b4",
    'storageBucket': "spanel-3f7b4.appspot.com",
    'messagingSenderId': "853023880902",
    'appId': "1:853023880902:web:bcb0bff5e94477744809c7",
    'measurementId': "G-NVC91BC1BV"
}
firebase = pyrebase.initialize_app(config)

authenticate = firebase.auth()

def signIn(request):
    return render(request, "signIn.html")

def postSign(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        try:
            user = authenticate.sign_in_with_email_and_password(email, password)
        except:
            message = "Invalid credentials"
            return render(request, "signIn.html", {'message': message})
        print(user['idToken'])
        session_id = user['idToken']
        request.session['uid'] = str(session_id)
        return render(request, "postSign.html", {"email": email})
    # If someone accesses this URL directly without POST data, redirect to signIn
    return redirect('signIn')

def logout(request):
    try:
        del request.session['uid']
    except KeyError:
        pass
    return redirect('signIn')  # Updated to use the named URL pattern

# New API endpoint for mobile authentication
@csrf_exempt
def api_login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            # Authenticate with Firebase
            user = authenticate.sign_in_with_email_and_password(email, password)

            # Return token and user info
            return JsonResponse({
                'success': True,
                'idToken': user['idToken'],
                'refreshToken': user['refreshToken'],
                'email': user['email'],
                'userId': user['localId']
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=400)
    else:
        return JsonResponse({
            'success': False,
            'error': 'Only POST method is allowed'
        }, status=405)

@csrf_exempt
def api_register(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            # Create user in Firebase
            user = authenticate.create_user_with_email_and_password(email, password)

            # Return token and user info
            return JsonResponse({
                'success': True,
                'idToken': user['idToken'],
                'refreshToken': user['refreshToken'],
                'email': user['email'],
                'userId': user['localId']
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=400)
    else:
        return JsonResponse({
            'success': False,
            'error': 'Only POST method is allowed'
        }, status=405)