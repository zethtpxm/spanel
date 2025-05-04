from django.shortcuts import render, redirect
from django.http import JsonResponse
import pyrebase
import json
from django.contrib import auth
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
import re
import logging
from django.shortcuts import redirect

logging.basicConfig(level=logging.DEBUG)

config = {
    'apiKey': "AIzaSyC31AZ2puxhW1f3r-_DAZeXDd-8UNwEkvk",
    'authDomain': "spanel-3f7b4.firebaseapp.com",
    'databaseURL': "https://spanel-3f7b4-default-rtdb.asia-southeast1.firebasedatabase.app/",
    'projectId': "spanel-3f7b4",
    'storageBucket': "spanel-3f7b4.appspot.com",
    'messagingSenderId': "853023880902",
    'appId': "1:853023880902:web:bcb0bff5e94477744809c7",
    'measurementId': "G-NVC91BC1BV"
}
firebase = pyrebase.initialize_app(config)

authenticate = firebase.auth()
database = firebase.database()


def signIn(request):
    return render(request, "signIn.html")


def welcome(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = authenticate.sign_in_with_email_and_password(email, password)
            session_id = user['idToken']
            request.session['uid'] = str(session_id)
            request.session['email'] = email
            return render(request, "welcome.html", {"email": email})

        except Exception as e:
            error_message = str(e)

            if "INVALID_LOGIN_CREDENTIALS" in error_message:
                message = "Incorrect email or password."
            elif "EMAIL_NOT_FOUND" in error_message:
                message = "No account found with this email."
            elif "INVALID_PASSWORD" in error_message:
                message = "Wrong password. Please try again."
            elif "TOO_MANY_ATTEMPTS_TRY_LATER" in error_message:
                message = "Too many attempts. Try again later."
            else:
                message = "Login failed. Please try again."

            return render(request, "signIn.html", {'message': message})

    return redirect('signIn')



def logout(request):
    try:
        del request.session['uid']
        del request.session['email']
    except KeyError:
        pass
    return redirect('signIn')

def redirect_to_signin(request):
    return redirect('signIn')

def signUp(request):
    return render(request, "signUp.html")

def postSignUp(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Basic field checks
        if not name or not email or not password:
            return render(request, "signUp.html", {"message": "All fields are required."})

        try:
            # Optional: email and password format validation
            validate_email(email)
            validate_password(password)

            # Attempt to register user
            user = authenticate.create_user_with_email_and_password(email, password)
            uid = user['localId']
            data = {"name": name, "status": "1"}
            database.child("users").child(uid).child("details").set(data)

            return render(request, "signIn.html", {"message": "Account created successfully!"})

        except ValidationError as ve:
            return render(request, "signUp.html", {"message": str(ve)})
        except Exception as e:
            error_message = str(e)
            # Map Firebase errors to clearer messages
            if "EMAIL_EXISTS" in error_message:
                error_message = "This email is already registered."
            elif "WEAK_PASSWORD" in error_message:
                error_message = "Password must be at least 6 characters."
            elif "INVALID_EMAIL" in error_message:
                error_message = "Invalid email format."
            return render(request, "signUp.html", {"message": error_message})
    else:
        return redirect("signUp")


# Helper function to validate email
def validate_email(email):
    if not email:
        raise ValidationError("Email is required")

    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        raise ValidationError("Please enter a valid email address")

    return email


# Helper function to validate password
def validate_password(password):
    if not password:
        raise ValidationError("Password is required")

    if len(password) < 6:
        raise ValidationError("Password must be at least 6 characters long")

    return password


# API endpoint for mobile authentication
@csrf_exempt
def api_login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            try:
                validate_email(email)
                validate_password(password)
            except ValidationError as e:
                return JsonResponse({
                    'success': False,
                    'error': str(e)
                }, status=400)

            try:
                # Attempt to sign in the user
                user = authenticate.sign_in_with_email_and_password(email, password)
                return JsonResponse({
                    'success': True,
                    'idToken': user['idToken'],
                    'refreshToken': user['refreshToken'],
                    'email': user['email'],
                    'userId': user['localId']
                })
            except Exception as e:
                error_str = str(e)
                logging.error(f"Authentication error: {error_str}")

                # Print full error for debugging
                print(f"Full Firebase error: {error_str}")

                # Check for different variations of errors
                if "INVALID_LOGIN_CREDENTIALS" in error_str:
                    # Since we can't determine whether it's an email or password issue,
                    # provide a more generic message
                    return JsonResponse({
                        'success': False,
                        'error': "Email is not registered or password is incorrect."
                    }, status=400)
                elif any(err in error_str.upper() for err in ["EMAIL_NOT_FOUND", "USER_NOT_FOUND"]):
                    return JsonResponse({
                        'success': False,
                        'error': "Email is not registered. Please sign up first."
                    }, status=400)
                elif "INVALID_PASSWORD" in error_str.upper():
                    return JsonResponse({
                        'success': False,
                        'error': "Incorrect password"
                    }, status=400)
                else:
                    return JsonResponse({
                        'success': False,
                        'error': "Login failed. Please try again."
                    }, status=400)

        except Exception as e:
            logging.error(f"General error: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': "Login failed. Please try again."
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
            username = data.get('username')
            contact_number = data.get('contactNumber')

            # Validate input
            try:
                validate_email(email)
                validate_password(password)
            except ValidationError as e:
                return JsonResponse({
                    'success': False,
                    'error': str(e)
                }, status=400)

            # Create user in Firebase
            user = authenticate.create_user_with_email_and_password(email, password)
            uid = user['localId']

            # Store additional user information in Firebase database
            user_data = {
                "email": email,
                "username": username or "",
                "contactNumber": contact_number or "",
                "status": "1"  # Active user
            }

            database.child("users").child(uid).child("details").set(user_data)

            # Return token and user info
            return JsonResponse({
                'success': True,
                'idToken': user['idToken'],
                'refreshToken': user['refreshToken'],
                'email': user['email'],
                'userId': user['localId']
            })
        except Exception as e:
            error_message = str(e)

            # Provide better error messages
            if "EMAIL_EXISTS" in error_message:
                error_message = "Email already in use. Please sign in or use a different email."
            elif "WEAK_PASSWORD" in error_message:
                error_message = "Password should be at least 6 characters"
            elif "INVALID_EMAIL" in error_message:
                error_message = "Invalid email format"

            return JsonResponse({
                'success': False,
                'error': error_message
            }, status=400)
    else:
        return JsonResponse({
            'success': False,
            'error': 'Only POST method is allowed'
        }, status=405)


@csrf_exempt
def api_reset_password(request):
    """
    API endpoint for resetting user password.
    Requires:
    1. Authentication token (Bearer token)
    2. Email verification
    3. Current password verification
    """
    logging.debug("api_reset_password called")

    if request.method == 'POST':
        try:
            logging.debug(f"Request headers: {request.headers}")

            # Extract auth token
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                logging.warning("Invalid auth header format")
                return JsonResponse({
                    'success': False,
                    'error': 'Invalid authentication token'
                }, status=401)

            token = auth_header.split(' ')[1]
            logging.debug("Token extracted successfully")

            # Parse request data
            try:
                request_body = request.body.decode('utf-8')
                logging.debug(f"Request body: {request_body}")
                data = json.loads(request_body)
            except json.JSONDecodeError as e:
                logging.error(f"JSON decode error: {e}")
                return JsonResponse({
                    'success': False,
                    'error': 'Invalid JSON in request body'
                }, status=400)

            email = data.get('email')
            current_password = data.get('currentPassword')
            new_password = data.get('newPassword')

            logging.debug(
                f"Email: {email}, Current password provided: {'Yes' if current_password else 'No'}, New password provided: {'Yes' if new_password else 'No'}")

            # Validate inputs
            if not email or not current_password or not new_password:
                logging.warning("Missing required fields")
                return JsonResponse({
                    'success': False,
                    'error': 'All fields are required'
                }, status=400)

            try:
                validate_email(email)
                validate_password(new_password)
            except ValidationError as e:
                logging.warning(f"Validation error: {e}")
                return JsonResponse({
                    'success': False,
                    'error': str(e)
                }, status=400)

            try:
                # First, verify the token is valid by getting user info
                try:
                    logging.debug(f"Getting account info for token")
                    # For pyrebase, we can use get_account_info to verify token
                    user_info = authenticate.get_account_info(token)
                    logging.debug(f"User info received")

                    if not user_info or 'users' not in user_info or not user_info['users']:
                        logging.error("Invalid user info returned from Firebase")
                        return JsonResponse({
                            'success': False,
                            'error': 'Failed to retrieve user information. Session may have expired.'
                        }, status=401)

                    token_email = user_info['users'][0]['email']
                    uid = user_info['users'][0]['localId']
                    logging.debug(f"Token email: {token_email}, Provided email: {email}")

                    # Check if the email provided matches the token's email
                    if email.lower() != token_email.lower():
                        logging.warning(f"Email mismatch: {email} vs {token_email}")
                        return JsonResponse({
                            'success': False,
                            'error': 'Email verification failed. Please ensure you are using your correct email.'
                        }, status=403)

                    logging.debug("Email verification successful")
                except Exception as e:
                    logging.error(f"Token verification error: {str(e)}")
                    return JsonResponse({
                        'success': False,
                        'error': 'Invalid or expired session. Please login again.'
                    }, status=401)

                logging.debug("Verifying current credentials")
                try:
                    user = authenticate.sign_in_with_email_and_password(email, current_password)
                    logging.debug("User authenticated successfully")
                except Exception as auth_error:
                    logging.error(f"Authentication error: {str(auth_error)}")
                    error_str = str(auth_error)
                    if "INVALID_PASSWORD" in error_str.upper():
                        return JsonResponse({
                            'success': False,
                            'error': "Current password is incorrect"
                        }, status=400)
                    elif "INVALID_LOGIN_CREDENTIALS" in error_str.upper():
                        return JsonResponse({
                            'success': False,
                            'error': "Current password is incorrect"
                        }, status=400)
                    else:
                        return JsonResponse({
                            'success': False,
                            'error': f"Authentication failed: {error_str}"
                        }, status=400)

                # Now change the password using the correct method in pyrebase
                logging.debug("Changing password")
                try:
                    user = authenticate.sign_in_with_email_and_password(email, current_password)
                    # Then use the update_password method which is the correct method in pyrebase
                    authenticate.update_password(token, new_password)
                    logging.debug("Password changed successfully")

                    return JsonResponse({
                        'success': True,
                        'message': 'Password changed successfully'
                    })

                except Exception as password_change_error:
                    logging.error(f"Error in password change operation: {str(password_change_error)}")
                    error_str = str(password_change_error)

                    if "INVALID_ID_TOKEN" in error_str.upper() or "EXPIRED_ID_TOKEN" in error_str.upper():
                        return JsonResponse({
                            'success': False,
                            'error': "Session expired. Please login again."
                        }, status=401)
                    elif "WEAK_PASSWORD" in error_str.upper():
                        return JsonResponse({
                            'success': False,
                            'error': "New password is too weak. It must be at least 6 characters."
                        }, status=400)
                    else:
                        return JsonResponse({
                            'success': False,
                            'error': f"Failed to update password: {error_str}"
                        }, status=400)

            except Exception as e:
                import traceback
                error_str = str(e)
                logging.error(f"Firebase error during password reset: {error_str}")
                logging.error(f"Traceback: {traceback.format_exc()}")

                # Return detailed error for debugging
                return JsonResponse({
                    'success': False,
                    'error': f"Password reset failed: {error_str}"
                }, status=400)

        except Exception as e:
            logging.error(f"General error in password reset: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': "An error occurred. Please try again."
            }, status=500)
    else:
        return JsonResponse({
            'success': False,
            'error': 'Only POST method is allowed'
        }, status=405)