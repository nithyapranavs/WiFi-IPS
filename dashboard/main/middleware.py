
from django.shortcuts import redirect
from django.urls import reverse

class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Allow access to the login page and static files without login
        if request.path in [reverse('login'), reverse('logout')] or request.path.startswith('/static/'):
            return self.get_response(request)
        
        # Check if the user is logged in (assuming `is_logged_in` session key)
        if not request.session.get('is_logged_in'):
            return redirect('login')
        
        return self.get_response(request)
