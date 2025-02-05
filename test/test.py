from flask import Flask, request, jsonify, url_for, redirect

app = Flask(__name__)

TRUSTED_IP = "192.168.1.1"
SESSION_HEADER = "password"
VALID_USER = "user"
VALID_PASSWORD = "password"

#------------------------TEST EXAMPLES---------------------------

"""
Fuzzing Tests:
python3 fbps.py http://127.0.0.1:5000/bypass

Method Tests:
python3 fbps.py -m PUT http://127.0.0.1:5000/bypass
python3 fbps.py -A http://127.0.0.1:5000/bypass

Header Tests:
python3 fbps.py -L 2 http://127.0.0.1:5000/bypass
python3 fbps.py -H "X-Forwarded-For:192.168.1.1" http://127.0.0.1:5000/bypass
python3 fbps.py -H "Bearer:password" http://127.0.0.1:5000/bypass

Cookie Tests:
python3 fbps.py -c "session=password" http://127.0.0.1:5000/bypass

Body Tests:
python3 fbps.py -b "user=user&password=password" -H "Content-Type:application/x-www-form-urlencoded" http://127.0.0.1:5000/bypass

Uppercase Tests:
python3 fbps.py -L 2 http://127.0.0.1:5000/bypass

NOTE: replace http://127.0.0.1:5000 with your current Flask server IP & Port
"""

#------------------------BASIC RESPONSES------------------------

# Route that returns a 200 OK
@app.route('/bypass_success', methods=['GET', 'POST'])
def forced_success():
    return jsonify(message="Bypass success!"), 200

# Route that returns a 403 Forbidden
@app.route('/bypass_forbidden', methods=['GET', 'POST'])
def forced_forbidden():
    return jsonify(message="Access Forbidden."), 403

#----------------HEADERS, COOKIE & PARAMS TESTS------------------

# Route that returns a 403 Forbidden, unless specific headers are set
@app.route('/bypass', methods=['GET', 'POST'])
def forbidden():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    bearer_header = request.headers.get('Bearer')
    session_cookie = request.cookies.get('session')
    body_user = request.form.get('user')
    body_password = request.form.get('password')

    if client_ip == TRUSTED_IP:
        return jsonify(message="Access granted for IP: " + client_ip), 200
    # Returns 200 OK if Bearer header is set to the correct Session header value
    elif bearer_header == SESSION_HEADER:
        return jsonify(message="Access granted via Session Header."), 200
    # Returns 200 OK if session cookie is set to the correct Session header value
    elif session_cookie == SESSION_HEADER:
        return jsonify(message="Access granted via cookie."), 200
    # Returns 200 OK if the body contains the correct user and password
    elif body_user==VALID_USER and body_password == VALID_PASSWORD:
        return jsonify(message="Access granted via credentials."), 200
    else:
        return jsonify(error="Access Forbidden."), 403  

#------------------------METHOD TESTS---------------------------

# Route that returns a 200 OK if the method used is PUT
@app.route('/;/bypass', methods=['PUT'])
def method_success():
    return jsonify(message="Bypass success!"), 200

#------------------------FUZZING TESTS--------------------------

# Route that returns a 200 OK
@app.route('/&/bypass', methods=['GET', 'POST'])
def success():
    return jsonify(message="Bypass success!"), 200

# Route that returns a 500 Internal Server Error
@app.route('/bypass/.json', methods=['GET', 'POST'])
def internal_error():
    return jsonify(error="Internal server error!"), 500

# Route that redirects (301) to a page that returns a 403 Forbidden
@app.route('/./bypass', methods=['GET', 'POST'])
def redirect_to_forbidden():
    return redirect(url_for('forced_forbidden')), 301

# Route that redirects (301) to a page that returns a 200 OK
@app.route('/?/bypass', methods=['GET', 'POST'])
def redirect_to_success():
    return redirect(url_for('forced_success')), 301

# Route that returns a 302 Found
@app.route('/.../bypass', methods=['GET', 'POST'])
def found():
    return jsonify(error="Found."), 302

#------------------------UPPERCASE TEST------------------------

# Route that returns a 200 OK
@app.route('/bypasS', methods=['GET', 'POST'])
def uppercase_success():
    return jsonify(message="Bypass success!"), 200

#--------------------------------------------------------------

@app.before_request
def handle_options_request():
    if request.method == 'OPTIONS':
        return jsonify(error="Method Not Allowed."), 405

# Handle all other routes with a 404 Not Found
@app.errorhandler(404)
def page_not_found(e):
    return jsonify(error="Not Found."), 404

if __name__ == '__main__':
    # Run the Flask app in debug mode (for development)
    app.run(debug=True, host='0.0.0.0', port=5000)
