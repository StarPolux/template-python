from flask import Flask, request, render_template_string, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask import Flask, request, redirect, session, render_template_string
from datetime import datetime
import re 
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'molly2'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    users = db.relationship('User', backref='group', lazy=True)
    
class UserList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    users = db.relationship('User', backref='user_list', lazy=True)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    online = db.Column(db.Boolean, default=False)
    mac_address = db.Column(db.String(120), nullable=True)
    ip_address = db.Column(db.String(100), nullable=True)
    banned_ips = db.relationship('BannedIP', backref='user', lazy=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    list_id = db.Column(db.Integer, db.ForeignKey('user_list.id'))

class BannedEntity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100), nullable=True)
    mac_address = db.Column(db.String(120), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class ConnectionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    mac_address = db.Column(db.String(120), nullable=False)



@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == 'OrderStore' and password == 'molly':
            session['authenticated'] = True
            return redirect('/set_activation_code')
        else:
            return 'Login Failed'

    return '''
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

def is_authenticated():
    return session.get('authenticated', False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/set_activation_code', methods=['GET', 'POST'])
def set_activation_code():
    if not is_authenticated():
        return redirect('/')

    message = ""
    user_lists = UserList.query.all()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        list_id = request.form.get('list_id')

        if not username or not password:
            message = "Username or password not provided"
        else:
            hashed_password = generate_password_hash(password)
            user = User(username=username, password=hashed_password, list_id=list_id)
            db.session.add(user)
            try:
                db.session.commit()
                message = "User created successfully"
            except IntegrityError:
                db.session.rollback()
                message = "This username already exists"
    
    users = User.query.all()
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Set Activation Code</title>
                ''' + common_styles + '''
        </head>
        <body>
            <div class="header">
                <h1>User Management System</h1>
                ''' + render_navbar() + '''
            </div>
            <!-- Navbar aquí -->
            <div class="container">
                <h2>Create a New User</h2>
                <form method="POST">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <select name="list_id">
                        {% for user_list in user_lists %}
                            <option value="{{ user_list.id }}">{{ user_list.name }}</option>
                        {% endfor %}
                    </select>
                    <input type="submit" value="Create User">
                </form>
                <p>{{ message }}</p>
                <!-- Tabla de usuarios aquí -->
            </div>
        </body>
        </html>
    ''', users=users, user_lists=user_lists, message=message)



@app.route('/send_device_info', methods=['POST'])
def send_device_info():
    data = request.json
    mac_address = data.get('mac_address')
    ip_address = data.get('ip_address')

    if not re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac_address.lower()):
        return jsonify({"status": "failed", "message": "Invalid MAC address format"})

    if not re.match("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_address):
        return jsonify({"status": "failed", "message": "Invalid IP address format"})
    
    return jsonify({"status": "success", "mac_address": mac_address, "ip_address": ip_address})

@app.route('/activate', methods=['POST'])
def activate():
    data = request.json

    if not all(key in data for key in ['username', 'password', 'mac_address', 'ip_address']):
        return jsonify({"status": "failed", "message": "Missing data"}), 400

    username = data.get('username')
    password = data.get('password')
    mac_address = data.get('mac_address')
    ip_address = data.get('ip_address')
    banned_ip = BannedIP.query.filter_by(ip_address=ip_address).first()
    if banned_ip:
        return jsonify({"status": "failed", "message": "This IP address is banned."}), 403

    user = User.query.filter_by(username=username).first()
    if user:
        if check_password_hash(user.password, password):
            if (user.mac_address and user.mac_address != mac_address) or \
               (user.ip_address and user.ip_address != ip_address):
                return jsonify({"status": "failed", "message": "Device mismatch"}), 401

            user.online = True
            user.mac_address = mac_address
            user.ip_address = ip_address
            db.session.commit()
            login_user(user)
            return jsonify({"status": "success", "message": "Activated successfully"})
        else:
            return jsonify({"status": "failed", "message": "Invalid password"}), 401
    else:
        return jsonify({"status": "failed", "message": "User not found"}), 404


@app.route('/logout')
def logout():
    if not is_authenticated():
        return redirect('/')
    current_user.online = False
    db.session.commit()
    logout_user()
    return jsonify({"status": "success", "message": "Logged out successfully"})


common_styles = '''
<style>
    body { font-family: 'Arial', sans-serif; background: #f7f7f7; margin: 0; padding: 0; }
    .header { background: #333; color: white; text-align: center; padding: 10px 0; }
    .navbar { background: #444; overflow: hidden; }
    .navbar a { float: left; color: white; text-align: center; padding: 14px 16px; text-decoration: none; display: block; }
    .navbar a:hover { background-color: #ddd; color: black; }
    .container { width: 80%; margin: 20px auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    h2 { color: #333; margin-top: 0; }
</style>
'''
@app.route('/online_users', methods=['GET', 'POST'])
def online_users():
    if not is_authenticated():
        return redirect('/')

    message = ""
    if request.method == 'POST':
        new_list_name = request.form.get('new_list_name')
        if new_list_name:
            new_list = UserList(name=new_list_name)
            db.session.add(new_list)
            try:
                db.session.commit()
                message = "List created successfully"
            except Exception as e:
                db.session.rollback()
                message = f"Error: {str(e)}"

    user_lists = UserList.query.all()
    users = User.query.filter_by(online=True).all()

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Online Users</title>
        ''' + common_styles + '''
    </head>
    <body>
        <div class="header">
            <h1>User Management System</h1>
        </div>
        ''' + render_navbar() + '''
        <div class="container">
            <h2>Online Users</h2>
            <!-- Formulario para nuevas listas -->
            <form method="POST">
                <input type="text" name="new_list_name" placeholder="New List Name">
                <input type="submit" value="Create New List">
            </form>
            <p>{{ message }}</p>
            <!-- Visualización de listas existentes -->
            {% for user_list in user_lists %}
                <h3>{{ user_list.name }}</h3>
                <ul>
                    {% for user in user_list.users %}
                        <li>{{ user.username }} - {{ 'Online' if user.online else 'Offline' }}</li>
                    {% endfor %}
                </ul>
            {% endfor %}
            <!-- Tabla de usuarios -->
            <table>
                <tr>
                    <th>User</th>
                    <th>Status</th>
                    <th>IP</th>
                    <th>MAC</th>
                    <th>Actions</th>
                </tr>
                {% for user in users %}
                    <tr>
                        <td>{{ user.username }}</td>
                        <td>
                            <span class="status-dot {{ 'online' if user.online else 'offline' }}"></span>
                            {{ 'Online' if user.online else 'Offline' }}
                        </td>
                        <td>{{ user.ip_address }}</td>
                        <td>{{ user.mac_address }}</td>
                        <td>
                            <a href="/ban_ip/{{ user.id }}">Ban IP</a>
                            <a href="/delete_user/{{ user.id }}">Delete User</a>
                        </td>
                    </tr>
                {% endfor %}
            </table>
        </div>
    </body>
    </html>
    ''', user_lists=user_lists, users=users, message=message)




@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    if not is_authenticated():
        return redirect('/')
    
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    if request.method == 'POST':
        db.session.delete(user)
        db.session.commit()
        return redirect('/online_users')

    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Delete User</title>
            ''' + common_styles + '''
        </head>
        <body>
            ''' + render_navbar() + '''
            <div class="container">
                <h2>Delete User</h2>
                <p>Are you sure you want to delete {{ user.username }}?</p>
                <form method="POST">
                    <input type="submit" value="Delete User">
                </form>
            </div>
        </body>
        </html>
    ''', user=user)  




def render_navbar():
    return '''
    <div class="navbar">
        <a href="/set_activation_code">Set Activation Code</a>
        <a href="/online_users">Online Users</a>
        <a href="/connection_history/1">Connection History</a>
        <a href="/ban_ip/1">Ban IP</a>
        <a href="/delete_user/1">Delete User</a>
        <a href="/logout">Logout</a>
        <!-- Más enlaces según sea necesario -->
    </div>
    '''

@app.route('/ban_ip/<int:user_id>', methods=['GET', 'POST'])
def ban_ip(user_id):
    if not is_authenticated():
        return redirect('/')
    user = User.query.get(user_id)
    if not user:
        return jsonify({"status": "failed", "message": "User not found"}), 404

    if request.method == 'POST':
        ip_address = request.form.get('ip_address')
        unban = request.form.get('unban')

        if unban:
            # Desbanea la IP
            BannedIP.query.filter_by(ip_address=unban, user_id=user_id).delete()
            db.session.commit()
            return jsonify({"status": "success", "message": f"IP {unban} unbanned successfully"})

        if not ip_address:
            return jsonify({"status": "failed", "message": "IP address required"}), 400

        # Procesa el baneo de la IP
        new_banned_ip = BannedIP(ip_address=ip_address, user_id=user_id)
        db.session.add(new_banned_ip)
        db.session.commit()
        return jsonify({"status": "success", "message": f"IP {ip_address} banned successfully"})

    banned_ips = BannedIP.query.filter_by(user_id=user_id).all()

    # Muestra el formulario y la lista de IPs baneadas
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Ban IP Address</title>
            ''' + common_styles + '''
        </head>
        <body>
            ''' + render_navbar() + '''
            <div class="container">
                <h2>Ban IP Address for {{ user.username }}</h2>
                <form method="POST">
                    <input type="text" name="ip_address" placeholder="Enter IP Address" required>
                    <input type="submit" value="Ban IP">
                </form>
                <h3>Banned IPs</h3>
                <ul>
                    {% for banned_ip in banned_ips %}
                        <li>{{ banned_ip.ip_address }} 
                            <form method="post">
                                <input type="hidden" name="unban" value="{{ banned_ip.ip_address }}">
                                <input type="submit" value="Unban">
                            </form>
                        </li>
                    {% endfor %}
                </ul>
            </div>
        </body>
        </html>
    ''', user=user, banned_ips=banned_ips)



def render_navbar():
    return '''
    <div class="navbar">
        <a href="/set_activation_code">Set Activation Code</a>
        <a href="/online_users">Online Users</a>
        <a href="/connection_history/1">Connection History</a>
        <a href="/ban_ip/1">Ban IP</a>
        <a href="/delete_user/1">Delete User</a>
        <a href="/logout">Logout</a>
        <!-- Más enlaces según sea necesario -->
    </div>
    '''

@app.route('/unban_ip/<int:ip_id>', methods=['GET'])
def unban_ip(ip_id):
    if not is_authenticated():
        return redirect('/')
    banned_ip = BannedIP.query.get(ip_id)
    if banned_ip:
        db.session.delete(banned_ip)
        db.session.commit()
        return jsonify({"status": "success", "message": "IP unbanned successfully"})
    else:
        return jsonify({"status": "failed", "message": "IP not found"}), 404


@app.route('/connection_history/<int:user_id>', methods=['GET'])
def connection_history(user_id):
    if not is_authenticated():
        return redirect('/')
    history = ConnectionHistory.query.filter_by(user_id=user_id).order_by(ConnectionHistory.timestamp.desc()).all()
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Connection History</title>
            ''' + common_styles + '''
        </head>
        <body>
            ''' + render_navbar() + '''
            <div class="container">
                <h2>Connection History for User {{ user_id }}</h2>
                <table>
                    <tr>
                        <th>Timestamp</th>
                        <th>MAC Address</th>
                    </tr>
                    {% for record in history %}
                        <tr>
                            <td>{{ record.timestamp }}</td>
                            <td>{{ record.mac_address }}</td>
                        </tr>
                    {% endfor %}
                </table>
            </div>
            <!-- Pie de Página -->
        </body>
        </html>
    ''', history=history)   

@app.route('/is_ip_banned', methods=['POST'])
def is_ip_banned():
    data = request.json
    ip_address = data.get('ip_address')
    banned_ip = BannedIP.query.filter_by(ip_address=ip_address).first()
    is_banned = banned_ip is not None
    return jsonify({"is_banned": is_banned})

@app.route('/is_ready', methods=['GET'])
def is_ready():
    return jsonify({"status": "success", "message": "Server is ready"})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0')
