from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__, static_folder='../frontend/build')
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'nuraV@321'
app.config['MYSQL_DB'] = 'todo_db'
app.config['JWT_SECRET_KEY'] = 'nuraV@321'  # Change this in production
mysql = MySQL(app)
api = Api(app)
CORS(app)  # Enable CORS

jwt = JWTManager(app)

### Step 3: User Registration and Login

#### User Registration Endpoint
@app.route('/', methods=['GET'])
def home():
    return "Welcome to the To-Do List API!", 200


class UserRegister(Resource):
    def get(self):
        # Fetch all users from the database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        cursor.close()
        
        # Convert query result to a list of usernames
        user_list = [{"username": user[1], "password":user[2]} for user in users]
        
        return jsonify(user_list)
    def post(self):
        data = request.get_json()
        
        # Check if JSON data was provided
        if not data:
            return {'message': 'No input data provided'}, 400

        # Extract username and password
        username = data.get('username')
        password = data.get('password')

        # Validate input
        if not username or not password:
            return {'message': 'Username and password are required'}, 400

        # Check if the user already exists
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user:
            return {'message': 'User already exists'}, 400

        # Hash the password and insert the new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        mysql.connection.commit()
        cursor.close()
        
        return {'message': 'User created successfully'}, 201

api.add_resource(UserRegister, '/register')

class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()

        if user and check_password_hash(user[2], password):  # user[2] is the password
            access_token = create_access_token(identity=user[0])  # user[0] is the user id
            return {'access_token': access_token}, 200
        return {'message': 'Invalid credentials'}, 401

api.add_resource(UserLogin, '/login')


class TodoList(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM todos WHERE user_id = %s", (user_id,))
        todos = cursor.fetchall()
        cursor.close()
        return [{'id': todo[0], 'text': todo[2], 'completed': todo[3]} for todo in todos], 200

    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()
        data = request.get_json()
        text = data['text']

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO todos (user_id, text) VALUES (%s, %s)", (user_id, text))
        mysql.connection.commit()
        cursor.close()
        return {'message': 'Todo created'}, 201

class TodoResource(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM todos WHERE user_id = %s", (user_id,))
        todos = cursor.fetchall()
        cursor.close()
        return [{'id': todo[0], 'text': todo[2], 'completed': todo[3]} for todo in todos], 200
    
    @jwt_required()
    def delete(self, todo_id):
        user_id = get_jwt_identity()
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM todos WHERE id = %s AND user_id = %s"   , (todo_id, user_id))
        mysql.connection.commit()
        cursor.close()
        return {'message': 'Todo deleted'}, 200
    
    @jwt_required()
    def patch(self, todo_id):
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if 'completed' not in data:
            return {'message': 'No completion status provided'}, 400
        
        completed = data['completed']

        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE todos SET completed = %s WHERE id = %s AND user_id = %s", (completed, todo_id, user_id))
        mysql.connection.commit()
        cursor.close()
        
        return {'message': 'Todo updated'}, 200
api.add_resource(TodoList, '/todos')
api.add_resource(TodoResource, '/todos/<int:todo_id>')

