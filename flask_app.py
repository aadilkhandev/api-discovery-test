from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Hello World"

@app.route("/users", methods=["GET"])
def get_users():
    return []

@app.route("/users", methods=["POST"])
def create_user():
    return {}

@app.get("/products")
def get_products():
    return []

@app.post("/products")
def create_product():
    return {}