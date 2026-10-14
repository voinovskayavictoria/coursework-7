from logic.route_extractor import extract_python_routes, extract_express_routes

flask_code = '''
from flask import Flask, request
from flask_login import login_required

app = Flask(__name__)

@app.route('/api/users', methods=['GET'])
def list_users():
    return []

@app.route('/admin/delete', methods=['POST'])
@login_required
@admin_required
def delete_user():
    return "ok"

@app.post('/api/login')
def login():
    return "ok"
'''

for r in extract_python_routes(flask_code, "app.py"):
    print(r.to_dict())

express_code = '''
const express = require("express");
const router = express.Router();

router.get("/api/users", authMiddleware, listUsers);
app.post("/api/login", login);
app.delete("/admin/users/:id", authMiddleware, adminMiddleware, deleteUser);
'''

print("--- Express ---")
for r in extract_express_routes(express_code, "routes.js"):
    print(r.to_dict())