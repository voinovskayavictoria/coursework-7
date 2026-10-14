from logic.route_extractor import extract_python_routes
from logic.state_builder import build_state_graph

code = '''
from flask import Flask, request
from flask_login import login_required

app = Flask(__name__)

@app.route('/api/login', methods=['POST'])
def login():
    return "ok"

@app.route('/api/users', methods=['GET'])
@login_required
def list_users():
    return []

@app.route('/admin/delete', methods=['POST'])
@login_required
@admin_required
def delete_user():
    return "ok"

@app.route('/admin/users/list', methods=['GET'])
def list_all_users_unsafe():
    return []

@app.route('/api/order/<int:order_id>', methods=['DELETE'])
def cancel_order(order_id):
    user_id = request.args.get('user_id')
    return "ok"
'''

routes = extract_python_routes(code, "app.py")

graph = build_state_graph(routes)

print("=== SUMMARY ===")
for k, v in graph["summary"].items():
    print(f"  {k}: {v}")

print("\n=== ANOMALIES ===")
for a in graph["anomalies"]:
    print(f"  [{a['method']}] {a['path']} ({a['file']}:{a['line']})")
    print(f"     required={a['required_role']}  actual={a['actual_role']}")
    print(f"     reason: {a['reason']}")

print("\n=== STATES ===")
for s in graph["states"]:
    print(f"  {s['name']}: {s['routes_count']} routes")