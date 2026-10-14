from logic.route_extractor import extract_python_routes
from logic.state_builder import build_state_graph
from logic.mutation_engine import generate_scenarios

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
scenarios = generate_scenarios(graph["anomalies"], base_url="https://shop.example.com")

print(f"Найдено сценариев: {len(scenarios)}\n")

for s in scenarios:
    print(f"[{s.severity.upper()}] {s.method} {s.path}")
    print(f"   Тип атаки: {s.attack_type}")
    print(f"   Файл: {s.file}:{s.line}")
    print(f"   Причина: {s.reason}")
    print(f"   Параметры: {s.test_params}")
    print(f"   curl-примеры:")
    for cmd in s.curl_examples:
        print(f"     {cmd}")
    print()