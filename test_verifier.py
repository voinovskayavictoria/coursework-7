import tempfile
from pathlib import Path

from logic.route_extractor import extract_python_routes
from logic.state_builder import build_state_graph
from logic.mutation_engine import generate_scenarios
from logic.verifier import verify_scenarios

# Создаём временную папку с "проектом"
tmp = Path(tempfile.mkdtemp(prefix="verifier_test_"))
app_py = tmp / "app.py"

# ВАЖНО: код сохраняем в файл, чтобы верификатор его видел
code = '''
from flask import Flask, request
from flask_login import login_required, current_user

app = Flask(__name__)

@app.route('/api/login', methods=['POST'])
def login():
    return "ok"

@app.route('/api/users', methods=['GET'])
@login_required
def list_users():
    if not current_user:
        abort(401)
    return []

@app.route('/admin/users/list', methods=['GET'])
def list_all_users_unsafe():
    # нет проверки ни авторизации, ни роли
    return []

@app.route('/admin/delete', methods=['POST'])
@login_required
@admin_required
def delete_user():
    if not current_user or not current_user.is_admin:
        abort(403)
    return "ok"

@app.route('/api/order/<int:order_id>', methods=['DELETE'])
def cancel_order(order_id):
    # нет проверки владения
    order = get_order(order_id)
    order.delete()
    return "ok"
'''

app_py.write_text(code, encoding="utf-8")

routes = extract_python_routes(code, "app.py")
graph = build_state_graph(routes)
scenarios = generate_scenarios(graph["anomalies"], base_url="https://shop.example.com")

print(f"Аномалий: {len(graph['anomalies'])}")
print(f"Сценариев: {len(scenarios)}")
print()

results = verify_scenarios(scenarios, project_root=str(tmp))

verified = [r for r in results if r["verified"]]
false_positives = [r for r in results if not r["verified"]]

print(f"Подтверждено уязвимостей: {len(verified)}")
print(f"Ложных срабатываний: {len(false_positives)}")
print()

for r in results:
    icon = "✅ ПОДТВЕРЖДЕНА" if r["verified"] else "❌ ложное"
    print(f"{icon}  [{r['method']}] {r['path']}")
    print(f"   auth={r['auth_check_found']}  role={r['role_check_found']}  ownership={r['ownership_check_found']}")
    print(f"   {r['verification_reason']}")
    print()