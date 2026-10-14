"""
Тест оркестратора анализа бизнес-логики.
Создаёт временный Flask-проект, запускает analyze_logic и печатает находки.
"""
import tempfile
from pathlib import Path

from logic.analyzer import analyze_logic, LOGIC_RULE_NAME


# Пример уязвимого Flask-проекта
VULNERABLE_APP = '''
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
    user_id = request.args.get('user_id')
    order = get_order(order_id)
    order.delete()
    return "ok"
'''


def main():
    tmp = Path(tempfile.mkdtemp(prefix="analyzer_test_"))
    app_file = tmp / "app.py"
    app_file.write_text(VULNERABLE_APP, encoding="utf-8")

    print(f"Тестовый проект: {tmp}")
    print("Запуск анализа...\n")

    findings = analyze_logic(
        project_root=str(tmp),
        max_depth=None,
        enabled_rules=None,
        base_url="https://shop.example.com",
    )

    print(f"Найдено логических уязвимостей: {len(findings)}\n")

    for i, f in enumerate(findings, 1):
        print(f"--- Finding #{i} ---")
        print(f"  name:        {f['name']}")
        print(f"  severity:    {f['severity']}")
        print(f"  rule:        {f['rule']}")
        print(f"  description: {f['description']}")
        print(f"  recommendation: {f['recommendation']}")
        print(f"  code_snippet:")
        for line in f['code_snippet'].splitlines():
            print(f"      {line}")
        print()

    # Проверка фильтрации по правилам
    print("--- Проверка фильтрации ---")
    findings_filtered = analyze_logic(
        project_root=str(tmp),
        max_depth=None,
        enabled_rules={"Слабый CSP"},  # НЕ содержит "Логические уязвимости"
    )
    print(f"С фильтром 'Слабый CSP' найдено: {len(findings_filtered)} (ожидается 0)")

    findings_all = analyze_logic(
        project_root=str(tmp),
        max_depth=None,
        enabled_rules={LOGIC_RULE_NAME},
    )
    print(f"С фильтром '{LOGIC_RULE_NAME}' найдено: {len(findings_all)} (ожидается > 0)")

    print("\nТест завершён.")


if __name__ == "__main__":
    main()