import os
import subprocess

from flask import request


def run_dynamic(user_target):
    # ruleid: traust-python-injection-subprocess-shell
    subprocess.run(f"nslookup {user_target}", shell=True)

    # ruleid: traust-python-injection-subprocess-shell
    os.system("ping -c1 " + user_target)

    # ok: traust-python-injection-subprocess-shell
    subprocess.run("systemctl restart chronyd", shell=True)

    # ok: traust-python-injection-subprocess-shell
    subprocess.run(["nslookup", user_target])


def handler():
    host = request.args.get("host")
    # ruleid: traust-python-injection-request-to-shell-taint
    subprocess.check_output(["dig", host])

    # ok: traust-python-injection-request-to-shell-taint
    subprocess.check_output(["dig", "example.com"])


def raw_sql(request, connection, Model):
    q = request.GET.get("q")
    cursor = connection.cursor()
    # ruleid: traust-python-injection-raw-sql-taint
    cursor.execute(f"SELECT * FROM t WHERE name = '{q}'")

    # ruleid: traust-python-injection-raw-sql-taint
    Model.objects.extra(where=[f"name = '{q}'"])

    # ok: traust-python-injection-raw-sql-taint
    cursor.execute("SELECT * FROM t WHERE fixed = 1")


def render_user_template(request):
    import jinja2

    tpl = request.form.get("template")
    # ruleid: traust-python-injection-jinja2-template-taint
    return jinja2.Template(tpl).render()


def render_static_template():
    import jinja2

    # ok: traust-python-injection-jinja2-template-taint
    return jinja2.Template("hello {{ name }}").render(name="world")
