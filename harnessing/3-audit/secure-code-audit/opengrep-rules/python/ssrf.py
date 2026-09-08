import requests
from flask import request


def proxy():
    target = request.args.get("url")
    # ruleid: traust-python-ssrf-request-taint
    requests.get(target)

    # ruleid: traust-python-ssrf-request-taint
    requests.post("https://" + request.form.get("backend") + "/api")

    # ok: traust-python-ssrf-request-taint
    requests.get("https://api.openshift.com/healthz")
