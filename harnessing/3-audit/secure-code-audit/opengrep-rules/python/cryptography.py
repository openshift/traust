import requests


def fetch(url, session):
    # ruleid: traust-python-cryptography-requests-verify-false
    requests.get(url, verify=False)

    # ruleid: traust-python-cryptography-requests-verify-false
    session.verify = False

    # ok: traust-python-cryptography-requests-verify-false
    requests.get(url, timeout=30)

    # ok: traust-python-cryptography-requests-verify-false
    requests.get(url, verify="/etc/pki/ca-trust/custom.pem")


def irc_factory(sock, host):
    import functools
    import ssl

    # ruleid: traust-python-cryptography-ssl-wrap-socket
    wrapper = ssl.wrap_socket

    # ruleid: traust-python-cryptography-ssl-wrap-socket
    ssl.wrap_socket(sock)

    # ok: traust-python-cryptography-ssl-wrap-socket
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # ok: traust-python-cryptography-ssl-wrap-socket
    wrapper = functools.partial(ctx.wrap_socket, server_hostname=host)
    return wrapper


def build_dsn(user, host):
    # ruleid: traust-python-cryptography-insecure-dsn-transport
    dsn = f"postgresql://{user}@{host}:5432/app?sslmode=disable"

    # ruleid: traust-python-cryptography-insecure-dsn-transport
    mysql_dsn = "mysql+pymysql://app@db/app?ssl-mode=DISABLED"

    # ok: traust-python-cryptography-insecure-dsn-transport
    safe = f"postgresql://{user}@{host}:5432/app?sslmode=verify-full"
    return dsn, mysql_dsn, safe
