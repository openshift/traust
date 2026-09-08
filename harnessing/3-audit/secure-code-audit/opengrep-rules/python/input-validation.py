import yaml


def parse(doc):
    # ruleid: traust-python-input-validation-yaml-unsafe-load
    yaml.load(doc)

    # ruleid: traust-python-input-validation-yaml-unsafe-load
    yaml.load(doc, Loader=yaml.UnsafeLoader)

    # ruleid: traust-python-input-validation-yaml-unsafe-load
    yaml.unsafe_load(doc)

    # ok: traust-python-input-validation-yaml-unsafe-load
    yaml.safe_load(doc)

    # ok: traust-python-input-validation-yaml-unsafe-load
    yaml.load(doc, Loader=yaml.SafeLoader)

    # ok: traust-python-input-validation-yaml-unsafe-load
    yaml.load(open("config/defaults.yaml"))

    # ok: traust-python-input-validation-yaml-unsafe-load
    yaml.load(open("settings.yml"), Loader=yaml.FullLoader)


def ruamel_roundtrip(doc):
    from ruamel.yaml import YAML

    yaml = YAML(typ="rt")

    # ok: traust-python-input-validation-yaml-unsafe-load
    yaml.load(doc)


def restore_state(request):
    import pickle

    raw = request.body
    # ruleid: traust-python-input-validation-pickle-loads-taint
    return pickle.loads(raw)


def restore_state_encoded(request):
    import base64
    import pickle

    blob = request.form.get("state")
    # ruleid: traust-python-input-validation-pickle-loads-taint
    return pickle.loads(base64.b64decode(blob))


def load_trusted_cache(path):
    import pickle

    # ok: traust-python-input-validation-pickle-loads-taint
    with open(path, "rb") as f:
        return pickle.load(f)
