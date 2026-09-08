import os
import tarfile
import zipfile


def unpack(archive_path, dest):
    tar = tarfile.open(archive_path)
    # ruleid: traust-python-path-traversal-tar-extractall-nofilter
    tar.extractall(dest)

    member = tar.getmembers()[0]
    # ruleid: traust-python-path-traversal-tar-extractall-nofilter
    tar.extract(member, dest)

    # ok: traust-python-path-traversal-tar-extractall-nofilter
    tar.extractall(dest, filter="data")

    # ok: traust-python-path-traversal-tar-extractall-nofilter
    tar.extract(member, dest, filter="data")


def unpack_zip(archive_path, dest):
    # zipfile sanitizes member paths on extract — zip-slip is tarfile-only;
    # flagging these re-seeds a refuted FP class (Precision Gate R9).
    zf = zipfile.ZipFile(archive_path)
    # ok: traust-python-path-traversal-tar-extractall-nofilter
    zf.extractall(dest)

    with zipfile.ZipFile(archive_path) as zf2:
        # ok: traust-python-path-traversal-tar-extractall-nofilter
        zf2.extractall(dest)


def contained(base, name):
    p = os.path.join(base, name)
    # ruleid: traust-python-path-traversal-containment-startswith
    if os.path.realpath(p).startswith(base):
        return p

    # ruleid: traust-python-path-traversal-containment-startswith
    if os.path.abspath(p).startswith(base):
        return p

    # ok: traust-python-path-traversal-containment-startswith
    if os.path.realpath(p).startswith(base + os.sep):
        return p

    # ok: traust-python-path-traversal-containment-startswith
    if os.path.abspath(p).startswith(os.path.join(base, "")):
        return p
    return None
