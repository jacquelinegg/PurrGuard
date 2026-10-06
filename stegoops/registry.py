"""Fetches a file from an image in GitLab Container Registry - no docker, no disk write (streaming layers).
Note: protocol is standard Docker Registry v2; tested only with a fake registry (see tests)."""
import os
import tarfile

import requests

ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"])
MAX_FILE = 32 * 1024 * 1024


class RegistryError(Exception):
    pass


def parse_ref(ref):
    host, _, rest = ref.partition("/")
    if "@" in rest:
        repo, _, tag = rest.partition("@")
    else:
        repo, _, tag = rest.rpartition(":") if ":" in rest.split("/")[-1] else (rest, "", "latest")
    return host, repo, tag or "latest"


class Client:
    def __init__(self, host, repo, session=None, user="gitlab-ci-token", password=None, scheme="https"):
        self.s, self.base, self.repo = session or requests.Session(), f"{scheme}://{host}", repo
        self.auth = (user, password or os.environ.get("CI_JOB_TOKEN", ""))
        self.token = None

    def _get(self, path, **kw):
        h = {**kw.pop("headers", {}), **({"Authorization": f"Bearer {self.token}"} if self.token else {})}
        r = self.s.get(self.base + path, headers=h, timeout=60, **kw)
        if r.status_code == 401 and not self.token:
            params = dict(p.split("=", 1) for p in r.headers.get("WWW-Authenticate", "").partition(" ")[2].replace('"', "").split(",") if "=" in p)
            realm = params.pop("realm", None)
            if not realm:
                raise RegistryError("Registry denied access without Bearer realm")
            t = self.s.get(realm, params={**params, "scope": f"repository:{self.repo}:pull"}, auth=self.auth, timeout=30)
            if t.status_code != 200:
                raise RegistryError(f"Registry token: HTTP {t.status_code}")
            self.token = t.json().get("token") or t.json().get("access_token")
            return self._get(path, **kw)
        if r.status_code != 200:
            raise RegistryError(f"{path}: HTTP {r.status_code}")
        return r

    def manifest(self, ref):
        m = self._get(f"/v2/{self.repo}/manifests/{ref}", headers={"Accept": ACCEPT}).json()
        if "manifests" in m:  # index -> linux/amd64
            pick = next((x for x in m["manifests"] if x.get("platform", {}).get("os") == "linux"
                         and x.get("platform", {}).get("architecture") == "amd64"), m["manifests"][0])
            m = self.manifest(pick["digest"])
        return m

    def file_from_layers(self, layers, path):
        target = os.path.normpath(path).lstrip("/")
        d, b = os.path.split(target)
        for layer in reversed(layers):  # top layer wins
            r = self._get(f"/v2/{self.repo}/blobs/{layer['digest']}", stream=True)
            with tarfile.open(fileobj=r.raw, mode="r|*") as tar:
                for mem in tar:
                    name = os.path.normpath(mem.name).lstrip("/")
                    if name == target and mem.isfile():
                        if mem.size > MAX_FILE:
                            raise RegistryError("The file is too large")
                        return tar.extractfile(mem).read()
                    if name == os.path.join(d, ".wh." + b):
                        raise RegistryError(f"{path} is deleted in an upper layer")
        raise RegistryError(f"{path} not found in image")


def fetch_file(image_ref, path, session=None, scheme="https", password=None):
    host, repo, tag = parse_ref(image_ref)
    c = Client(host, repo, session=session, scheme=scheme, password=password)
    return c.file_from_layers(c.manifest(tag)["layers"], path)
