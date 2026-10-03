from ..core.models import Finding


def idor_probe(client, reporter, path_template, id_a, id_b, token_a, token_b):
    """Read-only BOLA/IDOR probe using two explicitly authorized accounts."""
    if "{id}" not in path_template:
        raise ValueError("--path must contain an {id} placeholder")
    path_b = path_template.replace("{id}", str(id_b))
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    try:
        own = client.request("GET", path_template.replace("{id}", str(id_a)), headers=headers_a, allow_redirects=False)
        cross = client.request("GET", path_b, headers=headers_a, allow_redirects=False)
        owner = client.request("GET", path_b, headers=headers_b, allow_redirects=False)
    except Exception as exc:
        reporter.error(f"IDOR probe failed: {exc}")
        return
    if cross.status_code == 200 and cross.text.strip() and owner.status_code == 200:
        reporter.add(Finding(
            "HIGH", "authorization", "Possible BOLA/IDOR: account A can read account B resource",
            f"Account A received HTTP 200 for {path_b}; account B also received HTTP 200.",
            "Enforce object-level authorization on every resource lookup and derive ownership from the authenticated principal.", cross.url))
    else:
        reporter.info(f"IDOR probe: own={own.status_code}, cross={cross.status_code}, owner={owner.status_code}")
