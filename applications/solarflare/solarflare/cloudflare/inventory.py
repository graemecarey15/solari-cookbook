"""What's in the account: Workers and Pages projects, the hostnames that reach
them, and which analytics script id belongs to which Pages project.

Pages Functions script ids come from the Pages API (`production_script_name`),
never from lining up timings: the sample case is why.
"""
from dataclasses import dataclass, field
from pathlib import Path

from . import saved


@dataclass
class Resource:
    kind: str                 # "worker" or "pages"
    name: str
    script_ids: list[str]     # names in analytics: the Worker name, or pages-worker--<n>-{production,preview}
    hosts: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass
class Host:
    host: str
    resource: Resource
    via: str                  # custom_domain, route, pages_domain, pages_dev
    zone: str | None          # None: not in any of the account's zones (e.g. *.pages.dev)


class Inventory:
    def __init__(self, resources: list[Resource], hosts: list[Host], zones: list[str]):
        self.resources = resources
        self.hosts = hosts
        self.zones = zones

    @classmethod
    def from_folder(cls, folder: Path) -> "Inventory":
        zones = saved.zone_names(folder)

        def zone_of(host: str) -> str | None:
            host = host.lower()
            return next((z for z in zones if host == z or host.endswith("." + z)), None)

        resources, hosts = [], []
        by_worker: dict[str, Resource] = {}
        for w in saved.results(folder, "workers"):
            r = Resource("worker", w["id"], [w["id"]])
            resources.append(r)
            by_worker[w["id"]] = r

        def add_host(host: str, r: Resource, via: str) -> None:
            if host and host not in r.hosts:
                r.hosts.append(host)
                hosts.append(Host(host, r, via, zone_of(host)))

        for d in saved.results(folder, "worker_domains"):
            if d.get("service") in by_worker:
                add_host(d["hostname"], by_worker[d["service"]], "custom_domain")
        for zone_routes in (saved.load(folder, "worker_routes") or {}).values():
            for route in zone_routes.get("result") or []:
                if route.get("script") in by_worker:
                    host = route["pattern"].split("/", 1)[0].lstrip("*.")
                    add_host(host, by_worker[route["script"]], "route")

        for p in saved.results(folder, "pages_projects"):
            ids = [s for s in (p.get("production_script_name"), p.get("preview_script_name")) if s]
            r = Resource("pages", p["name"], ids)
            resources.append(r)
            for domain in p.get("domains") or []:
                add_host(domain, r, "pages_dev" if domain.endswith(".pages.dev") else "pages_domain")
        return cls(resources, hosts, zones)

    def by_script_id(self, script_id: str) -> Resource | None:
        return next((r for r in self.resources if script_id in r.script_ids), None)
