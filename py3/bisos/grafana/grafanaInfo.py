# -*- coding: utf-8 -*-

""" #+begin_org
* ~[Summary]~ :: =CS-Lib= The single source of the facts of this host's Grafana installation.
#+end_org """

""" #+begin_org
* [[elisp:(org-cycle)][| ~Description~ |]] :: Facts shared by grafana-sbom.pcs, grafanaUsage-sbom.pcs, grafanaAdmin.cs,
quickGrafana.cs, grafana-sysd.pcs, grafana-here-dns.pcs and grafana-wvd.pcs: the account, the pinned
upstream versions and their checksums, the install/config/data paths, the EnvironmentFile, the fqdn,
the banna ports (Grafana's own, and Prometheus's for the provisioned datasource) and the admin login.
** Pure: importing this module has no side effects and touches no host state.
** The generators below return the text of /etc/grafana/grafana.ini, /etc/default/grafana, the
provisioning files and the shared [Service] lines of the unit, so that the code that writes them and
the code that checks them (grafanaAdmin.cs -i driftCheck) cannot disagree.
** The admin login is admin / grafana: the rawBisos out-of-the-box convention (user admin, password
the service's name). It is insecure by design; securing a host is a separate layer on top.
** Status: Starting point.
** /[[elisp:(org-cycle)][| Planned Improvements |]]/ :
*** TODO The "secure it" layer: a real admin password, HTTPS (bisos.crypt), listening beyond loopback.
*** TODO Architectures other than amd64: add each one's checksum to the *Sha256 tuples.
#+end_org """

####+BEGIN: b:prog:file/proclamations :outLevel 1
""" #+begin_org
* *[[elisp:(org-cycle)][| Proclamations |]]* :: Libre-Halaal Software --- Part Of BISOS ---  Poly-COMEEGA Format.
** This is Libre-Halaal Software. © Neda Communications, Inc. Subject to AGPL.
** It is part of BISOS (ByStar Internet Services OS)
** Best read and edited  with Blee in Poly-COMEEGA (Polymode Colaborative Org-Mode Enhance Emacs Generalized Authorship)
#+end_org """
####+END:

####+BEGIN: b:prog:file/particulars :authors ("./inserts/authors-mb.org")
""" #+begin_org
* *[[elisp:(org-cycle)][| Particulars |]]* :: Authors, version
** This File: /bisos/git/bxRepos/bisos-pip/grafana/py3/bisos/grafana/grafanaInfo.py
** Authors: Mohsen BANAN, http://mohsen.banan.1.byname.net/contact
#+end_org """
####+END:

import dataclasses
import difflib
import json
import pathlib

from bisos.banna import tcpPorts as bannaTcpPorts


def _bannaPortNu(portName: str) -> int:
    """The registry, bisos.banna, is authoritative: never hardcode these ports."""
    return bannaTcpPorts.tcpPortsAssignedList.tcpPortsList[portName].portNu


@dataclasses.dataclass(frozen=True)
class GrafanaInfo:
    """The facts of this host's Grafana installation. Built once, as grafanaInfo below."""

    acctName: str = "grafana"

    # Grafana OSS is not packaged by Debian. The upstream tarball is pinned with the SHA-256
    # dl.grafana.com publishes next to it (<tarball>.sha256). Per Debian architecture.
    version: str = "13.2.4"
    distSha256: tuple = (("amd64", "c48765988fd88572607e4ea670251af8a8e64ab3e360d0f3cf67a6f3587b92ab"),)

    # gcx, Grafana Labs' CLI for Grafana's HTTP API (it replaced grafanactl), released on GitHub
    # with a SHA-256 per asset. The usage side: grafanaUsage-sbom.pcs installs it.
    gcxVersion: str = "1.6.0"
    gcxSha256: tuple = (("amd64", "335e051cda6edfb4ad5757540208961dbdfab6d89d4af11a4087de6ffa0ec111"),)

    installBase: pathlib.Path = pathlib.Path("/opt/grafana")
    confDir: pathlib.Path = pathlib.Path("/etc/grafana")

    # grafana.db (users, dashboards, ...) and installed plugins. Owned by the account.
    dataDir: pathlib.Path = pathlib.Path("/var/lib/grafana")

    # Read by systemd as root before the unit drops to User=. root:acctName 640.
    # Grafana reads GF_<SECTION>_<KEY> variables as overrides of grafana.ini.
    envFile: pathlib.Path = pathlib.Path("/etc/default/grafana")

    # Loopback only, behind nginx (grafana.here), as every rawBisos web UI is.
    listenIp: str = "127.0.0.1"

    fqdn: str = "grafana.here"

    # rawBisos convention: user admin, password the service's name. Insecure by design;
    # Grafana applies it only when it creates grafana.db (the first start).
    adminUser: str = "admin"
    adminPassword: str = "grafana"

    portNu: int = dataclasses.field(default_factory=lambda: _bannaPortNu('grafana'))
    # Prometheus's port, for the provisioned datasource. From banna: bisos.grafana does not
    # import bisos.prometheus, and works (with an unreachable datasource) without it.
    prometheusPortNu: int = dataclasses.field(default_factory=lambda: _bannaPortNu('prometheus'))

    @property
    def distName(self) -> str:
        """The tarball's top directory (it carries no architecture)."""
        return f"grafana-{self.version}"

    def distUrl(self, arch: str = "amd64") -> str:
        return f"https://dl.grafana.com/oss/release/grafana-{self.version}.linux-{arch}.tar.gz"

    @property
    def distDir(self) -> pathlib.Path:
        return self.installBase / self.distName

    @property
    def homeLink(self) -> pathlib.Path:
        """installBase/current -> distDir. Grafana's --homepath; units and CLI go through it."""
        return self.installBase / "current"

    @property
    def grafanaBin(self) -> pathlib.Path:
        return self.homeLink / "bin" / "grafana"

    def gcxUrl(self, arch: str = "amd64") -> str:
        return (f"https://github.com/grafana/gcx/releases/download/"
                f"v{self.gcxVersion}/gcx_{self.gcxVersion}_linux_{arch}.tar.gz")

    @property
    def gcxDir(self) -> pathlib.Path:
        return self.installBase / f"gcx-{self.gcxVersion}"

    @property
    def gcxLink(self) -> pathlib.Path:
        return self.installBase / "gcx"

    @property
    def gcxBin(self) -> pathlib.Path:
        return self.gcxLink / "gcx"

    @property
    def gcxLogin(self) -> str:
        """The gcx login to this host's Grafana with the rawBisos login.

        gcx stores credentials in the OS keychain and refuses to fall back to a file; a BISOS host
        has no keychain service, so GCX_KEYCHAIN=off (plaintext under ~/.config/gcx --- rawBisos).
        Later gcx invocations need GCX_KEYCHAIN=off too (export it).
        """
        return (f"GCX_KEYCHAIN=off GRAFANA_PASSWORD={self.adminPassword} {self.gcxBin} login local"
                f" --server {self.baseUrl} --basic-auth --user {self.adminUser} --yes")

    @property
    def iniFile(self) -> pathlib.Path:
        return self.confDir / "grafana.ini"

    @property
    def provisioningDir(self) -> pathlib.Path:
        return self.confDir / "provisioning"

    @property
    def datasourceFile(self) -> pathlib.Path:
        return self.provisioningDir / "datasources" / "prometheus.yaml"

    @property
    def dashboardProviderFile(self) -> pathlib.Path:
        return self.provisioningDir / "dashboards" / "bisos.yaml"

    @property
    def dashboardsDir(self) -> pathlib.Path:
        """The JSON dashboards the provider above loads."""
        return self.confDir / "dashboards"

    @property
    def hostDashboardFile(self) -> pathlib.Path:
        return self.dashboardsDir / "host.json"

    @property
    def pluginsDir(self) -> pathlib.Path:
        return self.dataDir / "plugins"

    @property
    def listenAddr(self) -> str:
        return f"{self.listenIp}:{self.portNu}"

    @property
    def baseUrl(self) -> str:
        """The address humans browse, through the nginx vhost."""
        return f"http://{self.fqdn}"

    @property
    def localUrl(self) -> str:
        """Straight to Grafana, bypassing nginx."""
        return f"http://{self.listenAddr}"

    @property
    def prometheusUrl(self) -> str:
        return f"http://{self.listenIp}:{self.prometheusPortNu}"


# A Singleton
grafanaInfo = GrafanaInfo()


def tarballSetupScript(url: str, sha256: tuple, dirName: str, link: pathlib.Path,
                       base: pathlib.Path, hasTopDir: bool = True) -> str:
    """Bash: fetch a pinned release tarball for this host's architecture, verify, unpack, link.

    Unpacked once per version into base/<dirName>, root-owned; link then points at it. A tarball
    whose SHA-256 does not match is discarded and nothing is unpacked. url and dirName may contain
    the literal ARCH, replaced by the Debian architecture at run time. hasTopDir=False is for
    tarballs whose files are at the top level (gcx): they are unpacked into base/<dirName>.
    """
    cases = "\n".join(f'    {arch}) sha={sha} ;;' for arch, sha in sha256)
    into = "{base}" if hasTopDir else '"$dir"'
    return f"""
set -e
arch=$(dpkg --print-architecture)
case "$arch" in
{cases}
    *) echo "no pinned checksum for architecture $arch" >&2 ; exit 1 ;;
esac
dir={base}/{dirName.replace("ARCH", "$arch")}
sudo mkdir -p {base}
if [ ! -d "$dir" ] ; then
    tmpDir=$(mktemp -d)
    trap 'rm -rf "$tmpDir"' EXIT
    curl -fsSL -o "$tmpDir/dist.tgz" {url.replace("ARCH", "$arch")}
    echo "$sha  $tmpDir/dist.tgz" | sha256sum -c --quiet -
    {"" if hasTopDir else 'sudo mkdir -p "$dir"'}
    sudo tar -xzf "$tmpDir/dist.tgz" -C {into.format(base=base)}
    sudo chown -R root:root "$dir"
fi
sudo ln -sfn "$dir" {link}
"""


def distSetupScript(info: GrafanaInfo = grafanaInfo) -> str:
    return tarballSetupScript(info.distUrl("ARCH"), info.distSha256, info.distName,
                              info.homeLink, info.installBase)


def gcxSetupScript(info: GrafanaInfo = grafanaInfo) -> str:
    return tarballSetupScript(info.gcxUrl("ARCH"), info.gcxSha256, info.gcxDir.name,
                              info.gcxLink, info.installBase, hasTopDir=False)


def iniFileContent(info: GrafanaInfo = grafanaInfo) -> str:
    """The content /etc/grafana/grafana.ini is generated with. Written only when absent.

    Only what differs from the tarball's conf/defaults.ini. Logs go to the console, so to
    journald. Phoning home (usage reports, update checks, plugin preinstalls) is off.
    """
    return (
        "; Generated by grafana-sbom.pcs from bisos.grafana.grafanaInfo. Written only when absent.\n"
        "[paths]\n"
        f"data = {info.dataDir}\n"
        f"plugins = {info.pluginsDir}\n"
        f"provisioning = {info.provisioningDir}\n"
        "\n"
        "[server]\n"
        f"http_addr = {info.listenIp}\n"
        f"http_port = {info.portNu}\n"
        f"domain = {info.fqdn}\n"
        f"root_url = {info.baseUrl}/\n"
        "\n"
        "[security]\n"
        "; rawBisos convention, insecure by design: applied only when grafana.db is created.\n"
        f"admin_user = {info.adminUser}\n"
        f"admin_password = {info.adminPassword}\n"
        "\n"
        "[log]\n"
        "mode = console\n"
        "\n"
        "[analytics]\n"
        "reporting_enabled = false\n"
        "check_for_updates = false\n"
        "check_for_plugin_updates = false\n"
        "\n"
        "[plugins]\n"
        "; Grafana otherwise downloads its \"preinstalled\" app plugins from grafana.com at every start,\n"
        "; unpinned and unverified, outside the sbom. Plugins are installed deliberately (grafana cli).\n"
        "preinstall_disabled = true\n"
        "preinstall_auto_update = false\n"
    )


def envFileContent(info: GrafanaInfo = grafanaInfo) -> str:
    """The content /etc/default/grafana is generated with. Written only when absent."""
    return (
        "# Grafana reads GF_<SECTION>_<KEY>=value as an override of grafana.ini, e.g.\n"
        "# GF_LOG_LEVEL=debug\n"
    )


def datasourceContent(info: GrafanaInfo = grafanaInfo) -> str:
    """Provisioning of this host's Prometheus as the default datasource. Written only when absent."""
    return (
        "# Generated by grafana-sbom.pcs from bisos.grafana.grafanaInfo. Written only when absent.\n"
        "apiVersion: 1\n"
        "datasources:\n"
        "  - name: Prometheus\n"
        "    uid: bisos-prometheus\n"
        "    type: prometheus\n"
        "    access: proxy\n"
        f"    url: {info.prometheusUrl}\n"
        "    isDefault: true\n"
        "    editable: true\n"
    )


def dashboardProviderContent(info: GrafanaInfo = grafanaInfo) -> str:
    """Provisioning of the dashboards in dashboardsDir. Written only when absent."""
    return (
        "# Generated by grafana-sbom.pcs from bisos.grafana.grafanaInfo. Written only when absent.\n"
        "apiVersion: 1\n"
        "providers:\n"
        "  - name: bisos\n"
        "    folder: BISOS\n"
        "    type: file\n"
        "    allowUiUpdates: true\n"
        "    options:\n"
        f"      path: {info.dashboardsDir}\n"
    )


def hostDashboardContent(info: GrafanaInfo = grafanaInfo) -> str:
    """A small dashboard of this host's node_exporter metrics, for out-of-the-box use.

    Generated, not downloaded: no grafana.com dependency. Written only when absent.
    """
    ds = {"type": "prometheus", "uid": "bisos-prometheus"}

    def panel(pid: int, title: str, expr: str, unit: str, x: int, y: int) -> dict:
        return {
            "id": pid, "type": "timeseries", "title": title, "datasource": ds,
            "gridPos": {"h": 8, "w": 12, "x": x, "y": y},
            "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
            "targets": [{"refId": "A", "datasource": ds, "expr": expr, "legendFormat": "{{instance}}"}],
        }

    dashboard = {
        "uid": "bisos-host",
        "title": "Host (node_exporter)",
        "tags": ["bisos"],
        "timezone": "browser",
        "schemaVersion": 39,
        "refresh": "30s",
        "time": {"from": "now-1h", "to": "now"},
        "panels": [
            panel(1, "CPU busy", '1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m]))',
                  "percentunit", 0, 0),
            panel(2, "Load (1m)", "node_load1", "short", 12, 0),
            panel(3, "Memory used", "1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes",
                  "percentunit", 0, 8),
            panel(4, "Root filesystem used",
                  '1 - node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}',
                  "percentunit", 12, 8),
        ],
    }
    return json.dumps(dashboard, indent=2) + "\n"


def sysdServiceLines(envFile: pathlib.Path, info: GrafanaInfo = grafanaInfo) -> str:
    """The identity lines the grafana unit has in its [Service] section."""
    return (
        f"User={info.acctName}\n"
        f"Group={info.acctName}\n"
        f"EnvironmentFile={envFile}\n"
    )


def textDrift(liveText: str, generatedText: str) -> list[str]:
    """A unified diff of a structured file (INI, YAML, JSON) against its generator; empty when they agree."""
    return list(difflib.unified_diff(generatedText.splitlines(), liveText.splitlines(),
                                     "generator", "live", lineterm=""))


def unitDrift(unitText: str, envFile: pathlib.Path, info: GrafanaInfo = grafanaInfo) -> list[str]:
    """The identity lines (sysdServiceLines) that an installed unit file lacks."""
    present = {line.strip() for line in unitText.splitlines()}
    return [line for line in sysdServiceLines(envFile, info).splitlines() if line not in present]


####+BEGIN: b:py3:cs:framework/endOfFile :basedOn "classification"
""" #+begin_org
* [[elisp:(org-cycle)][| *End-Of-Editable-Text* |]] :: emacs and org variables and control parameters
#+end_org """

#+STARTUP: showall

### local variables:
### no-byte-compile: t
### end:
####+END:
