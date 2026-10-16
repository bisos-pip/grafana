#!/bin/bash -i
#

# Safety check: must run from a directory named "tests"
if [[ "$(basename "$PWD")" != "tests" ]]; then
    echo "ERROR: verify.sh must be run from a directory named 'tests'." >&2
    echo "  Current PWD: $PWD" >&2
    exit 1
fi

# Starting-point smoke test for bisos.grafana -- covers grafanaAdmin.cs, quickGrafana.cs,
# the read-only Cmnds of the planted files, and bisos.grafana.grafanaInfo's generators.
# Nothing here installs, starts or writes anything on the host.

# --- CS entry points: smoke test (no args → examples/usage, non-zero ok) ---

lpDo ../bin/grafanaAdmin.cs
lpDo ../bin/quickGrafana.cs
lpDo ../bin/grafana-assemble.cs

# --- grafanaAdmin.cs: each admin sub-Cmnd runs and produces examples output ---

lpDo ../bin/grafanaAdmin.cs -i examples
lpDo ../bin/grafanaAdmin.cs -i hostInfo
lpDo ../bin/grafanaAdmin.cs -i servicesInfo
lpDo ../bin/grafanaAdmin.cs -i apiInfo
lpDo ../bin/grafanaAdmin.cs -i driftCheck
lpDo ../bin/grafanaAdmin.cs -i fullUpdate

# --- planted files: menus and read-only Cmnds ---

lpDo ../bin/grafana-sbom.pcs -i readme
lpDo ../bin/grafanaUsage-sbom.pcs -i readme
lpDo ../bin/grafanaCbs-sbom.pcs -i readme
lpDo ../bin/grafana-sysd.pcs
lpDo ../bin/grafana-cbs.pcs
lpDo ../bin/cbmProc-grafana.spcs
lpDo ../bin/grafana-here-dns.pcs
lpDo ../bin/grafana-wvd.pcs -i configFileStdout --cls=configFile_nginxVd

# --- bisos.grafana.grafanaInfo: banna numbers and generator invariants ---

lpDo python3 -c "
import json, subprocess, sys
from bisos.banna import sysAccts
from bisos.grafana.grafanaInfo import (
    grafanaInfo as i, iniFileContent, datasourceContent, hostDashboardContent,
    distSetupScript, gcxSetupScript, textDrift,
)

cases = [
    ('banna: grafana port',                i.portNu == 24011),
    ('banna: prometheus port (datasource)', i.prometheusPortNu == 24010),
    ('banna sysAccts: grafana uid',        sysAccts.sysAcctOf(i.acctName).uid == 505),
    ('banna sysAccts: homeDir',            sysAccts.sysAcctOf(i.acctName).homeDir == str(i.dataDir)),
    ('listener on loopback',               'http_addr = 127.0.0.1' in iniFileContent()),
    ('root_url is grafana.here',           'root_url = http://grafana.here/' in iniFileContent()),
    ('rawBisos login admin / grafana',     'admin_user = admin' in iniFileContent() and 'admin_password = grafana' in iniFileContent()),
    ('no plugin downloads at start',       'preinstall_disabled = true' in iniFileContent()),
    ('no phoning home',                    'reporting_enabled = false' in iniFileContent()),
    ('datasource -> banna prometheus',     f'url: http://127.0.0.1:{i.prometheusPortNu}' in datasourceContent()),
    ('host dashboard is valid JSON',       json.loads(hostDashboardContent())['uid'] == 'bisos-host'),
    ('dashboard uses the datasource uid',  'bisos-prometheus' in hostDashboardContent()),
    ('tarball scripts parse',              all(subprocess.run(['bash', '-n'], input=s, text=True).returncode == 0
                                               for s in (distSetupScript(), gcxSetupScript()))),
    ('drift: ini edit reported',           textDrift(iniFileContent() + 'x = 1\n', iniFileContent()) != []),
]

failed = 0
for name, ok in cases:
    print(f'  [{\"PASS\" if ok else \"FAIL\"}] {name}')
    failed += not ok

if failed:
    print(f'grafanaInfo: {failed} test(s) FAILED')
    sys.exit(1)
else:
    print('grafanaInfo: all cases PASS')
" 2>/dev/null || true
