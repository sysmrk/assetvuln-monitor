"""Synthetic samples; deliberately fake CVE IDs, never mixed with live feeds."""
from datetime import datetime, timezone


def inventory():
    machines = [
        ('301','WS-FIN-01','10.10.20.11','Windows 11 Enterprise','10.0.26200','FINANCE'),
        ('302','WS-FIN-02','10.10.20.12','Windows 11 Enterprise','10.0.26200','FINANCE'),
        ('303','SRV-APP-01','10.10.30.21','Windows Server 2022','21H2','DC'),
        ('304','SRV-APP-02','10.10.30.22','Windows Server 2022','21H2','DC'),
        ('305','DEV-LNX-01','10.10.40.11','Ubuntu 24.04','24.04','DEV'),
        ('306','DEV-LNX-02','10.10.40.12','Ubuntu 24.04','24.04','DEV'),
        ('307','SRV-DB-01','10.10.30.31','RHEL 9','9.4','DC'),
        ('308','SRV-WEB-01','10.10.30.41','RHEL 9','9.4','DMZ'),
        ('309','WS-HR-01','10.10.20.31','Windows 11 Enterprise','10.0.26200','HR'),
        ('310','WS-OPS-01','10.10.20.51','Windows 11 Enterprise','10.0.26200','OPS'),
    ]
    result = []
    for i, (rid, name, ip, osname, ver, domain) in enumerate(machines):
        asset = dict(source_id=rid, hostname=name, ip_address=ip, os_name=osname,
                     os_version=ver, domain=domain, fqdn=f'{name.lower()}.example.local',
                     agent_status='Installed Successfully')
        sw = [dict(name='Demo Web Framework', vendor='Demo Software Foundation',
                   version='1.4.0' if i % 3 else '2.0.0'),
              dict(name='Demo Utility Library', vendor='Demo Software Foundation',
                   version='3.2.1' if i % 2 else '4.0.0'),
              dict(name='Visual Studio Code', vendor='Microsoft', version='1.95.0'),
              dict(name='7-Zip', vendor='Igor Pavlov', version='24.08')]
        result.append((asset, sw))
    return result


def vulnerabilities():
    now = datetime.now(timezone.utc).isoformat()
    return [
        {'id':'CVE-DEMO-0001','title':'DEMO ONLY: framework input validation issue',
         'summary':'Synthetic test data, not a real security advisory.',
         'severity':'CRITICAL','cvss':9.1,'kev':True,'epss':.52,
         'publishedAt':now,'synthetic':True,
         'affected':[{'package':{'ecosystem':'PyPI','name':'demo-web-framework'},
                      'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'1.5.0'}]}]}]},
        {'id':'CVE-DEMO-0002','title':'DEMO ONLY: utility memory handling issue',
         'summary':'Synthetic test data, not a real security advisory.',
         'severity':'HIGH','cvss':8.1,'kev':False,'epss':.23,
         'publishedAt':now,'synthetic':True,
         'affected':[{'package':{'ecosystem':'npm','name':'demo-util'},
                      'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'3.5.0'}]}]}]},
        {'id':'CVE-DEMO-0003','title':'DEMO ONLY: unaffected range example',
         'summary':'Synthetic test data, not a real security advisory.',
         'severity':'MEDIUM','cvss':5.4,'kev':False,'epss':.03,
         'publishedAt':now,'synthetic':True,
         'affected':[{'package':{'ecosystem':'PyPI','name':'demo-web-framework'},
                      'versions':['0.4.0']}]}]
