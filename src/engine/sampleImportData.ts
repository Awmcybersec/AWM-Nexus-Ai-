/**
 * AWM Nexus — Sample Valid External Tool Outputs
 * Realistic, verified samples for Nmap XML, Burp XML, Nessus XML, and Nuclei JSONL
 */

export const SAMPLE_NMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV --script=vuln -p 80,443,3000 127.0.0.1" start="1709300000" version="7.93">
<host starttime="1709300001" endtime="1709300010">
  <status state="up" reason="localhost-response"/>
  <address addr="127.0.0.1" addrtype="ipv4"/>
  <hostnames>
    <hostname name="localhost" type="user"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="3000">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Node.js Express / Vite" version="22.23.4" method="probed" conf="10"/>
      <script id="http-vuln-cve2021-41773" output="State: VULNERABLE&#xa;  Path traversal enabled via unvalidated URI prefixes.&#xa;  References: https://nvd.nist.gov/vuln/detail/CVE-2021-41773"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="https" product="OpenSSL" version="3.0.22" tunnel="ssl" method="probed" conf="10"/>
      <script id="ssl-enum-ciphers" output="  TLSv1.0: Deprecated legacy protocol enabled with weak cipher suites.&#xa;  Least strength: low"/>
    </port>
  </ports>
</host>
</nmaprun>`;

export const SAMPLE_BURP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE issues SYSTEM "burp-issues.dtd">
<issues burpVersion="2024.1.1">
  <issue>
    <serialNumber>1001</serialNumber>
    <type>1048832</type>
    <name>SQL Injection (Blind Boolean-based)</name>
    <host ip="127.0.0.1">http://127.0.0.1:3000</host>
    <path>/api/v1/search</path>
    <location>http://127.0.0.1:3000/api/v1/search?q=test</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>&lt;p&gt;SQL injection vulnerabilities arise when user input is concatenated directly into SQL queries without parameterization (CWE-89).&lt;/p&gt;</issueBackground>
    <issueDetail>The parameter 'q' was found to be vulnerable to blind boolean-based SQL injection using payloads: ' AND 1=1 -- and ' AND 1=2 --</issueDetail>
    <remediationBackground>Use parameterized queries or Object Relational Mapping (ORM) with prepared statements.</remediationBackground>
    <vulnerabilityClassifications>CWE-89, CAPEC-66</vulnerabilityClassifications>
    <requestresponse>
      <request base64="false">GET /api/v1/search?q=admin'-- HTTP/1.1&#xa;Host: 127.0.0.1:3000</request>
      <response base64="false">HTTP/1.1 200 OK&#xa;Content-Type: application/json&#xa;&#xa;{"results": [{"id": 1, "username": "admin"}]}</response>
    </requestresponse>
  </issue>
  <issue>
    <serialNumber>1002</serialNumber>
    <type>2097408</type>
    <name>Cross-Site Scripting (Reflected)</name>
    <host ip="127.0.0.1">http://127.0.0.1:3000</host>
    <path>/login</path>
    <location>http://127.0.0.1:3000/login?msg=invalid</location>
    <severity>Medium</severity>
    <confidence>Certain</confidence>
    <issueBackground>Reflected Cross-site scripting (XSS) occurs when an application receives user data in an HTTP request and includes it in immediate response (CWE-79).</issueBackground>
    <issueDetail>The parameter 'msg' is echoed into script blocks without HTML encoding.</issueDetail>
    <remediationBackground>Context-aware output encoding and strict Content Security Policy.</remediationBackground>
    <vulnerabilityClassifications>CWE-79, CAPEC-63</vulnerabilityClassifications>
  </issue>
</issues>`;

export const SAMPLE_NESSUS_XML = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Corporate External Perimeter Audit">
    <ReportHost name="127.0.0.1">
      <HostProperties>
        <tag name="host-ip">127.0.0.1</tag>
        <tag name="host-fqdn">localhost.localdomain</tag>
        <tag name="operating-system">Linux Kernel 5.15</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" pluginID="104743" pluginName="TLS Version 1.0 Protocol Detection" pluginFamily="General" severity="2">
        <description>The remote service accepts connections encrypted using TLS 1.0. This version has known weaknesses.</description>
        <solution>Enable TLS 1.2 and/or TLS 1.3 and disable TLS 1.0.</solution>
        <cve>CVE-2011-3389</cve>
        <cwe>CWE-326</cwe>
        <cvss_base_score>5.0</cvss_base_score>
        <see_also>https://tools.ietf.org/html/rfc7568</see_also>
        <plugin_output>TLSv1.0 is enabled on port 443 with CBC ciphers.</plugin_output>
      </ReportItem>
      <ReportItem port="3000" svc_name="http" protocol="tcp" pluginID="156014" pluginName="Log4j Remote Code Execution (Log4Shell)" pluginFamily="CGI abuses" severity="4">
        <description>Apache Log4j versions 2.0-beta9 through 2.15.0 are vulnerable to remote code execution via JNDI lookups.</description>
        <solution>Upgrade to Log4j 2.17.1 or newer.</solution>
        <cve>CVE-2021-44228</cve>
        <cwe>CWE-502</cwe>
        <cvss_base_score>10.0</cvss_base_score>
        <plugin_output>Detected JNDI lookup callback from header injection probe.</plugin_output>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;

export const SAMPLE_NUCLEI_JSONL = `{"template-id":"cve-2021-44228","info":{"name":"Apache Log4j RCE (Log4Shell)","author":["pdteam"],"severity":"critical","description":"Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.","reference":["https://logging.apache.org/log4j/2.x/security.html","https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],"classification":{"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cvss-score":10.0,"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"]},"remediation":"Upgrade Apache Log4j to version 2.17.1 or set log4j2.formatMsgNoLookups=true."},"type":"http","host":"http://127.0.0.1:3000","matched-at":"http://127.0.0.1:3000/api/v1/auth","extracted-results":["jndi:ldap://127.0.0.1:1389/a"],"timestamp":"2026-03-01T12:00:00.000Z"}
{"template-id":"git-config-exposure","info":{"name":"Git Config Exposure","author":["geeknik"],"severity":"medium","description":".git/config exposure leaks repository origin remote URLs and branch details.","classification":{"cwe-id":["CWE-200"],"cvss-score":5.3},"remediation":"Block access to .git directory in web server location rules."},"type":"http","host":"http://127.0.0.1:3000","matched-at":"http://127.0.0.1:3000/.git/config","extracted-results":["[remote \\"origin\\"]"],"timestamp":"2026-03-01T12:00:01.000Z"}`;
