/**
 * AWM Nexus — Security Tool Registry
 * Authoritative registry of professional authorized security-testing tools with real binary detection
 */

import { SecurityTool, ToolCategory, ToolProfile, ToolAvailabilityStatus, CapabilityTier } from '../types';

export const INITIAL_TOOL_REGISTRY: SecurityTool[] = [
  // --- RECONNAISSANCE ---
  {
    id: 'nmap-recon',
    name: 'Nmap Network Scanner',
    category: 'RECON',
    binaryName: 'nmap',
    description: 'Industry standard network mapper for port discovery, OS detection, and vulnerability probing.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'NON_DESTRUCTIVE_SCAN',
    documentationUrl: 'https://nmap.org/docs.html',
    installCommand: 'apt-get update && apt-get install -y nmap',
    installable: true,
    verificationCommand: 'nmap --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'fast-syn',
        name: 'Fast SYN Port Scan',
        description: 'Quick scan of top 100 common ports using TCP SYN.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: false,
        defaultFlags: ['-sT', '-F', '-T4', '--open'],
        allowedFlags: ['-F', '-T4', '-p', '-sT', '-sV', '--open', '-Pn'],
        forbiddenFlags: ['-oG', '-oN', '-oX', '--script=*exploit*', '--script=*dos*'],
        timeoutSeconds: 30
      },
      {
        id: 'service-version',
        name: 'Service & Version Detection',
        description: 'Comprehensive probe of top 1000 ports with banner grabbing and version fingerprints.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: false,
        defaultFlags: ['-sT', '-sV', '--version-intensity', '5', '-T3', '-Pn'],
        allowedFlags: ['-sT', '-sV', '--version-intensity', '-p', '-T3', '-T4', '-Pn'],
        forbiddenFlags: ['-oG', '-oN', '-oX', '--script=*exploit*'],
        timeoutSeconds: 60
      },
      {
        id: 'nse-vuln',
        name: 'NSE Vulnerability Audit',
        description: 'Vulnerability script engine audit for known CVEs on discovered open ports.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: true,
        hitlReason: 'NSE vulnerability scripts send active payload probes that may trigger alerts or service disruptions.',
        defaultFlags: ['-sV', '--script=vuln', '-T3', '-Pn'],
        allowedFlags: ['-sV', '--script=vuln', '--script=safe', '-p', '-Pn'],
        forbiddenFlags: ['--script=*dos*', '--script=*brute*'],
        timeoutSeconds: 120
      }
    ]
  },
  {
    id: 'amass-recon',
    name: 'OWASP Amass',
    category: 'RECON',
    binaryName: 'amass',
    description: 'In-depth attack surface mapping and external asset discovery utilizing open source information.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'RECON_READONLY',
    documentationUrl: 'https://github.com/owasp-amass/amass',
    installCommand: 'apt-get install -y amass || go install -v github.com/owasp-amass/amass/v4/...@master',
    installable: true,
    verificationCommand: 'amass version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'amass-passive',
        name: 'Passive DNS & Subdomain Enum',
        description: 'Non-intrusive passive reconnaissance against public registries and certificate logs.',
        capabilityTier: 'RECON_READONLY',
        requiresHITL: false,
        defaultFlags: ['enum', '-passive', '-d'],
        allowedFlags: ['enum', '-passive', '-d', '-timeout', '-src'],
        forbiddenFlags: ['-active', '-brute'],
        timeoutSeconds: 60
      },
      {
        id: 'amass-active',
        name: 'Active Reconnaissance & DNS Brute',
        description: 'Active DNS permutations and zone queries for thorough domain enumeration.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: true,
        hitlReason: 'Active DNS enumeration generates high-frequency requests across target authoritative nameservers.',
        defaultFlags: ['enum', '-active', '-d'],
        allowedFlags: ['enum', '-active', '-d', '-brute'],
        forbiddenFlags: [],
        timeoutSeconds: 90
      }
    ]
  },
  {
    id: 'subfinder-recon',
    name: 'Subfinder',
    category: 'RECON',
    binaryName: 'subfinder',
    description: 'Fast passive subdomain discovery tool designed to sift through massive amounts of passive sources.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'RECON_READONLY',
    documentationUrl: 'https://github.com/projectdiscovery/subfinder',
    installCommand: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    installable: true,
    verificationCommand: 'subfinder -version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'subfinder-default',
        name: 'Passive Subdomain Harvesting',
        description: 'Harvest subdomains from certificate transparency and passive telemetry.',
        capabilityTier: 'RECON_READONLY',
        requiresHITL: false,
        defaultFlags: ['-d', '-all', '-silent'],
        allowedFlags: ['-d', '-all', '-silent', '-t'],
        forbiddenFlags: [],
        timeoutSeconds: 45
      }
    ]
  },
  {
    id: 'dnsrecon-recon',
    name: 'DNSRecon',
    category: 'RECON',
    binaryName: 'dnsrecon',
    description: 'DNS enumeration and zone transfer reconnaissance tool.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'RECON_READONLY',
    documentationUrl: 'https://github.com/darkoperator/dnsrecon',
    installCommand: 'apt-get install -y dnsrecon || pip install dnsrecon',
    installable: true,
    verificationCommand: 'dnsrecon -v',
    isNativeBinary: true,
    profiles: [
      {
        id: 'dnsrecon-std',
        name: 'Standard Record & AXFR Check',
        description: 'Checks standard NS, SOA, MX, A, AAAA, TXT records and attempts DNS Zone Transfer (AXFR).',
        capabilityTier: 'RECON_READONLY',
        requiresHITL: false,
        defaultFlags: ['-d', '-t', 'std'],
        allowedFlags: ['-d', '-t', 'std', 'axfr', 'srv'],
        forbiddenFlags: ['-t', 'brt'],
        timeoutSeconds: 30
      }
    ]
  },

  // --- WEB ENUMERATION ---
  {
    id: 'ffuf-web',
    name: 'ffuf (Fast Web Fuzzer)',
    category: 'WEB_ENUM',
    binaryName: 'ffuf',
    description: 'High-performance web fuzzing utility written in Go for discovering directories, parameters, and virtual hosts.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'ACTIVE_PROBE',
    documentationUrl: 'https://github.com/ffuf/ffuf',
    installCommand: 'go install github.com/ffuf/ffuf/v2@latest',
    installable: true,
    verificationCommand: 'ffuf -V',
    isNativeBinary: true,
    profiles: [
      {
        id: 'ffuf-dirs',
        name: 'Targeted Endpoint Discovery',
        description: 'Rate-limited directory and API endpoint discovery using standard wordlists.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: false,
        defaultFlags: ['-rate', '50', '-mc', '200,204,301,302,307,401,403', '-timeout', '5'],
        allowedFlags: ['-rate', '-mc', '-timeout', '-H', '-recursion'],
        forbiddenFlags: ['-rate', '10000'],
        timeoutSeconds: 45
      },
      {
        id: 'ffuf-aggressive',
        name: 'Deep Recursive Parameter Fuzzing',
        description: 'Deep parameter and hidden field discovery across sensitive endpoints.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: true,
        hitlReason: 'High query density may trigger rate limiting or server load on target web service.',
        defaultFlags: ['-rate', '150', '-recursion', '-recursion-depth', '2'],
        allowedFlags: ['-rate', '-recursion', '-recursion-depth', '-mc', '-H'],
        forbiddenFlags: [],
        timeoutSeconds: 90
      }
    ]
  },
  {
    id: 'gobuster-web',
    name: 'Gobuster',
    category: 'WEB_ENUM',
    binaryName: 'gobuster',
    description: 'URI, DNS subdomain, and vhost brute-forcing tool written in Go.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'ACTIVE_PROBE',
    documentationUrl: 'https://github.com/OJ/gobuster',
    installCommand: 'go install github.com/OJ/gobuster/v3@latest',
    installable: true,
    verificationCommand: 'gobuster version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'gobuster-dir',
        name: 'Web Directory & File Enumeration',
        description: 'Enumerates web paths, config files, and hidden endpoints.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: false,
        defaultFlags: ['dir', '-t', '20', '-k', '-e'],
        allowedFlags: ['dir', '-t', '-k', '-e', '-x', '-s'],
        forbiddenFlags: ['-t', '500'],
        timeoutSeconds: 60
      }
    ]
  },
  {
    id: 'feroxbuster-web',
    name: 'Feroxbuster',
    category: 'WEB_ENUM',
    binaryName: 'feroxbuster',
    description: 'Fast, simple, recursive content discovery tool written in Rust.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'ACTIVE_PROBE',
    documentationUrl: 'https://github.com/epi052/feroxbuster',
    installCommand: 'cargo install feroxbuster || apt-get install -y feroxbuster',
    installable: true,
    verificationCommand: 'feroxbuster --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'ferox-safe',
        name: 'Controlled Content Discovery',
        description: 'Recursive directory scanner with auto-tuning response filters.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: false,
        defaultFlags: ['--rate-limit', '30', '--depth', '2', '--silent'],
        allowedFlags: ['--rate-limit', '--depth', '--silent', '-x', '-H'],
        forbiddenFlags: [],
        timeoutSeconds: 60
      }
    ]
  },
  {
    id: 'whatweb-web',
    name: 'WhatWeb',
    category: 'WEB_ENUM',
    binaryName: 'whatweb',
    description: 'Web scanner identifying technologies, CMSs, blogging platforms, JavaScript libraries, and web servers.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'RECON_READONLY',
    documentationUrl: 'https://github.com/urbanadventurer/WhatWeb',
    installCommand: 'apt-get install -y whatweb',
    installable: true,
    verificationCommand: 'whatweb --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'whatweb-stealth',
        name: 'Stealth Tech Fingerprinting',
        description: 'Passive header and HTML pattern identification of web frameworks.',
        capabilityTier: 'RECON_READONLY',
        requiresHITL: false,
        defaultFlags: ['-a', '1', '--color=never'],
        allowedFlags: ['-a', '1', '2', '--color=never', '-U'],
        forbiddenFlags: ['-a', '3', '-a', '4'],
        timeoutSeconds: 30
      }
    ]
  },

  // --- WEB / API INSPECTION ---
  {
    id: 'curl-probe',
    name: 'cURL Network & HTTP Client',
    category: 'WEB_API',
    binaryName: 'curl',
    description: 'Universal command line tool for transferring data with URLs, supporting HTTP/HTTPS/TLS probing and header analysis.',
    availabilityStatus: 'INSTALLED', // Checked during boot
    capabilityTier: 'RECON_READONLY',
    documentationUrl: 'https://curl.se/docs/',
    installCommand: 'apt-get install -y curl',
    installable: true,
    verificationCommand: 'curl --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'http-header-audit',
        name: 'Security Headers & TLS Inspection',
        description: 'Inspects HTTP response headers (CSP, HSTS, X-Frame-Options, CORS, server banners).',
        capabilityTier: 'RECON_READONLY',
        requiresHITL: false,
        defaultFlags: ['-I', '-sS', '-L', '--max-time', '10', '-k'],
        allowedFlags: ['-I', '-i', '-sS', '-L', '--max-time', '-k', '-H', '-A'],
        forbiddenFlags: ['--upload-file', '-T', '-d', '--data-binary'],
        timeoutSeconds: 15
      },
      {
        id: 'api-endpoint-probe',
        name: 'API Endpoint Verification & Response Capture',
        description: 'Queries API endpoint with specific headers and inspects response structure and auth behavior.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: false,
        defaultFlags: ['-sS', '-i', '--max-time', '15', '-H', 'Accept: application/json'],
        allowedFlags: ['-sS', '-i', '--max-time', '-H', '-X', 'GET', 'POST', 'OPTIONS', 'HEAD'],
        forbiddenFlags: ['--upload-file'],
        timeoutSeconds: 20
      }
    ]
  },
  {
    id: 'zap-web',
    name: 'OWASP ZAP (Zed Attack Proxy)',
    category: 'WEB_API',
    binaryName: 'zap-cli',
    description: 'Open source web application security scanner for identifying vulnerabilities in web applications and APIs.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'ACTIVE_PROBE',
    documentationUrl: 'https://www.zaproxy.org/docs/',
    installCommand: 'pip install --upgrade zapcli',
    installable: true,
    verificationCommand: 'zap-cli --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'zap-baseline',
        name: 'Passive Baseline Security Scan',
        description: 'Spider target application and perform passive rule analysis without altering data.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: false,
        defaultFlags: ['quick-scan', '--spider', '-r'],
        allowedFlags: ['quick-scan', '--spider', '-r', '-l', 'Low'],
        forbiddenFlags: ['--scanners', 'all-active'],
        timeoutSeconds: 90
      },
      {
        id: 'zap-active',
        name: 'Full Active Application Scan',
        description: 'Comprehensive active scan against SQLi, XSS, CSRF, and injection flaws.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: true,
        hitlReason: 'ZAP active scanning injects payloads into input parameters which may mutate test data.',
        defaultFlags: ['active-scan', '--recursive'],
        allowedFlags: ['active-scan', '--recursive', '-l', 'High'],
        forbiddenFlags: [],
        timeoutSeconds: 180
      }
    ]
  },
  {
    id: 'nikto-web',
    name: 'Nikto Web Server Scanner',
    category: 'WEB_API',
    binaryName: 'nikto',
    description: 'Web server scanner testing for dangerous files, outdated server software, and configuration errors.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'ACTIVE_PROBE',
    documentationUrl: 'https://cirt.net/Nikto2',
    installCommand: 'apt-get install -y nikto',
    installable: true,
    verificationCommand: 'nikto -Version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'nikto-std',
        name: 'Standard Web Server Misconfiguration Scan',
        description: 'Tests web server for 6700+ potentially dangerous files/programs and server configs.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: false,
        defaultFlags: ['-h', '-Tuning', '1,2,3,4,8,9', '-timeout', '10'],
        allowedFlags: ['-h', '-Tuning', '-timeout', '-ssl', '-port'],
        forbiddenFlags: ['-mutate'],
        timeoutSeconds: 90
      }
    ]
  },
  {
    id: 'burp-api',
    name: 'Burp Suite REST API',
    category: 'WEB_API',
    binaryName: 'burpsuite',
    description: 'Enterprise grade web vulnerability scanner interface for authenticated security testing.',
    availabilityStatus: 'NOT_CONFIGURED',
    capabilityTier: 'ACTIVE_PROBE',
    documentationUrl: 'https://portswigger.net/burp/documentation',
    installCommand: 'echo "Configure Burp Suite Enterprise / REST API endpoint in settings"',
    installable: false,
    verificationCommand: 'curl -s http://127.0.0.1:1337/v0.1/version',
    isNativeBinary: false,
    profiles: [
      {
        id: 'burp-audit',
        name: 'Burp Crawl & Audit',
        description: 'Automated crawl and vulnerability audit of target web application.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: true,
        hitlReason: 'Burp Audit executes automated injection tests across all discovered endpoints.',
        defaultFlags: ['--config=audit_default'],
        allowedFlags: ['--config'],
        forbiddenFlags: [],
        timeoutSeconds: 180
      }
    ]
  },

  // --- VULNERABILITY SCANNERS ---
  {
    id: 'nuclei-vuln',
    name: 'Nuclei Template Vulnerability Scanner',
    category: 'VULNERABILITY',
    binaryName: 'nuclei',
    description: 'Fast and customizable vulnerability scanner based on community-curated YAML templates.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'ACTIVE_PROBE',
    documentationUrl: 'https://github.com/projectdiscovery/nuclei',
    installCommand: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    installable: true,
    verificationCommand: 'nuclei -version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'nuclei-critical-cve',
        name: 'Critical & High CVEs Audit',
        description: 'Runs verified templates against target for critical and high severity known CVEs.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: true,
        hitlReason: 'Critical CVE templates verify real exploit paths against web services.',
        defaultFlags: ['-s', 'critical,high', '-nc', '-silent', '-stats'],
        allowedFlags: ['-s', 'critical,high,medium,low', '-nc', '-silent', '-stats', '-t', '-tags'],
        forbiddenFlags: ['-t', 'fuzzing/', '-code'],
        timeoutSeconds: 90
      },
      {
        id: 'nuclei-misconfig',
        name: 'Exposures & Misconfigurations',
        description: 'Scans for exposed panels, leaked config files, default credentials, and security misconfigurations.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: false,
        defaultFlags: ['-tags', 'exposure,misconfig,panel', '-nc', '-silent'],
        allowedFlags: ['-tags', '-nc', '-silent', '-rate-limit'],
        forbiddenFlags: [],
        timeoutSeconds: 60
      }
    ]
  },
  {
    id: 'openvas-vuln',
    name: 'OpenVAS / Greenbone Vulnerability Management',
    category: 'VULNERABILITY',
    binaryName: 'gvm-cli',
    description: 'Comprehensive network vulnerability scanner and vulnerability management solution.',
    availabilityStatus: 'NOT_CONFIGURED',
    capabilityTier: 'ACTIVE_PROBE',
    documentationUrl: 'https://greenbone.github.io/docs/',
    installCommand: 'apt-get install -y gvm',
    installable: true,
    verificationCommand: 'gvm-cli --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'openvas-full',
        name: 'Full and Fast Vulnerability Assessment',
        description: 'Comprehensive assessment of network assets against known security feeds.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: true,
        hitlReason: 'OpenVAS sends thousands of active vulnerability checks across all open ports.',
        defaultFlags: ['--scan-config', 'Full and fast'],
        allowedFlags: ['--scan-config'],
        forbiddenFlags: [],
        timeoutSeconds: 300
      }
    ]
  },

  // --- NETWORK PROBING ---
  {
    id: 'masscan-net',
    name: 'Masscan TCP Port Scanner',
    category: 'NETWORK',
    binaryName: 'masscan',
    description: 'Ultra high-speed TCP port scanner capable of scanning entire ranges in seconds.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'ACTIVE_PROBE',
    documentationUrl: 'https://github.com/robertdavidgraham/masscan',
    installCommand: 'apt-get install -y masscan',
    installable: true,
    verificationCommand: 'masscan --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'masscan-targeted',
        name: 'Controlled Rate Port Sweep',
        description: 'Sweeps top 1000 ports at a conservative 500 pkts/sec rate limit.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: true,
        hitlReason: 'Masscan transmits raw SYN packets at high frequency; rate must be explicitly authorized.',
        defaultFlags: ['-p1-1000', '--rate=500', '--wait=2'],
        allowedFlags: ['-p', '--rate', '--wait'],
        forbiddenFlags: ['--rate=100000'],
        timeoutSeconds: 45
      }
    ]
  },
  {
    id: 'tshark-net',
    name: 'TShark (Wireshark CLI)',
    category: 'NETWORK',
    binaryName: 'tshark',
    description: 'Network protocol analyzer for capturing and dissecting packet streams.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'RECON_READONLY',
    documentationUrl: 'https://www.wireshark.org/docs/man-pages/tshark.html',
    installCommand: 'apt-get install -y tshark',
    installable: true,
    verificationCommand: 'tshark --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'tshark-summary',
        name: 'Traffic Protocol Dissection',
        description: 'Passive capture and dissection of security handshake frames.',
        capabilityTier: 'RECON_READONLY',
        requiresHITL: false,
        defaultFlags: ['-c', '100', '-q', '-z', 'io,phs'],
        allowedFlags: ['-c', '-q', '-z', '-Y', '-f'],
        forbiddenFlags: [],
        timeoutSeconds: 30
      }
    ]
  },

  // --- DNS & TLS ---
  {
    id: 'dig-dns',
    name: 'Dig (Domain Information Groper)',
    category: 'DNS_TLS',
    binaryName: 'dig',
    description: 'Flexible DNS lookup utility for querying DNS name servers and testing record configurations.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'RECON_READONLY',
    documentationUrl: 'https://linux.die.net/man/1/dig',
    installCommand: 'apt-get install -y dnsutils',
    installable: true,
    verificationCommand: 'dig -v',
    isNativeBinary: true,
    profiles: [
      {
        id: 'dig-all-records',
        name: 'Comprehensive Record Enumeration',
        description: 'Queries ANY, A, AAAA, MX, NS, TXT, and SOA records with DNSSEC validation.',
        capabilityTier: 'RECON_READONLY',
        requiresHITL: false,
        defaultFlags: ['ANY', '+noall', '+answer', '+dnssec'],
        allowedFlags: ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'ANY', 'AXFR', '+noall', '+answer', '+dnssec'],
        forbiddenFlags: [],
        timeoutSeconds: 15
      },
      {
        id: 'dig-axfr',
        name: 'Zone Transfer Validation (AXFR)',
        description: 'Attempts DNS Zone Transfer against target authoritative name servers.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: false,
        defaultFlags: ['AXFR'],
        allowedFlags: ['AXFR', '+short', '+time=3'],
        forbiddenFlags: [],
        timeoutSeconds: 20
      }
    ]
  },
  {
    id: 'openssl-tls',
    name: 'OpenSSL TLS/SSL Inspector',
    category: 'DNS_TLS',
    binaryName: 'openssl',
    description: 'Cryptographic toolkit for testing SSL/TLS ciphers, certificate validation, and protocol downgrade risks.',
    availabilityStatus: 'INSTALLED',
    capabilityTier: 'RECON_READONLY',
    documentationUrl: 'https://www.openssl.org/docs/',
    installCommand: 'apt-get install -y openssl',
    installable: true,
    verificationCommand: 'openssl version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'openssl-cert-check',
        name: 'TLS Handshake & Certificate Verification',
        description: 'Performs TLS handshake, validates chain of trust, expiry dates, and SAN extensions.',
        capabilityTier: 'RECON_READONLY',
        requiresHITL: false,
        defaultFlags: ['s_client', '-connect', '-brief'],
        allowedFlags: ['s_client', '-connect', '-brief', '-servername', '-tls1_2', '-tls1_3', '-cipher'],
        forbiddenFlags: ['-key', '-sign', '-cafile=/etc/shadow'],
        timeoutSeconds: 15
      },
      {
        id: 'openssl-weak-ciphers',
        name: 'Legacy Protocol & Weak Cipher Audit',
        description: 'Checks whether legacy SSLv3, TLS 1.0, or weak RC4/DES ciphers are accepted.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: false,
        defaultFlags: ['s_client', '-tls1', '-connect'],
        allowedFlags: ['s_client', '-tls1', '-tls1_1', '-connect', '-cipher'],
        forbiddenFlags: [],
        timeoutSeconds: 20
      }
    ]
  },
  {
    id: 'testssl-tls',
    name: 'testssl.sh',
    category: 'DNS_TLS',
    binaryName: 'testssl',
    description: 'Command line tool which checks a server\'s service on any port for the support of TLS/SSL ciphers and flaws.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'NON_DESTRUCTIVE_SCAN',
    documentationUrl: 'https://testssl.sh/',
    installCommand: 'git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl',
    installable: true,
    verificationCommand: 'testssl --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'testssl-vulns',
        name: 'TLS Vulnerability Assessment (Heartbleed, POODLE, ROBOT)',
        description: 'Tests target HTTPS endpoint for critical TLS/SSL implementation vulnerabilities.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: false,
        defaultFlags: ['-U', '--quiet', '--color', '0'],
        allowedFlags: ['-U', '--quiet', '--color', '-E', '-S', '-P'],
        forbiddenFlags: [],
        timeoutSeconds: 90
      }
    ]
  },

  // --- CLOUD SECURITY ---
  {
    id: 'aws-cli',
    name: 'AWS Security CLI',
    category: 'CLOUD',
    binaryName: 'aws',
    description: 'Official AWS Command Line Interface for cloud configuration auditing and IAM assessment.',
    availabilityStatus: 'NOT_CONFIGURED',
    capabilityTier: 'RECON_READONLY',
    documentationUrl: 'https://docs.aws.amazon.com/cli/',
    installCommand: 'apt-get install -y awscli',
    installable: true,
    verificationCommand: 'aws --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'aws-s3-audit',
        name: 'S3 Bucket Public Exposure Check',
        description: 'Inspects bucket ACLs and public access block configurations.',
        capabilityTier: 'RECON_READONLY',
        requiresHITL: false,
        defaultFlags: ['s3api', 'get-bucket-policy-status'],
        allowedFlags: ['s3api', 's3', 'get-bucket-policy-status', 'get-public-access-block', 'list-buckets'],
        forbiddenFlags: ['delete-bucket', 'put-bucket-policy', 'rm'],
        timeoutSeconds: 30
      }
    ]
  },
  {
    id: 'scoutsuite-cloud',
    name: 'ScoutSuite Multi-Cloud Auditor',
    category: 'CLOUD',
    binaryName: 'scout',
    description: 'Open source multi-cloud security auditing tool for AWS, Azure, GCP, and Kubernetes.',
    availabilityStatus: 'NOT_CONFIGURED',
    capabilityTier: 'RECON_READONLY',
    documentationUrl: 'https://github.com/nccgroup/ScoutSuite',
    installCommand: 'pip install scoutsuite',
    installable: true,
    verificationCommand: 'scout --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'scout-gcp',
        name: 'GCP Security Posture Review',
        description: 'Audits GCP IAM, Compute, Storage, and Kubernetes engine policies against CIS benchmarks.',
        capabilityTier: 'RECON_READONLY',
        requiresHITL: false,
        defaultFlags: ['gcp', '--no-browser'],
        allowedFlags: ['gcp', 'aws', 'azure', '--no-browser', '--services'],
        forbiddenFlags: [],
        timeoutSeconds: 120
      }
    ]
  },

  // --- KUBERNETES ---
  {
    id: 'kubectl-k8s',
    name: 'Kubectl Security Inspector',
    category: 'KUBERNETES',
    binaryName: 'kubectl',
    description: 'Kubernetes CLI for inspecting pod security policies, RBAC roles, and cluster service exposures.',
    availabilityStatus: 'NOT_CONFIGURED',
    capabilityTier: 'RECON_READONLY',
    documentationUrl: 'https://kubernetes.io/docs/reference/kubectl/',
    installCommand: 'curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && chmod +x kubectl && mv kubectl /usr/local/bin/',
    installable: true,
    verificationCommand: 'kubectl version --client',
    isNativeBinary: true,
    profiles: [
      {
        id: 'k8s-rbac-audit',
        name: 'RBAC Authorization & Can-I Audit',
        description: 'Inspects user/serviceaccount cluster permissions and privilege escalation vectors.',
        capabilityTier: 'RECON_READONLY',
        requiresHITL: false,
        defaultFlags: ['auth', 'can-i', '--list'],
        allowedFlags: ['auth', 'can-i', '--list', 'get', 'pods', 'services', 'nodes'],
        forbiddenFlags: ['delete', 'apply', 'edit', 'exec', 'attach'],
        timeoutSeconds: 30
      }
    ]
  },
  {
    id: 'kube-bench',
    name: 'Kube-Bench CIS Benchmark',
    category: 'KUBERNETES',
    binaryName: 'kube-bench',
    description: 'Checks whether Kubernetes is deployed securely by running the tests documented in the CIS Kubernetes Benchmark.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'NON_DESTRUCTIVE_SCAN',
    documentationUrl: 'https://github.com/aquasecurity/kube-bench',
    installCommand: 'apt-get install -y kube-bench',
    installable: true,
    verificationCommand: 'kube-bench version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'kube-bench-cis',
        name: 'Master & Node CIS Benchmark',
        description: 'Runs complete CIS benchmark automated validation tests.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: false,
        defaultFlags: ['run', '--targets', 'master,node'],
        allowedFlags: ['run', '--targets', '--json', '--outputfile'],
        forbiddenFlags: [],
        timeoutSeconds: 60
      }
    ]
  },

  // --- PASSWORD & HASH AUDITING ---
  {
    id: 'hashcat-audit',
    name: 'Hashcat Password Recovery & Audit',
    category: 'PASSWORD_HASH',
    binaryName: 'hashcat',
    description: 'World\'s fastest and most advanced password recovery and cryptographic entropy auditing utility.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'CONTROLLED_EXPLOIT',
    documentationUrl: 'https://hashcat.net/hashcat/',
    installCommand: 'apt-get install -y hashcat',
    installable: true,
    verificationCommand: 'hashcat --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'hashcat-entropy-benchmark',
        name: 'Controlled Entropy & Benchmark Probe',
        description: 'Calculates algorithm throughput and password policy entropy resistance.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: false,
        defaultFlags: ['-b', '-m', '1000'],
        allowedFlags: ['-b', '-m', '--speed-only'],
        forbiddenFlags: [],
        timeoutSeconds: 30
      },
      {
        id: 'hashcat-dictionary-audit',
        name: 'Authorized Policy Verification Dictionary Attack',
        description: 'Verifies hash storage resilience against standard dictionary words.',
        capabilityTier: 'CONTROLLED_EXPLOIT',
        requiresHITL: true,
        hitlReason: 'Password auditing involves computational hash testing on customer authentication artifacts.',
        defaultFlags: ['-m', '0', '-a', '0', '--potfile-disable'],
        allowedFlags: ['-m', '-a', '--potfile-disable', '-w'],
        forbiddenFlags: [],
        timeoutSeconds: 120
      }
    ]
  },
  {
    id: 'john-audit',
    name: 'John the Ripper',
    category: 'PASSWORD_HASH',
    binaryName: 'john',
    description: 'Fast password cracker and security audit tool for testing password strength.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'CONTROLLED_EXPLOIT',
    documentationUrl: 'https://www.openwall.com/john/',
    installCommand: 'apt-get install -y john',
    installable: true,
    verificationCommand: 'john --version',
    isNativeBinary: true,
    profiles: [
      {
        id: 'john-test',
        name: 'Cipher Suite & Digest Benchmark',
        description: 'Runs standard cryptographic hashing benchmarks.',
        capabilityTier: 'NON_DESTRUCTIVE_SCAN',
        requiresHITL: false,
        defaultFlags: ['--test=10'],
        allowedFlags: ['--test', '--format'],
        forbiddenFlags: [],
        timeoutSeconds: 20
      }
    ]
  },

  // --- CONTROLLED VALIDATION ---
  {
    id: 'msf-validation',
    name: 'Metasploit Framework',
    category: 'CONTROLLED_VAL',
    binaryName: 'msfconsole',
    description: 'Penetration testing framework for verifying exploitability, validating security controls, and assessing risk.',
    availabilityStatus: 'NOT_INSTALLED',
    capabilityTier: 'CONTROLLED_EXPLOIT',
    documentationUrl: 'https://www.metasploit.com/',
    installCommand: 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall',
    installable: true,
    verificationCommand: 'msfconsole -v',
    isNativeBinary: true,
    profiles: [
      {
        id: 'msf-aux-check',
        name: 'Auxiliary Vulnerability Verification Module',
        description: 'Runs controlled non-destructive auxiliary scanner module to verify vulnerability presence.',
        capabilityTier: 'ACTIVE_PROBE',
        requiresHITL: true,
        hitlReason: 'Metasploit auxiliary modules directly interact with vulnerable endpoints.',
        defaultFlags: ['-q', '-x', 'use auxiliary/scanner/http/http_version; run; exit'],
        allowedFlags: ['-q', '-x'],
        forbiddenFlags: ['exploit/*', 'payload/*'],
        timeoutSeconds: 60
      },
      {
        id: 'msf-exploit-validate',
        name: 'Controlled Exploitability Verification',
        description: 'Validates real exploitability of confirmed vulnerability in controlled sandbox scope.',
        capabilityTier: 'CONTROLLED_EXPLOIT',
        requiresHITL: true,
        hitlReason: 'CRITICAL: Controlled exploit execution actively tests payload execution. Requires explicit Authorization & HITL sign-off.',
        defaultFlags: ['-q'],
        allowedFlags: ['-q', '-x'],
        forbiddenFlags: [],
        timeoutSeconds: 120
      }
    ]
  }
];

class ToolRegistryManager {
  private tools: Map<string, SecurityTool> = new Map();
  private verifiedAt: string | null = null;

  constructor() {
    for (const tool of INITIAL_TOOL_REGISTRY) {
      this.tools.set(tool.id, { ...tool });
    }
  }

  public getAllTools(): SecurityTool[] {
    return Array.from(this.tools.values());
  }

  public getTool(id: string): SecurityTool | undefined {
    return this.tools.get(id);
  }

  public getToolByBinary(binaryName: string): SecurityTool | undefined {
    return Array.from(this.tools.values()).find(t => t.binaryName === binaryName);
  }

  public searchTools(query: string): SecurityTool[] {
    const q = query.toLowerCase().trim();
    if (!q) return this.getAllTools();
    return this.getAllTools().filter(t =>
      t.name.toLowerCase().includes(q) ||
      t.id.toLowerCase().includes(q) ||
      t.binaryName.toLowerCase().includes(q) ||
      t.category.toLowerCase().includes(q) ||
      t.description.toLowerCase().includes(q)
    );
  }

  public getToolsByCategory(category: ToolCategory): SecurityTool[] {
    return this.getAllTools().filter(t => t.category === category);
  }

  public updateToolStatus(id: string, status: ToolAvailabilityStatus, version?: string, detectedPath?: string): void {
    const tool = this.tools.get(id);
    if (tool) {
      tool.availabilityStatus = status;
      if (version) tool.version = version;
      if (detectedPath) tool.detectedPath = detectedPath;
      tool.lastChecked = new Date().toISOString();
    }
  }

  public setToolSimulationMode(id: string): void {
    const tool = this.tools.get(id);
    if (tool && tool.availabilityStatus === 'NOT_INSTALLED') {
      tool.availabilityStatus = 'SIMULATED';
      tool.lastChecked = new Date().toISOString();
    }
  }

  /**
   * Sanitizes and constructs an invocation argument list safely without shell injection
   */
  public buildInvocationArguments(
    tool: SecurityTool,
    profile: ToolProfile,
    target: string,
    customParams: string[] = []
  ): { safeArgs: string[]; isSafe: boolean; rejectionReason?: string } {
    // Check forbidden characters in target and parameters
    const dangerousPatterns = [';', '&', '|', '`', '$', '>', '<', '\n', '\r', '$(', '`'];
    
    for (const char of dangerousPatterns) {
      if (target.includes(char)) {
        return { safeArgs: [], isSafe: false, rejectionReason: `Target contains illegal shell meta-character: ${char}` };
      }
    }

    // Detect if customParams is already a pre-built arguments array (e.g. contains profile defaultFlags or target)
    const customJoined = customParams.join(' ');
    const defaultJoined = profile.defaultFlags.join(' ');
    const isAlreadyPrebuilt = (profile.defaultFlags.length > 0 && customJoined.startsWith(defaultJoined)) ||
      (profile.defaultFlags.length > 0 && customParams[0] === profile.defaultFlags[0]);

    const safeArgs: string[] = isAlreadyPrebuilt ? [] : [...profile.defaultFlags];

    for (const param of customParams) {
      if (typeof param !== 'string') continue;
      for (const char of dangerousPatterns) {
        if (param.includes(char)) {
          return { safeArgs: [], isSafe: false, rejectionReason: `Parameter contains forbidden shell meta-character: ${char}` };
        }
      }

      const trimmed = param.trim();
      if (!trimmed) continue;

      // Check forbidden flags
      for (const forbidden of profile.forbiddenFlags) {
        if (trimmed === forbidden || trimmed.startsWith(forbidden + '=') || (forbidden.endsWith('*') && trimmed.startsWith(forbidden.slice(0, -1)))) {
          return { safeArgs: [], isSafe: false, rejectionReason: `Flag '${trimmed}' is strictly forbidden for security profile '${profile.name}'` };
        }
      }

      safeArgs.push(trimmed);
    }

    // Check if target is already included at the end of safeArgs
    const targetAlreadyPresent = safeArgs.length > 0 && (
      safeArgs[safeArgs.length - 1] === target ||
      safeArgs[safeArgs.length - 1] === `http://${target}` ||
      safeArgs[safeArgs.length - 1] === `https://${target}` ||
      safeArgs[safeArgs.length - 1] === `${target}:443`
    );

    if (!targetAlreadyPresent) {
      // Append target safely depending on tool
      if (tool.binaryName === 'curl') {
        let formattedTarget = target;
        if (!formattedTarget.startsWith('http://') && !formattedTarget.startsWith('https://')) {
          formattedTarget = `http://${formattedTarget}`;
        }
        safeArgs.push(formattedTarget);
      } else if (tool.binaryName === 'openssl') {
        if (!safeArgs.includes('-connect')) {
          safeArgs.push('-connect');
        }
        const connStr = target.includes(':') ? target : `${target}:443`;
        safeArgs.push(connStr);
      } else {
        safeArgs.push(target);
      }
    }

    return { safeArgs, isSafe: true };
  }
}

export const toolRegistry = new ToolRegistryManager();
