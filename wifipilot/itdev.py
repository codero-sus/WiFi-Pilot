# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""The devices an assessment meets, and the three editions of wifipilot.

Three axes, kept separate because they answer three different questions:

``domain`` — the *edition*: ``wifi`` (the air and the frames on it), ``bluetooth`` (the
host controller and the profiles above it), ``it`` (the network, the services and the
devices on the far side of the bridge), or ``all``.

``devices`` — the *type of thing* being tested: a router, a camera, a printer, a PLC, a
BLE beacon.  A type carries the ports it usually exposes, the protocols it speaks, the
vendors that build it and the attacks that make sense against it, so it is a filter, a
plan and a report heading at once.

``category``/``noise``/``impact`` — *how* an attack behaves; that lives in
:mod:`wifipilot.attacks.meta` and is untouched by any of this.

Everything here is *typical*, never *certain*: a port is a hint and a banner is a claim,
which is what :func:`classification_note` exists to say.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

__all__ = ["DOMAINS", "DOMAIN_LABELS", "domain_label", "DeviceType", "DEVICE_TYPES",
           "device_type", "device_type_label", "device_catalog", "device_ids",
           "types_for_port", "types_for_domain", "classify", "classification_note",
           "edition_catalog", "ports_of", "SUGGESTED_ATTACKS", "DEVICE_GROUPS",
           "suggested_attacks", "roadmap_attacks", "SYNONYM_PROTOCOLS"]

#: edition id -> label/description.  Order is the order the UI offers them.
DOMAINS: List[Dict[str, str]] = [
    {"id": "wifi", "label": "Wi-Fi", "short": "802.11 air",
     "description": "the radio and everything on it: capture, injection, rogue "
                    "infrastructure, deauthentication, WPS and WEP"},
    {"id": "bluetooth", "label": "Bluetooth", "short": "BR/EDR and BLE",
     "description": "the host controller and the profiles above it: BlueBorne, BIAS, "
                    "KNOB, GATT, RFCOMM, OBEX and HID"},
    {"id": "it", "label": "IT / IoT", "short": "services and devices",
     "description": "the network behind the bridge: discovery, credentials, protocol "
                    "abuse, cameras, printers, building systems, industrial control "
                    "and servers"},
    {"id": "all", "label": "Everything", "short": "all three editions",
     "description": "plan across the air, the radios and the network in one run"},
]

DOMAIN_LABELS: Dict[str, str] = {entry["id"]: entry["label"] for entry in DOMAINS}
DOMAIN_LABELS["all"] = "Everything"

#: device groups, in the order the UI lists them
DEVICE_GROUPS: List[Dict[str, str]] = [
    {"id": "network", "label": "Network infrastructure"},
    {"id": "server", "label": "Servers and storage"},
    {"id": "iot", "label": "IoT and embedded"},
    {"id": "ot", "label": "Industrial and building systems"},
    {"id": "voip", "label": "Telephony and conferencing"},
    {"id": "consumer", "label": "Consumer and smart home"},
    {"id": "mobile", "label": "Phones, tablets and wearables"},
    {"id": "bt", "label": "Bluetooth devices"},
]


def domain_label(domain: str) -> str:
    return DOMAIN_LABELS.get(domain, domain or "Wi-Fi")


@dataclass(frozen=True)
class DeviceType:
    """One class of device: how to spot it, and what to do once it is spotted."""

    id: str
    label: str
    group: str = "iot"
    domain: str = "it"
    description: str = ""
    ports: Tuple[int, ...] = ()
    protocols: Tuple[str, ...] = ()
    vendors: Tuple[str, ...] = ()
    attacks: Tuple[str, ...] = ()
    tells: Tuple[str, ...] = ()
    risk: str = ""

    @property
    def search_terms(self) -> Tuple[str, ...]:
        return (self.id, self.label.lower()) + tuple(v.lower() for v in self.vendors)

    @property
    def group_label(self) -> str:
        """The human name of this device's group, for the UI's headings and reports."""
        for entry in DEVICE_GROUPS:
            if entry.get("id") == self.group:
                return str(entry.get("label", self.group))
        return self.group

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "label": self.label, "group": self.group,
                "group_label": self.group_label,
                "domain": self.domain, "description": self.description,
                "ports": list(self.ports), "protocols": list(self.protocols),
                "vendors": list(self.vendors), "attacks": list(self.attacks),
                "tells": list(self.tells), "risk": self.risk}


def D(dev_id: str, label: str, group: str, ports: Sequence[int],
      protocols: Sequence[str], vendors: Sequence[str], attacks: Sequence[str],
      description: str = "", tells: Sequence[str] = (), risk: str = "",
      domain: str = "it") -> DeviceType:
    """Shorthand for the table below: one device type per row, readable at a glance."""
    return DeviceType(id=dev_id, label=label, group=group, domain=domain, ports=tuple(ports),
                      protocols=tuple(protocols), vendors=tuple(vendors),
                      attacks=tuple(attacks), description=description,
                      tells=tuple(tells), risk=risk)


#: every device class the catalogue knows.  Rows are deliberately compact: ports and
#: protocols are what the fingerprint uses, ``attacks`` is what the planner proposes.
DEVICE_TYPES: List[DeviceType] = [
    # -- network infrastructure --------------------------------------------- #
    D("router", "Router / residential gateway", "network",
      (53, 80, 443, 1900, 5353, 7547, 8080),
      ("mdns", "ssdp", "upnp", "http", "tr069", "dns"),
      ("TP-Link", "Netgear", "D-Link", "Asus", "MikroTik", "Huawei", "Zyxel"),
      ("discover", "default_creds", "auth_bypass", "config_dump", "unauth_write", "flood"),
      "the device that is the network: DHCP, DNS, NAT and a web UI nobody changed",
      ("answers SSDP as InternetGatewayDevice", "hostname ends .router"),
      "default credentials on the gateway are the whole network"),
    D("firewall", "Firewall / UTM appliance", "network", (443, 4443, 500, 4500, 8443),
      ("tls", "http", "ssh"), ("Fortinet", "Sophos", "Palo Alto", "Check Point", "pfSense"),
      ("version_audit", "default_creds", "tls_audit", "discover"),
      "the perimeter: a management UI with advisory history",
      ("TLS certificate names the model",),
      "an unpatched management interface is a perimeter finding"),
    D("switch", "Managed switch", "network", (22, 23, 80, 161, 443),
      ("snmp", "telnet", "ssh", "lldp", "http"),
      ("Cisco", "HP", "Aruba", "Juniper", "Ubiquiti"),
      ("discover", "snmp_communities", "default_creds", "config_dump"),
      "layer 2 with a management address and a community string",
      ("LLDP advertises a switch model",), "SNMP read is a map; SNMP write is the network"),
    D("access_point", "Access point", "network", (22, 80, 443, 161, 8080),
      ("http", "ssh", "snmp", "mdns"), ("Ubiquiti", "Aruba", "Cisco Meraki", "Ruckus"),
      ("default_creds", "version_audit", "discover"),
      "the radio itself, and a management UI on the bridged side",
      ("mDNS name contains unifi or omada",),
      "the AP is the bridge: its UI is on the operational LAN"),
    D("vpn_gateway", "VPN concentrator", "network", (443, 500, 4500, 10443),
      ("ike", "tls", "http"), ("Cisco", "Fortinet", "Pulse", "SonicWall", "OpenVPN"),
      ("version_audit", "tls_audit", "discover"),
      "remote access: IKE on 500/4500 and an SSL VPN on 443",
      ("IKE answers with a vendor ID payload",),
      "remote access appliances are the classic way in from outside"),
    D("modem_ont", "Modem / ONT", "network", (80, 443, 7547),
      ("tr069", "http", "dns"), ("Calix", "Nokia", "Huawei", "ZTE", "Sagemcom"),
      ("tr069_probe", "default_creds", "config_dump"),
      "the ISP's box: TR-069 management and the site's DNS",
      ("CWMP Inform sent to an ACS address",),
      "TR-069 carries ISP credentials and often no mutual TLS"),
    D("load_balancer", "Load balancer / reverse proxy", "network", (80, 443, 8080),
      ("http", "tls"), ("F5", "HAProxy", "nginx", "Citrix", "AWS"),
      ("discover", "version_audit", "tls_audit", "config_dump"),
      "the front door: certificates, headers and the routing table behind it",
      ("Server header plus a health endpoint",), "the proxy holds every backend's URL"),
    D("wireless_controller", "Wireless LAN controller", "network", (22, 80, 443, 161),
      ("http", "ssh", "snmp"), ("Cisco", "Aruba", "Extreme", "Ruckus"),
      ("default_creds", "version_audit", "config_dump"),
      "the box that owns every AP and every PSK on site",
      ("a controller login page listing AP counts",),
      "controller compromise is a site-wide credential change"),
    # -- cameras, recorders, access control --------------------------------- #
    D("ip_camera", "IP camera", "iot", (80, 443, 554, 8000, 8080, 8554),
      ("rtsp", "onvif", "http", "mdns"),
      ("Hikvision", "Dahua", "Axis", "Reolink", "Amcrest", "Foscam", "Wyze"),
      ("discover", "rtsp_anonymous", "default_creds", "version_audit", "config_dump"),
      "RTSP with an ONVIF profile and a stream that may need no password",
      ("RTSP DESCRIBE answers without a 401", "ONVIF names the model"),
      "an open stream is live video of the site to anyone on the LAN"),
    D("nvr_dvr", "NVR / DVR", "iot", (80, 443, 554, 8000, 8080, 34567),
      ("rtsp", "onvif", "http"), ("Hikvision", "Dahua", "Uniview", "Swann", "Lorex"),
      ("default_creds", "version_audit", "rtsp_anonymous", "config_dump"),
      "the recorder behind the cameras: every stream, one shared password",
      ("channel list matches the camera count",),
      "one credential away from every recording the site holds"),
    D("doorbell", "Video doorbell / intercom", "iot", (80, 443, 5060, 8000),
      ("http", "sip", "onvif", "mdns"), ("Ring", "Hikvision", "Akuvox", "2N", "Doorbird"),
      ("discover", "default_creds", "sip_enum"),
      "a camera at the door with a SIP or vendor backend",
      ("SIP OPTIONS answered by a door station",),
      "an intercom is a door opener and a microphone in one box"),
    D("badge_reader", "Access control reader", "iot", (80, 443, 4070),
      ("http", "osdp", "serial"), ("HID", "Suprema", "ZKTeco", "Lenel", "Honeywell"),
      ("default_creds", "config_dump", "discover"),
      "card and biometric readers on a controller that has a web UI",
      ("controller page lists doors and readers",),
      "access control that opens from the LAN is not access control"),
    D("alarm_panel", "Alarm / intrusion panel", "iot", (80, 443, 5000, 3060),
      ("http", "proprietary"), ("DSC", "Honeywell", "Bosch", "Texecom", "Paradox"),
      ("discover", "default_creds", "config_dump"),
      "the panel that decides whether the site is armed",
      ("vendor portal page with a zone list",),
      "a panel that can be disarmed over the network is the site's security"),
    D("gateway_hub", "Smart home hub / bridge", "iot", (80, 443, 6667, 8080),
      ("http", "mdns", "zigbee_gateway"), ("SmartThings", "Hubitat", "Home Assistant"),
      ("discover", "default_creds", "config_dump"),
      "the bridge between the site's radios and its cloud account",
      ("mDNS advertises a hub service",),
      "the hub's API speaks for every device it paired"),
    D("sensor", "Wireless sensor / detector", "iot", (80, 161, 5353),
      ("mdns", "snmp", "http"), ("Aqara", "Shelly", "Xiaomi", "Sonoff"),
      ("discover", "snmp_communities", "config_dump"),
      "a small radio that reports one number and announces itself over mDNS",
      ("mDNS TXT record carries a model",),
      "sensors leak occupancy and are rarely updatable"),
]


DEVICE_TYPES += [
    # -- printers and imaging ----------------------------------------------- #
    D("printer", "Network printer", "iot", (80, 161, 443, 515, 631, 9100),
      ("pjl", "ipp", "snmp", "http", "telnet"),
      ("HP", "Canon", "Epson", "Brother", "Kyocera", "Ricoh", "Xerox"),
      ("discover", "pjl_command", "ipp_anonymous", "snmp_communities", "config_dump"),
      "PJL on 9100, IPP on 631 and a job history that holds what the office printed",
      ("PJL INFO ID answers with a model string",),
      "a printer is a computer with a document archive attached"),
    D("mfp_scanner", "MFP / scanner", "iot", (80, 139, 443, 445, 631, 9100),
      ("pjl", "ipp", "smb", "http"), ("Xerox", "Ricoh", "Konica Minolta", "Sharp"),
      ("config_dump", "smb_null_session", "default_creds", "discover"),
      "printer plus scanner, with an address book and stored documents",
      ("address book exposed through the web UI",),
      "the address book is who works here and where they mail things"),
    D("label_printer", "Label / receipt printer", "iot", (80, 443, 9100),
      ("pjl", "ipp", "http"), ("Zebra", "Epson", "Star", "Bixolon", "SATO"),
      ("discover", "pjl_command", "default_creds"),
      "a retail or logistics printer with a raw port open",
      ("ZPL or ESC/POS answers on 9100",), "shipping labels are a supply-chain leak"),
    # -- storage and servers ------------------------------------------------ #
    D("nas", "NAS / file share", "server", (22, 111, 139, 443, 445, 2049, 5000, 873),
      ("smb", "nfs", "rsync", "ssh", "http", "http_json"),
      ("Synology", "QNAP", "TrueNAS", "Buffalo", "Western Digital"),
      ("discover", "smb_null_session", "nfs_exports", "rsync_list", "default_creds",
       "version_audit"),
      "SMB, NFS and rsync in front of the site's files",
      ("SMB shares a volume name", "NFS EXPORT lists /volume1"),
      "one anonymous mount and the assessment has the file shares"),
    D("backup_appliance", "Backup appliance", "server", (22, 443, 3260, 8000),
      ("http", "ssh", "iscsi"), ("Veeam", "Rubrik", "Dell EMC", "Unitrends"),
      ("default_creds", "version_audit", "discover"),
      "the copy of everything, reachable from the network it protects",
      ("web UI titles itself a backup product",),
      "the backup server is the last line of defence and a first-class target"),
    D("hypervisor_host", "Virtualisation host", "server", (22, 443, 5988, 8006),
      ("http", "ssh", "cim"), ("VMware", "Proxmox", "Citrix", "Microsoft"),
      ("version_audit", "default_creds", "config_dump", "discover"),
      "ESXi or Proxmox: a management UI that owns the guests",
      ("443 answers with a hypervisor login page",),
      "one credential on the hypervisor is every guest on it"),
    D("linux_server", "Linux server", "server", (22, 80, 443, 3306, 5432, 6379),
      ("ssh", "http", "redis", "mysql", "postgres", "tls"),
      ("Canonical", "Red Hat", "Debian", "SUSE"),
      ("discover", "version_audit", "tls_audit", "cleartext_audit", "default_creds"),
      "the workhorse: SSH, a web stack, a database and an old forgotten service",
      ("SSH banner names the distribution",),
      "known-version services are a patch-management finding with CVE numbers"),
    D("windows_server", "Windows server", "server", (135, 139, 445, 3389, 5985),
      ("smb", "rdp", "netbios", "winrm"), ("Microsoft", "Dell", "HPE", "Lenovo"),
      ("discover", "smb_null_session", "rdp_probe", "netbios_enum", "version_audit"),
      "SMB, RDP and NetBIOS with signing deciding how much needs a password",
      ("SMB2 negotiate answers with a dialect list",),
      "SMB without signing is a relay target; a null session is an inventory"),
    D("domain_controller", "Domain controller / identity server", "server",
      (53, 88, 389, 445, 636, 3268), ("ldap", "kerberos", "dns", "smb"),
      ("Microsoft", "Samba", "Red Hat", "FreeIPA"),
      ("discover", "ldap_anonymous", "smb_null_session", "dns_audit"),
      "LDAP, Kerberos, DNS and SMB on one box, and the directory behind them",
      ("LDAP rootDSE answers without credentials",),
      "an anonymous LDAP bind lists every user and group in the company"),
    D("mail_server", "Mail server", "server", (25, 110, 143, 443, 465, 587, 993),
      ("smtp", "imap", "http", "tls"), ("Postfix", "Exchange", "Zimbra", "Mailcow"),
      ("discover", "version_audit", "tls_audit", "cleartext_audit"),
      "SMTP, IMAP and a webmail front end",
      ("SMTP banner names the MTA and version",),
      "an open relay gets the site blacklisted; a mailbox is a password reset"),
    D("database_server", "Database server", "server", (1433, 3306, 5432, 6379, 9200,
      27017), ("mysql", "postgres", "redis", "mongodb", "elastic", "mssql"),
      ("Oracle", "MongoDB", "Redis", "Elastic", "PostgreSQL"),
      ("discover", "unauth_read", "version_audit", "config_dump", "default_creds"),
      "the data, each engine with its own idea of whether auth is required",
      ("Redis answers PING without AUTH", "Elasticsearch reports a version"),
      "a database that answers before authentication is the whole dataset"),
    D("container_host", "Container host / orchestrator", "server",
      (2375, 2376, 5000, 6443, 8080, 10250), ("docker", "kubernetes", "http", "registry"),
      ("Docker", "Kubernetes", "Rancher", "Harbor"),
      ("discover", "docker_api", "k8s_api", "version_audit"),
      "the Docker socket behind an API, or a Kubernetes API server",
      ("GET /version answers with an ApiVersion",),
      "an unauthenticated container API is remote code execution by design"),
    D("web_server", "Web / application server", "server", (80, 443, 8080, 8443),
      ("http", "http_json", "tls"), ("nginx", "Apache", "IIS", "Tomcat", "Jenkins"),
      ("discover", "version_audit", "tls_audit", "config_dump", "auth_bypass"),
      "the site itself: default pages, admin paths, version banners",
      ("Server header and default page title",),
      "a version banner is a CVE list; a missing HSTS is a downgrade"),
    D("ci_server", "CI / build server", "server", (80, 443, 8080, 8443),
      ("http_json", "http", "tls"), ("Jenkins", "GitLab", "Atlassian", "JetBrains"),
      ("jenkins_audit", "discover", "version_audit", "config_dump"),
      "Jenkins or GitLab CI: build logs with secrets and a script console",
      ("/api/json answers without authentication",),
      "a CI server holds the deployment credentials it deploys with"),
    D("voip_phone", "VoIP desk phone", "voip", (80, 443, 5060, 5061),
      ("sip", "http", "tftp", "mdns"),
      ("Yealink", "Polycom", "Snom", "Grandstream", "Cisco", "Avaya"),
      ("sip_enum", "discover", "default_creds", "cleartext_audit"),
      "SIP in the clear and provisioning with the extension password in it",
      ("mDNS name ends .phone",), "an extension password is a phone bill and a listen-in"),
    D("pbx", "PBX / SIP server", "voip", (80, 443, 5038, 5060, 8088),
      ("sip", "http", "ami"), ("Asterisk", "FreePBX", "3CX", "Cisco", "Avaya"),
      ("sip_enum", "version_audit", "default_creds", "sip_flood"),
      "Asterisk or a hosted trunk: registration brute force and toll fraud",
      ("SIP 401 with a realm of the host name",),
      "the PBX is a way to spend the client's money by the minute"),
    D("video_conference", "Conference room system", "voip", (80, 443, 5060, 8080),
      ("http", "sip", "onvif"), ("Cisco", "Poly", "Logitech", "Crestron"),
      ("discover", "default_creds", "sip_enum"),
      "a codec with a camera, a microphone and an API that dials anywhere",
      ("web UI names a room system model",),
      "a room system is a live microphone on the site's network"),
]


DEVICE_TYPES += [
    # -- industrial and building systems ------------------------------------ #
    D("plc", "PLC / industrial controller", "ot", (102, 502, 4840, 44818),
      ("modbus", "s7comm", "cip", "opcua"),
      ("Siemens", "Schneider", "Rockwell", "Mitsubishi"),
      ("discover", "modbus_unauth_read", "modbus_unauth_write", "s7comm_audit",
       "cip_identify", "ot_flood"),
      "protocols designed for a trusted serial bus, now on a routable network",
      ("Modbus function 3 answers with register data",),
      "a write to a holding register can stop a physical process"),
    D("hmi_panel", "HMI / operator panel", "ot", (80, 443, 102, 502, 3389),
      ("http", "rdp", "modbus"), ("Siemens", "Advantech", "Beckhoff", "Weintek"),
      ("default_creds", "discover", "rdp_probe", "config_dump"),
      "the screen on the plant floor, running an OS nobody updates",
      ("a vendor login page with no lockout",),
      "the panel is how a human touches the process, and it is also a host"),
    D("rtu", "RTU / remote telemetry unit", "ot", (502, 20000, 2404),
      ("dnp3", "iec104", "modbus"), ("SEL", "ABB", "GE", "Siemens"),
      ("discover", "dnp3_audit", "iec104_audit", "ot_flood"),
      "DNP3 or IEC-104 back to a SCADA master that trusts the link",
      ("DNP3 link status request answered",),
      "a forged telemetry frame is a lie the control room believes"),
    D("building_controller", "Building / HVAC controller", "ot", (80, 443, 47808),
      ("bacnet", "http", "modbus"),
      ("Johnson Controls", "Honeywell", "Schneider", "Distech", "Trane"),
      ("discover", "bacnet_audit", "unauth_write", "config_dump"),
      "BACnet on the plant network, with setpoints readable and writable by design",
      ("BACnet I-Am broadcasts a device instance",),
      "HVAC writes are how a building gets uncomfortable or a lab gets warm"),
    D("energy_meter", "Energy meter / inverter", "ot", (80, 161, 502),
      ("modbus", "snmp", "http"), ("SMA", "SolarEdge", "Fronius", "Schneider", "ABB"),
      ("discover", "modbus_unauth_read", "snmp_communities"),
      "Modbus on a meter or inverter: the site's load, and sometimes its limits",
      ("Modbus registers with a plausible scaling",),
      "an inverter write can island or overvolt a site's supply"),
    D("medical_device", "Medical device", "iot", (80, 104, 2575, 11112),
      ("http", "dicom", "hl7", "modbus"), ("Philips", "GE", "Siemens", "Draeger"),
      ("discover", "dicom_echo", "cleartext_audit", "version_audit"),
      "patient monitors and imaging, long service lives and plain protocols",
      ("DICOM C-ECHO answered on 104 or 11112",),
      "clinical data must not be readable from the ordinary LAN"),
    # -- retail, signage, mobility ------------------------------------------ #
    D("pos_terminal", "POS / payment terminal", "iot", (80, 443, 9100, 3389),
      ("http", "ipp", "rdp"), ("Ingenico", "Verifone", "Square", "NCR", "Toshiba"),
      ("discover", "default_creds", "cleartext_audit", "version_audit"),
      "a till whose retail side is a host on the same flat network",
      ("the host answers with a retail product page",),
      "a payment host on the flat network is where PCI DSS starts mattering"),
    D("kiosk", "Kiosk / self-service", "iot", (80, 443, 5555, 8080),
      ("http", "adb", "vnc"), ("Diebold", "NCR", "Zebra", "Elo"),
      ("discover", "vnc_probe", "default_creds", "config_dump"),
      "a locked-down browser with an unlocked debug port",
      ("VNC or ADB answered without a challenge",),
      "a kiosk is a browser someone else controls, on your network"),
    D("digital_signage", "Digital signage / display", "iot", (80, 443, 8080),
      ("http", "mdns"), ("BrightSign", "Samsung", "LG", "NEC", "Crestron"),
      ("discover", "default_creds", "config_dump"),
      "a screen with a management API and a playlist",
      ("mDNS name for a display model",),
      "the signage VLAN is usually a hop away from the corporate one"),
    D("projector", "Projector / AV matrix", "iot", (80, 23, 3629, 4352),
      ("pjlink", "http", "telnet", "crestron"),
      ("Epson", "BenQ", "Crestron", "Extron", "Barco"),
      ("discover", "default_creds", "unauth_write", "cleartext_audit"),
      "PJLink or Crestron control with an API that predates trusting nobody",
      ("PJLink answers with %1POWR",),
      "a projector that accepts commands can blind a room during an incident"),
]


DEVICE_TYPES += [
    # -- consumer and smart home -------------------------------------------- #
    D("smart_tv", "Smart TV / media player", "consumer",
      (80, 443, 7000, 8008, 8009, 9080), ("http", "airplay", "cast", "mdns"),
      ("Samsung", "LG", "Sony", "Roku"), ("discover", "cast_audit", "airplay_audit",
                                          "default_creds"),
      "a TV with an API: casting, mirroring and a remote-control port",
      ("mDNS _googlecast advertises the device",),
      "casting is remote code execution for the screen"),
    D("smart_speaker", "Smart speaker / voice assistant", "consumer",
      (443, 8008, 8443), ("http", "cast", "mdns"),
      ("Amazon", "Google", "Sonos", "Apple"),
      ("discover", "cast_audit", "config_dump", "tls_audit"),
      "an always-listening microphone with a local API",
      ("mDNS advertises a speaker service",),
      "the speaker is a microphone; the API decides who can drive it"),
    D("smart_plug", "Smart plug / relay", "consumer", (80, 443, 6668, 9999),
      ("kasa", "http", "mdns"), ("TP-Link", "Shelly", "Tasmota", "Tuya", "Wemo"),
      ("discover", "kasa_switch", "unauth_write", "config_dump"),
      "a relay on the network with an XOR-obfuscated UDP protocol",
      ("UDP 9999 answers the Kasa handshake",),
      "a plug that can be toggled remotely is a physical effect"),
    D("smart_bulb", "Smart bulb / lighting", "consumer", (80, 443, 55443, 6668),
      ("http", "zigbee_gateway", "mdns"), ("Philips Hue", "LIFX", "Yeelight", "Tuya"),
      ("discover", "unauth_write", "config_dump"),
      "lighting with a JSON API on a port it documents itself",
      ("port 55443 answers a JSON command",),
      "lighting control is an occupancy signal and an unexpected effect"),
    D("smart_lock", "Smart lock / door controller", "consumer", (80, 443, 8080),
      ("http", "ble", "mdns"), ("August", "Yale", "Schlage", "Nuki"),
      ("discover", "default_creds", "config_dump", "ble_gatt_dump"),
      "a door with a radio and a bridge",
      ("bridge page lists locks",), "a lock on the network is a door on the network"),
    D("thermostat", "Thermostat / climate control", "consumer", (80, 443, 8080),
      ("http", "mdns", "zigbee_gateway"), ("Nest", "Honeywell", "Ecobee", "Tado"),
      ("discover", "default_creds", "config_dump"),
      "a controller whose API moves the building's temperature",
      ("mDNS TXT carries a model name",),
      "a thermostat write is a comfort, cost and safety finding"),
    D("robot_vacuum", "Robot vacuum / appliance", "consumer", (80, 443, 54321),
      ("miio", "http", "mqtt"), ("Roborock", "iRobot", "Dreame", "Ecovacs"),
      ("discover", "miio_info", "config_dump"),
      "an appliance that maps the building and phones the cloud",
      ("UDP 54321 answers a miIO hello",),
      "the floor plan it uploads is a floor plan of the client"),
    D("ev_charger", "EV charger", "consumer", (80, 443, 502, 8080),
      ("http", "modbus", "ocpp"), ("Wallbox", "Zaptec", "ABB", "Schneider"),
      ("discover", "modbus_unauth_read", "default_creds", "config_dump"),
      "a charger with OCPP to a backend and a local web UI",
      ("OCPP boot notification in the logs",),
      "charger control is energy control, and it holds a payment token"),
    D("camera_doorbell", "Consumer camera / baby monitor", "consumer", (80, 443, 554),
      ("http", "rtsp", "mqtt"), ("Wyze", "Eufy", "Blink", "Arlo"),
      ("discover", "rtsp_anonymous", "mqtt_audit", "default_creds"),
      "a cheap camera with a stream and an MQTT channel to its cloud",
      ("RTSP answers without authentication",),
      "consumer cameras are the most common open stream on a home network"),
    # -- phones, tablets and wearables -------------------------------------- #
    D("smartphone", "Smartphone", "mobile", (80, 443, 5555, 62078),
      ("http", "adb", "mdns"), ("Apple", "Samsung", "Xiaomi", "Google"),
      ("discover", "adb_probe", "config_dump"),
      "a client device with a debug port and a pairing history",
      ("mDNS advertises _adb or _airdrop",),
      "one compromised phone is every credential it ever saved"),
    D("tablet", "Tablet / mobile workstation", "mobile", (80, 443, 5900),
      ("http", "vnc", "mdns"), ("Apple", "Samsung", "Lenovo", "Microsoft"),
      ("discover", "vnc_probe", "config_dump"),
      "a client device on the corporate VLAN",
      ("VNC answers with a version banner",), "tablets hold the session tokens"),
    D("fitness_tracker", "Fitness tracker / smartwatch", "mobile", (),
      ("ble", "gatt"), ("Fitbit", "Garmin", "Polar", "Withings"),
      ("ble_scan_audit", "ble_gatt_dump", "ble_pair_bruteforce"),
      "a wearable advertising over BLE, often with no bonding",
      ("BLE advertisement carries a vendor UUID",),
      "wearable data is health data; bonding decides who can read it"),
    # -- Bluetooth-only targets --------------------------------------------- #
    D("bt_headset", "Bluetooth headset / audio", "bt", (),
      ("bluetooth", "rfcomm", "obex", "a2dp"),
      ("Jabra", "Plantronics", "Sony", "Bose"),
      ("bt_discover", "bt_sdp_enum", "bt_rfcomm_scan", "bt_bluebugging", "bt_bluesnarf",
       "bt_blueborne"),
      "the classic BR/EDR target: a host controller, RFCOMM and OBEX",
      ("SDP record for the Handsfree service",),
      "headset profiles have the oldest and most complete bug history"),
    D("bt_keyboard", "Bluetooth keyboard / mouse", "bt", (), ("bluetooth", "hid"),
      ("Logitech", "Microsoft", "Apple", "Keychron"),
      ("bt_discover", "bt_hid_injection", "bt_knob", "bt_bias"),
      "an HID host or device: keystrokes with no wire and often no encryption",
      ("HID service 0x1812 in the SDP or GATT table",),
      "an unpaired keyboard is a keyboard for whoever pairs first"),
    D("ble_sensor", "BLE sensor / tag", "bt", (), ("ble", "gatt", "adv"),
      ("Xiaomi", "Inkbird", "Ruuvitag", "Tile"),
      ("ble_scan_audit", "ble_gatt_dump", "ble_spoof_adv", "ble_pair_bruteforce"),
      "a coin cell that broadcasts a number and takes no password",
      ("manufacturer data in the advertisement",),
      "sensor data is telemetry about the site's physical state"),
    D("ble_beacon", "BLE beacon / proximity tag", "bt", (), ("ble", "ibeacon"),
      ("Estimote", "Kontakt", "Radius", "Minew"),
      ("ble_scan_audit", "ble_spoof_adv", "ble_track_resolve"),
      "an iBeacon or Eddystone whose whole job is being spoofable",
      ("an iBeacon manufacturer frame with a UUID",),
      "beacons drive indoor location and are trivially cloned"),
    D("bt_lock", "Bluetooth lock / padlock", "bt", (), ("ble", "gatt"),
      ("Master Lock", "Noke", "Igloohome"),
      ("ble_scan_audit", "ble_gatt_dump", "ble_pair_bruteforce", "bt_sweyntooth"),
      "a lock whose key is a GATT characteristic",
      ("GATT service with a writable unlock characteristic",),
      "the BLE lock's pairing mode is its vulnerability"),
    D("bt_car_kit", "Car kit / infotainment", "bt", (),
      ("bluetooth", "hfp", "pbap", "obex"), ("Parrot", "Pioneer", "Kenwood", "JVC"),
      ("bt_discover", "bt_sdp_enum", "bt_bluesnarf", "bt_bluebugging"),
      "a hands-free unit that reads its phone's phonebook to whoever it trusts",
      ("PBAP service in the SDP record",),
      "the car kit holds the contact list and the call history"),
    D("bt_printer", "Bluetooth printer", "bt", (), ("bluetooth", "spp", "rfcomm"),
      ("Zebra", "Star", "Brother", "Bixolon"),
      ("bt_discover", "bt_rfcomm_scan", "bt_spp_audit", "bt_bluesmack"),
      "a serial port profile printer: the label protocol over RFCOMM",
      ("SPP service in the SDP record",),
      "an SPP printer often accepts a job from any connected client"),
]


# --------------------------------------------------------------------------- #
# edition assignment for the device table
# --------------------------------------------------------------------------- #

#: which edition a device type belongs to when the row did not say.  Bluetooth-only
#: groups are the Bluetooth edition; an access point's management side is Wi-Fi's; and
#: everything else lives on the network the bridge leads to.
_EDITION_BY_GROUP = {"bt": "bluetooth"}


def _domain_for(dev: DeviceType) -> str:
    if dev.domain != "it":
        return dev.domain
    if dev.group == "bt":
        return "bluetooth"
    if dev.id in ("access_point", "wireless_controller", "bluetooth", "router"):
        return "wifi" if dev.id in ("access_point", "wireless_controller") else "it"
    if dev.group == "mobile" and {"ble", "gatt", "bluetooth"} & set(dev.protocols):
        return "bluetooth"
    return "it"


DEVICE_TYPES = [replace(dev, domain=_domain_for(dev)) for dev in DEVICE_TYPES]

# --------------------------------------------------------------------------- #
# lookups
# --------------------------------------------------------------------------- #

#: built at the end of the module: the last wave appends its rows with ``DEVICE_TYPES +=``
#: and a lookup table built here would silently miss them.
_BY_ID: Dict[str, DeviceType] = {}


def device_type(dev_id: str) -> Optional[DeviceType]:
    """The device type with this id, or ``None``."""
    return _BY_ID.get(dev_id or "")


def device_type_label(dev_id: str) -> str:
    dev = _BY_ID.get(dev_id or "")
    return dev.label if dev else (dev_id or "unknown device")


def device_ids() -> List[str]:
    return [dev.id for dev in DEVICE_TYPES]


def types_for_port(port: int) -> List[DeviceType]:
    return [dev for dev in DEVICE_TYPES if port in dev.ports]


def types_for_domain(domain: str) -> List[DeviceType]:
    if not domain or domain == "all":
        return list(DEVICE_TYPES)
    return [dev for dev in DEVICE_TYPES if dev.domain == domain]


#: how a device type is allowed to *name* the attacks it wants.  A row may hold either a
#: concrete registered name (``bt_bluesnarf``) or a technique (``default_creds``), which
#: is resolved against the protocols of the same row into ``it_<protocol>_<technique>``.
TECHNIQUES = ("discover", "version_audit", "default_creds", "auth_bypass", "config_dump",
              "unauth_read", "unauth_write", "flood", "cleartext_audit", "tls_audit",
              "sip_enum", "snmp_communities", "provisioning_audit")


def _names_for(dev: DeviceType) -> List[str]:
    """Every concrete attack name a device type suggests, techniques resolved."""
    names: List[str] = []
    for entry in dev.attacks:
        if entry in _BY_ID:                      # a device id never appears here
            continue
        if entry.endswith(TECHNIQUES) and entry not in TECHNIQUES:
            names.append(entry)                  # already a full name (bt_*, ble_*)
            continue
        if entry in TECHNIQUES:
            for protocol in dev.protocols:
                names.append(f"it_{protocol}_{entry}")
            continue
        names.append(entry)                      # a name from another edition
    seen: List[str] = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return seen


#: the roadmap: every attack a device type *ought* to be tested with.  A name in here
#: that this build does not implement yet is not a bug — it is what the next wave adds —
#: so this table is never what the UI shows.  :func:`suggested_attacks` is.
#: filled in at the end of the module, after every ``DEVICE_TYPES +=`` row is in place
SUGGESTED_ATTACKS: Dict[str, List[str]] = {}

#: protocol names the roadmap and the registry spell differently
SYNONYM_PROTOCOLS: Dict[str, str] = {"dns": "mdns", "dns_sd": "mdns", "upnp": "ssdp",
                                     "mongodb": "mongo", "zookeeper": "http_json",
                                     "jenkins": "http_json", "docker": "http_json",
                                     "elasticsearch": "http_json", "k8s": "http_json"}

#: technique names the roadmap and the registry spell differently
SYNONYM_TECHNIQUES: Dict[str, str] = {"probe": "discover", "identify": "discover",
                                      "info": "discover", "audit": "version_audit",
                                      "enum": "modules", "list": "modules",
                                      "read": "unauth_read", "write": "unauth_write"}

#: roadmap names that exist under another spelling: same technique, the name the wave
#: that implemented it settled on.  Anything not here and not resolvable by protocol and
#: technique stays in the roadmap and out of the resolved list.
ALIAS_ATTACKS: Dict[str, str] = {
    # Bluetooth: the roadmap was written for BLE-prefixed names, the wave shipped bt_*
    "ble_scan_audit": "bt_le_scan", "bt_discover": "bt_device_census",
    "ble_gatt_dump": "bt_gatt_enumeration", "bt_gatt_dump": "bt_gatt_enumeration",
    "ble_pair_bruteforce": "bt_pairing_audit", "ble_spoof_adv": "bt_beacon_clone",
    "ble_track_resolve": "bt_tracker_detect", "bt_sdp_enum": "bt_sdp_browse",
    "bt_spp_audit": "bt_rfcomm_scan", "bt_spp_brute": "bt_rfcomm_scan",
    "bt_hid_keylog": "bt_hid_injection", "bt_obex_push": "bt_bluesnarf",
    "bt_adv_flood": "bt_adv_name_flood",
    # IT: the roadmap's shorthand for "the service the registry implements"
    "rtsp_anonymous": "it_rtsp_anonymous", "ipp_anonymous": "it_ipp_anonymous",
    "ldap_anonymous": "it_ldap_anonymous", "smb_null_session": "it_smb_null_session",
    "modbus_unauth_read": "it_modbus_unauth_read",
    "modbus_unauth_write": "it_modbus_unauth_write",
    "bacnet_audit": "it_bacnet_version_audit", "cip_identify": "it_cip_discover",
    "dnp3_audit": "it_dnp3_version_audit", "iec104_audit": "it_iec104_version_audit",
    "s7comm_audit": "it_s7comm_version_audit", "mqtt_audit": "it_mqtt_version_audit",
    "airplay_audit": "it_airplay_version_audit", "cast_audit": "it_cast_version_audit",
    "jenkins_audit": "it_http_json_jenkins_audit", "kasa_switch": "it_kasa_discover",
    "miio_info": "it_miio_discover", "tr069_probe": "it_cwmp_discover",
    "rdp_probe": "it_rdp_discover", "vnc_probe": "it_vnc_discover",
    "rsync_list": "it_rsync_modules", "pjl_command": "it_pjl_discover",
    "dicom_echo": "it_dicom_echo", "docker_api": "it_http_json_discover",
    "elastic_audit": "it_http_json_cluster_read",
}

_RESOLVED: Dict[str, List[str]] = {}


def _resolve(name: str, protocols: Sequence[str], registered: Set[str]) -> str:
    """The registered attack a suggested name means, or ``""`` when this build has none."""
    if name in registered:
        return name
    if name in ALIAS_ATTACKS and ALIAS_ATTACKS[name] in registered:
        return ALIAS_ATTACKS[name]
    if not name.startswith(("it_", "bt_", "ble_")):
        if f"it_{name}" in registered:
            return f"it_{name}"
    parts = name.split("_")
    tail = "_".join(parts[2:]) if parts[0] == "it" and len(parts) > 2 else "_".join(parts[1:])
    if len(parts) >= 3 and parts[0] == "it":
        protocol, technique = parts[1], "_".join(parts[2:])
        protocol = SYNONYM_PROTOCOLS.get(protocol, protocol)
        technique = SYNONYM_TECHNIQUES.get(technique, technique)
        for candidate in (f"it_{protocol}_{technique}",
                          f"it_{protocol}_{technique}_audit",
                          f"it_{protocol}_version", f"it_{protocol}_banner",
                          f"it_{protocol}_discover"):
            if candidate in registered:
                return candidate
    # a roadmap technique that only some protocols implement: fall back to the protocol
    # of *this* device when it has one the registry knows
    for protocol in protocols:
        real = SYNONYM_PROTOCOLS.get(protocol, protocol)
        if f"it_{real}_{tail}" in registered:
            return f"it_{real}_{tail}"
        for candidate in (f"it_{real}_discover", f"it_{real}_version"):
            if candidate in registered and tail in ("discover", "version", "version_audit"):
                return candidate
    return ""


def suggested_attacks(device: Union[str, DeviceType]) -> List[str]:
    """The suggested attacks for a device type that **exist in this build**.

    The roadmap above is written for the ideal toolbox; this is the intersection with
    what is registered, which is what the UI, the planner and the reports may show.
    Resolution is done once and cached: 65 device types is not worth re-scanning the
    848-name registry per request.

    >>> from wifipilot.itdev import suggested_attacks
    >>> names = suggested_attacks("ip_camera")
    >>> "it_rtsp_anonymous" in names and all(n.startswith(("it_", "bt_")) for n in names)
    True
    """
    dev = device_type(device) if isinstance(device, str) else device
    if dev is None:
        return []
    if dev.id not in _RESOLVED:
        try:
            from .attacks import ATTACK_CLASSES
            registered: Set[str] = set(ATTACK_CLASSES)
        except Exception:                        # pragma: no cover - import cycle guard
            registered = set()
        resolved: List[str] = []
        for name in SUGGESTED_ATTACKS.get(dev.id, []):
            real = _resolve(name, dev.protocols, registered) if registered else name
            if real and real not in resolved:
                resolved.append(real)
        _RESOLVED[dev.id] = resolved
    return list(_RESOLVED[dev.id])


def roadmap_attacks(dev: Union[str, DeviceType]) -> List[str]:
    """The unresolved roadmap for a device type (what the next wave still owes it)."""
    dev = device_type(dev) if isinstance(dev, str) else dev
    return list(SUGGESTED_ATTACKS.get(dev.id, [])) if dev else []


def plan_for_device(dev: DeviceType, registered: Optional[Iterable[str]] = None) -> List[str]:
    """The attacks that apply to this device *and* exist in the registry."""
    names = suggested_attacks(dev) if registered is None else SUGGESTED_ATTACKS.get(dev.id, [])
    if registered is None:
        try:
            from .attacks import ATTACK_CLASSES as registered_map
            registered = set(registered_map)
        except Exception:                        # pragma: no cover - import cycle guard
            registered = set(names)
    known = set(registered)
    return [name for name in names if name in known]


def device_catalog() -> List[Dict[str, Any]]:
    """Every device type as a dict, with the attacks it suggests resolved."""
    out: List[Dict[str, Any]] = []
    for dev in DEVICE_TYPES:
        row = dev.to_dict()
        row["attack_names"] = suggested_attacks(dev)
        out.append(row)
    return out


def ports_of(dev_ids: Iterable[str]) -> List[int]:
    """The union of the ports of several device types, sorted (a starting scan list)."""
    ports = set()
    for dev_id in dev_ids:
        dev = _BY_ID.get(dev_id)
        if dev:
            ports.update(dev.ports)
    return sorted(ports)


def edition_catalog() -> List[Dict[str, Any]]:
    """The editions with device counts, for the UI's first control."""
    out: List[Dict[str, Any]] = []
    for entry in DOMAINS:
        devs = types_for_domain(entry["id"])
        row = dict(entry)
        row["devices"] = len(devs)
        out.append(row)
    return out


# --------------------------------------------------------------------------- #
# classification
# --------------------------------------------------------------------------- #

#: how much each kind of evidence is worth.  A port is a hint, a banner that names the
#: product is stronger, and a vendor that matches is stronger still.
_WEIGHTS = {"port": 2, "mdns": 3, "banner": 2, "vendor": 3, "hostname": 1, "protocol": 2}


def classify(ports: Iterable[int] = (), hostname: str = "", banners: Iterable[str] = (),
             vendor: str = "", services: Iterable[str] = (),
             hints: Iterable[str] = ()) -> List[Tuple[DeviceType, int, List[str]]]:
    """Best guesses for what a host is, best first.

    Every input is optional and every input is evidence, not proof: ports come from a
    scan, ``services`` and ``hostname`` from mDNS, ``banners`` from anything that
    answered, ``vendor`` from the MAC's OUI, ``hints`` from the operator or the session.
    Returns ``(device_type, score, evidence)`` triples sorted by score, so the caller
    can show the top three guesses *and* the reasoning behind each.
    """
    port_set = {int(p) for p in ports if p}
    text = " ".join([hostname or "", vendor or "", *banners, *services, *hints]).lower()
    scores: Dict[str, int] = {}
    evidence: Dict[str, List[str]] = {}

    def add(dev: DeviceType, points: int, why: str) -> None:
        scores[dev.id] = scores.get(dev.id, 0) + points
        evidence.setdefault(dev.id, []).append(why)

    for dev in DEVICE_TYPES:
        hits = port_set & set(dev.ports)
        if hits:
            add(dev, _WEIGHTS["port"] * len(hits),
                "port " + ", ".join(str(p) for p in sorted(hits)))
        for service in dev.protocols:
            if service and service in text:
                add(dev, _WEIGHTS["protocol"], f"service {service}")
        for value in dev.search_terms:
            if value and value in text:
                add(dev, _WEIGHTS["vendor"] if value in {v.lower() for v in dev.vendors}
                    else _WEIGHTS["hostname"], f"mentions {value}")
        for tell in dev.tells:
            words = [w for w in tell.lower().replace(",", " ").split() if len(w) > 3]
            if words and sum(1 for w in words if w in text) >= max(2, len(words) // 2):
                add(dev, _WEIGHTS["banner"], f"tell: {tell}")

    ranked = sorted(((dev, scores[dev.id], evidence.get(dev.id, []))
                     for dev in DEVICE_TYPES if dev.id in scores),
                    key=lambda row: (-row[1], row[0].id))
    return ranked


def classification_note(dev: DeviceType) -> str:
    """The sentence the UI shows next to a guess, so nobody mistakes it for a fact."""
    return (f"{dev.label}: a hypothesis from ports, banners and mDNS — confirm it on the "
            f"device before acting. {dev.risk}" if dev.risk else
            f"{dev.label}: a hypothesis from ports, banners and mDNS — confirm it first.")


DEVICE_TYPES += [
    # -- the four types the IT wave needed and the first table did not have ------ #
    D("ups", "UPS / power management", "ot", (80, 161, 443, 161, 502),
      ("snmp", "http", "modbus", "tls"), ("APC", "Eaton", "Vertiv", "CyberPower"),
      ("discover", "snmp_communities", "default_creds", "config_dump",
       "modbus_unauth_read"),
      "the box that keeps the rack alive, with a web UI from the year it was installed",
      ("SNMP answers with the manufacturer OID",),
      "a UPS that can be told to drop its load is an outage with a login page"),
    D("hvac", "HVAC unit / rooftop controller", "ot", (80, 443, 47808, 502),
      ("bacnet", "http", "modbus"), ("Trane", "Carrier", "Daikin", "Mitsubishi",
                                     "Lennox"),
      ("discover", "bacnet_audit", "unauth_write", "modbus_unauth_write", "config_dump"),
      "the compressor on the roof with a BACnet interface and a service laptop's "
      "password",
      ("BACnet I-Am with a device instance in the building range",),
      "an HVAC write is a comfort and a cost finding, and in a lab it is a safety one"),
    D("medical_workstation", "Clinical workstation", "iot", (80, 104, 443, 445),
      ("dicom", "http", "smb"), ("GE", "Siemens", "Philips", "Agfa"),
      ("discover", "dicom_echo", "smb_null_session", "version_audit",
       "cleartext_audit"),
      "the PC at the radiologist's desk with a DICOM viewer and a mapped share",
      ("DICOM port 104 open beside SMB 445",),
      "one workstation is the viewer, the cache and the shortcut into PACS"),
    D("speaker", "Networked speaker / amplifier", "consumer", (80, 443, 1400, 1443,
                                                               8008, 8080),
      ("http", "cast", "mdns", "airplay"), ("Sonos", "Bose", "Yamaha", "Denon",
                                            "Bluesound"),
      ("discover", "cast_audit", "airplay_audit", "config_dump", "cleartext_audit"),
      "an amplifier with an HTTP API and a name on the network",
      ("port 1400 answers a zone-player status",),
      "the audio VLAN is a hop away from the corporate one on most sites"),
]


# --------------------------------------------------------------------------- #
# the lookup tables (built last, so every appended row is in them)
# --------------------------------------------------------------------------- #

_BY_ID = {dev.id: dev for dev in DEVICE_TYPES}
SUGGESTED_ATTACKS.update({dev.id: _names_for(dev) for dev in DEVICE_TYPES})

assert len(_BY_ID) == len(DEVICE_TYPES), (
    "two device types share an id: "
    + ", ".join(sorted({dev.id for dev in DEVICE_TYPES if
                        [d.id for d in DEVICE_TYPES].count(dev.id) > 1})))

