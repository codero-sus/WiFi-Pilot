# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Domain model: access points, clients, captures, attempts, findings."""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .util import clamp, mac_norm, oui_vendor, slugify

# --------------------------------------------------------------------------- #
# enums (plain strings keep the JSON contract with the LLM trivial)
# --------------------------------------------------------------------------- #

ENCRYPTIONS = ("OPEN", "WEP", "WPA", "WPA2", "WPA3", "WPA2/WPA3", "OWE", "ENTERPRISE")
_STATS_FIELD_NAMES: Optional[Tuple[str, ...]] = None


def _iso_of(ts: float) -> str:
    """Epoch seconds -> ISO-8601 UTC (seconds precision), now_iso()'s format."""
    return datetime.fromtimestamp(ts, timezone.utc).replace(microsecond=0).isoformat()
WPS_STATES = ("", "unlocked", "locked", "configured", "unknown")
CAPTURE_KINDS = ("handshake", "pmkid", "wep_ivs")

#: attack primitives the planner is allowed to choose from (whitelist!).  Every
#: name here is registered in ``wifipilot.attacks.ATTACK_CLASSES`` and described in
#: ``wifipilot.attacks.meta``; a test keeps the three lists in step.
ATTACK_NAMES = [
    # offline: files the session already has, no radio, no authorisation
    "loot_audit",       # what is in the session's loot, and what is missing
    "eapol_audit",      # decode the EAPOL exchanges already captured
    "wep_audit",        # count IVs/ARP in a WEP capture and say what is missing
    "crack_sweep",      # every usable hash the session holds -> the cracker
    "eap_md5_crack",    # EAP-MD5 offline dictionary (RFC 2759)
    "pixie_offline",    # pixiewps against a stored WPS exchange
    "rogue_detect",     # rogue/twin infrastructure in the captures
    "twin_detect",      # identical SSIDs, different vendors
    "roam_audit",       # 802.11k/r/v and PMF posture
    "wps_lockout_audit",  # lockout policy of WPS APs already seen
    # capture
    "handshake",      # deauth + 4-way capture
    "handshake_broadcast",  # the same, deauthenticating every client at once
    "pmkid",          # client-less PMKID (hcxdumptool / airodump --pmkid)
    "pmkid_flood",    # active PMKID hunt: deauth to force M1 with a PMKID
    "hcxdump_capture",  # the hcxdumptool -> hcxpcapngtool pipeline
    # read-only surveys
    "passive",        # listen only, never transmit
    "pmf_audit",      # RSN/PMF audit: which classic attacks are still possible
    "saewolf",        # WPA3 SAE capture + transition-mode analysis
    "sae_group_audit",  # SAE groups, H2E and PMF posture from a capture
    "ie_audit",       # decode the elements airodump's CSV throws away
    "pnl_harvest",    # what clients are asking for, and which names are not on air
    "hidden_ssid",    # name a hidden network from probe responses/associations
    "tracker",        # follow one station: its real PNL, its signal trend
    "rogue_ap",       # read-only twin/attacker-infrastructure survey
    "enterprise",     # 802.1X survey: method, identity, server certificate
    # WPS / WEP
    "wps_pixie",      # offline Pixie-Dust against WPS
    "wps_ap_pin",     # vendor-derived static AP PIN
    "wps_lockout_probe",  # measure the lockout policy with three wrong PINs
    "wps_pbc",        # push-button enrolment: is a window open?
    "wps_pin",        # online PIN brute force / default-PIN replay
    "wep_ivs",        # ARP-replay IV harvesting
    "wep_p0841",      # injected ARP (P0841) so the IV harvest can run
    "wep_chopchop",   # KoreK chopchop: keystream without the key
    "wep_fragment",   # fragmentation attack: PRGA for injection
    "wep_hirte",      # client-oriented fragmentation
    "eapol_logoff",   # unauthenticated disconnect (PMF does not cover EAPOL)
    # rogue infrastructure, lures, impersonation
    "karma",          # answer every probe request and see who trusts the name
    "karma_detect",   # probes for names that cannot exist: find a Karma device
    "csa_attack",     # channel-switch announcement: silent eviction
    "ssid_confusion",  # the same SSID from a new BSSID
    "ssid_bruteforce",  # dictionary probes against a hidden network
    "ap_isolation_audit",  # can one client reach another? (spoofed ARP)
    "evil_twin",      # serve the SSID ourselves and see who prefers it
    "rogue_radius",   # impersonate the AP: will a client trust any certificate?
    # denial of service (opt-in, always, and capped in time)
    "deauth_flood",   # denial-of-service / WIDS detection test
    "auth_flood",     # authentication flood: association-table exhaustion test
    "assoc_flood",    # association flood: state exhaustion, no external tool
    "null_data_flood",  # power-save buffer exhaustion: no deauth frames at all
    "probe_flood",    # probe flood: hidden-SSID disclosure test
    "eapol_start_flood",  # 802.1X session exhaustion (enterprise)
    "sae_commit_flood",  # WPA3 CPU exhaustion: commits before authentication
    "tkip_michael",   # replay two corrupted TKIP frames: 60-second shutdown
    "wids_confusion",  # deauths carrying a neighbour's BSSID
    "beacon_flood",   # beacon-flood / WIDS detection test
    "disassoc_flood",  # the deauth flood's sibling, for WIDS rule sets
    "rts_flood",      # medium reservation with RTS: no management frame at all
    "cts_flood",      # CTS-to-self: the channel held silent
    "channel_switch_flood",  # CSA beacons walk clients off the network
    "sa_query_flood",  # PMF association-state exhaustion
    "tdls_teardown_flood",  # direct station links torn down
    "probe_response_flood",  # phantom scan lists
    "dhcp_discover_flood",  # the DHCP pool walked through
    # second-wave capture, protocol and network-layer work
    "injection_test",  # is the card really injecting? (aireplay-ng --test)
    "arp_replay",     # IV generation by replaying ARP
    "pcap_replay",    # re-send a capture's frames
    "mac_filter_probe",  # does the AP filter by address?
    "channel_sweep",  # what is on each channel, live
    "krack_detect",   # key-reinstallation patterns in a capture
    "kr00k_detect",   # all-zero ciphertext (CVE-2019-15126) in a capture
    "fragattacks_detect",  # A-MSDU/fragment exposure
    "ft_audit",       # 802.11r fast transition posture
    "beacon_rate_audit",  # beacon timing and interval anomalies
    "tsf_clone_detect",  # clones spotted by their TSF timers
    "client_fingerprint",  # devices by their probe requests
    "eap_identity_harvest",  # 802.1X identities and realms
    "eap_method_probe",  # which EAP methods the authenticator accepts
    "certificate_audit",  # the RADIUS server's certificate, decoded
    "ttls_inner_audit",  # what is inside the TLS tunnel
    "eap_tls_version",  # deprecated TLS versions in EAP-TLS
    "mschapv2_crack",  # MS-CHAPv2 offline dictionary (RFC 2759)
    "radius_secret_test",  # shared-secret dictionary against RADIUS
    "ap_admin_audit",  # management ports and pages on the gateway
    "upnp_audit",     # SSDP discovery and port-mapping exposure
    "snmp_audit",     # default community strings
    "dns_audit",      # open resolver / DNSSEC
    "wpad_audit",     # proxy auto-discovery exposure
    "rogue_dhcp_detect",  # a second DHCP server on the segment
    "arp_spoof_detect",  # two MACs for one address
    "ipv6_ra_audit",  # rogue router advertisements
    "rogue_dhcp",     # serve leases ourselves
    "dns_sink",       # answer every name ourselves
    "captive_portal",  # a portal page that asks for credentials
    "arp_mitm",       # poison the gateway relationship
    "beacon_clone",   # clone the SSID's beacons from a second radio
    "wpa3_downgrade_twin",  # imitate WPA3 as WPA2-only
    "pmf_downgrade_probe",  # does the AP enforce PMF?
    "btm_hijack",     # steer a client with a forged BTM request
    "capture_quality",  # which captures are worth cracking
    "hash_audit",     # mode-22000 files, and what is broken about them
    "wordlist_audit",  # what the wordlists actually contain
    "wordlist_mine",  # target-specific candidates from the engagement's own data
    "crack_plan",     # benchmarked time-versus-coverage plan
    "vendor_fingerprint",  # device table: vendor, model, element fingerprint
    "beacon_timeline",  # what changed while we watched
    "cleartext_sniff",  # credentials read out of a capture
    "pmk_check",      # loot that needs no cracking
    "loot_manifest",  # chain of custody (SHA-256 manifest)
]

# The batch waves (Bluetooth, IT, hijackers, …), appended in registry order.
# This block is GENERATED from the live registry so the whitelist is complete
# without importing a single attack class — ``import wifipilot`` must not pay
# for 46 attack modules before the first command runs (the planner whitelist,
# CLI validation and ``--help`` all read this list):
#   /tmp regen: import wifipilot.attacks, then dump ATTACK_NAMES[107:] here.
# ``attacks/__init__`` still appends any name missing from this list when it
# imports, and a test fails if this block drifts from the registry.
ATTACK_NAMES += [
    "mic_check", "nonce_reuse_audit", "key_version_audit", "tkip_countermeasures_audit",
    "group_cipher_audit", "cipher_downgrade_audit", "rsn_ie_audit", "ie_anomaly_audit",
    "malformed_ie_audit", "wildcard_probe_audit", "randomised_mac_ratio", "probe_privacy_audit",
    "assoc_history_audit", "client_vendor_audit", "client_count_audit", "data_frame_audit",
    "protected_ratio_audit", "duration_field_audit", "retransmit_audit", "fragment_audit",
    "beacon_interval_audit", "tsf_skew_audit", "assoc_response_audit", "auth_response_audit",
    "ssid_length_audit", "encryption_inventory", "bssid_oui_audit", "signal_histogram",
    "channel_usage_audit", "channel_overlap_audit", "handshake_message_audit", "pmkid_presence_audit",
    "eapol_retry_audit", "wpa3_transition_audit", "sa_query_activity", "eapol_logoff_audit",
    "llc_snap_audit", "qos_audit", "power_save_audit", "broadcast_storm_audit",
    "gratuitous_arp_audit", "arp_scan_detect", "dhcp_fingerprint_audit", "duplicate_seq_audit",
    "deauth_storm_detect", "auth_flood_detect", "probe_flood_detect", "pcap_report",
    "capture_coverage", "beacon_rate_histogram", "auth_algorithm_inventory", "station_inventory",
    "quality_histogram", "vendor_ie_inventory", "hidden_ap_audit", "extended_capability_audit",
    "rrm_measurement_audit", "neighbour_report_audit", "ft_mobility_audit", "bss_load_audit",
    "interworking_audit", "hs20_audit", "wmm_parameter_audit", "wps_config_audit",
    "country_power_audit", "ssid_hygiene_audit", "security_mismatch_audit", "client_capability_audit",
    "frame_control_audit", "airtime_estimate", "probe_response_latency_audit", "eapol_key_flags_audit",
    "group_rekey_audit", "eapol_timing_audit", "bt_device_census", "bt_tracker_detect",
    "bt_tracker_follow", "bt_ibeacon_audit", "bt_eddystone_audit", "bt_address_privacy",
    "bt_manufacturer_census", "bt_service_census", "bt_interval_audit", "bt_channel_audit",
    "bt_connectable_audit", "bt_pairing_audit", "bt_gatt_audit", "bt_feature_audit",
    "bt_le_scan", "bt_hci_inquiry", "bt_adv_name_flood", "bt_adv_dos",
    "bt_beacon_clone", "bt_tracker_clone", "bt_connectable_lure", "bt_pairing_flood",
    "bt_l2cap_echo_flood", "bt_sdp_browse", "bt_rfcomm_scan", "bt_gatt_enumeration",
    "ble_hid", "ble_hid_audit", "ble_hid_boot", "ble_hid_reconnect",
    "ble_smp_downgrade", "ble_gatt_hijack", "ble_irk_resolve", "ble_conn_param_hijack",
    "ble_hid_mimic", "ble_speaker_mimic", "ble_pairing_mimic", "ble_bond_hijack",
    "ble_adv_identity_clone", "ble_name_collision", "ble_device_mimic", "ble_tracker_mimic",
    "ble_beacon_mimic", "ble_eddystone_mimic", "ble_smartlock_mimic", "ble_badge_mimic",
    "ble_ev_charger_mimic", "ble_mesh_mimic", "ble_anchor_mimic", "ble_printer_mimic",
    "ble_ir_mimic", "ble_fastpair_mimic", "ble_fido_mimic", "ble_telemetry_mimic",
    "ble_patient_mimic", "ble_hid_multi_host", "ble_consumer_mimic", "ble_audio_le_mimic",
    "ble_peripheral_shadow", "ble_mouse_mimic", "ble_combo_dongle_mimic", "ble_lock_mimic",
    "ble_lock_mesh_mimic", "ble_bulb_mimic", "ble_mesh_lamp_mimic", "ble_plug_mimic",
    "ble_band_mimic", "ble_thermostat_mimic", "ble_scale_mimic", "ble_glucose_mimic",
    "ble_pressure_mimic", "ble_ecg_mimic", "ble_hr_mimic", "ble_air_quality_mimic",
    "ble_charger_mimic", "ble_label_printer_mimic", "ble_ir_hub_mimic", "ble_uwb_anchor_mimic",
    "ble_patient_monitor_mimic", "ble_vehicle_tracker_mimic", "ble_vending_mimic", "ble_doorbell_mimic",
    "ble_ibeacon_mimic", "ble_soundbar_mimic", "ble_hfp_hijack", "ble_hfp_audio_gateway",
    "ble_map_hijack", "ble_pbap_hijack", "ble_hfp_identity_spoof", "ble_sap_imsi_read",
    "ble_sap_file_sweep", "ble_obex_push", "ble_spp_hijack", "ble_dial_hijack",
    "ble_hidp_classic_inject", "ble_audio_session_takeover", "ble_l2cap_psm_sweep", "ble_sdp_browse_takeover",
    "ble_gatt_write_sweep", "ble_gatt_blob_dump", "ble_gatt_handle_enum", "ble_gatt_char_fuzz",
    "ble_gatt_read_flood", "ble_mtu_negotiation_abuse", "ble_notify_spoof", "ble_service_changed_abuse",
    "ble_signed_write_bypass", "ble_att_handle_brute", "ble_service_table_dump", "ble_gatt_value_dump",
    "ble_irk_crack", "ble_rpa_follow", "ble_adv_flood_le", "ble_scan_hog",
    "ble_conn_flood_le", "ble_conn_param_starve", "ble_phy_request", "ble_data_length_abuse",
    "ble_ll_unknown_probe", "ble_version_spoof", "ble_feature_page_spoof", "ble_encryption_negotiation",
    "ble_passkey_bruteforce", "ble_pairing_flood_le", "ble_oob_claim", "ble_lesc_downgrade",
    "ble_keypress_spoof", "ble_ctkd_cross_transport", "ble_key_size_probe", "ble_bond_overwrite",
    "ble_confirm_replay", "ble_public_key_audit", "ble_pair_lockout_probe", "ble_smp_command_probe",
    "twin_address_clone", "twin_element_clone", "twin_rsn_strip", "twin_tkip_downgrade",
    "twin_pmf_strip", "twin_wpa3_transition", "twin_owe_transition", "twin_hidden_name",
    "twin_enterprise_clone", "twin_mobility_domain", "twin_bss_load", "twin_country_mismatch",
    "twin_probe_shadow", "twin_signal_boost", "twin_ssid_suffix", "twin_multi_name",
    "twin_wmm_acm", "twin_neighbour_lure", "twin_quiet_element", "client_assoc_forgery",
    "client_table_flood", "client_sleep_spoof", "client_ps_poll_theft", "client_tdls_teardown",
    "client_sa_query_bypass", "client_roam_hijack", "client_eapol_logoff", "client_fourway_race",
    "client_amsdu_inject", "client_blockack_hijack", "client_rate_downgrade", "steer_btm_request",
    "steer_btm_disassoc", "steer_beacon_request", "steer_channel_load", "steer_spectrum_switch",
    "steer_fils_discovery", "steer_wnm_sleep", "steer_twt_setup", "steer_power_constraint",
    "steer_ssid_list", "steer_tpc_request", "steer_probe_answer", "session_gateway_impersonation",
    "session_dns_spoof", "session_tcp_reset", "session_seq_injection", "session_cookie_replay",
    "session_gtk_rekey", "session_msg1_flood", "session_deauth_race", "session_roam_capture",
    "session_data_replay", "session_arp_flood", "portal_clone", "portal_wildcard_dns",
    "portal_wispr_redirect", "portal_anqp_spoof", "portal_certificate_phish", "portal_hsts_downgrade",
    "portal_basic_auth", "portal_cookie_clone", "portal_oauth_phish", "portal_credential_reuse",
    "portal_javascript_inject", "enterprise_rogue_radius", "enterprise_peap_relay", "enterprise_certificate_swap",
    "enterprise_eap_md5", "enterprise_gtc_prompt", "enterprise_ttls_pap", "enterprise_mschapv2_relay",
    "enterprise_anonymous_identity", "enterprise_downgrade", "enterprise_supplicant_clone", "it_mimic_dns",
    "it_mimic_dhcp", "it_mimic_ntp", "it_mimic_syslog", "it_mimic_mqtt",
    "it_mimic_coap", "it_mimic_modbus", "it_mimic_bacnet", "it_mimic_rtsp",
    "it_mimic_sip", "it_mimic_pjl", "it_mimic_mdns", "it_mimic_ssdp",
    "it_mimic_tftp", "it_impersonate_onvif", "it_impersonate_szl", "it_impersonate_cip",
    "it_impersonate_snmp", "it_impersonate_cast", "it_impersonate_airplay", "it_impersonate_kasa",
    "it_impersonate_miio", "it_impersonate_opcua", "it_impersonate_ipp", "it_impersonate_stun",
    "it_impersonate_docker", "it_hijack_rtsp", "it_hijack_sip_register", "it_hijack_mqtt_retain",
    "it_hijack_onvif_uri", "it_hijack_modbus_coil", "it_hijack_bacnet_priority", "it_hijack_iec104",
    "it_hijack_dnp3", "it_hijack_pjl_job", "it_hijack_http_session", "it_hijack_cwmp",
    "it_hijack_adb", "it_poison_arp_gateway", "it_poison_dns", "it_poison_netbios",
    "it_poison_mdns", "it_poison_ssdp", "it_poison_dhcp_option", "it_poison_snmp_trap",
    "it_poison_bacnet_whois", "it_poison_ldap_referral", "it_poison_smb_negotiate", "it_poison_rdp_negotiation",
    "it_poison_telnet_banner", "it_relay_redis", "it_relay_memcached", "it_relay_mongo",
    "it_relay_postgres", "it_relay_mysql", "it_relay_smb", "it_relay_ldap",
    "it_relay_telnet", "it_relay_ipp", "it_relay_http_basic", "it_steal_camera_stream",
    "it_steal_printer_spool", "it_steal_plc_program", "it_steal_badge_db", "it_steal_phone_contacts",
    "it_steal_mqtt_retained", "it_steal_k8s_secrets", "it_steal_docker_images", "it_steal_sql_dump",
    "it_steal_iot_token", "it_mimic_ftp", "it_mimic_smtp", "it_mimic_imap",
    "it_mimic_rsync", "it_relay_ftp", "it_relay_smtp", "it_relay_imap",
    "it_relay_vnc", "it_relay_rsync", "it_relay_rdp", "it_relay_dicom",
    "it_relay_elastic", "it_relay_jenkins", "it_relay_kubernetes", "it_hijack_ftp_write",
    "it_hijack_smtp_relay", "it_hijack_imap_delete", "it_hijack_dicom_store", "it_hijack_vnc_session",
    "it_poison_elastic_shard", "it_poison_kubelet_response", "it_steal_ftp_files", "it_steal_smtp_credentials",
    "it_steal_imap_mailbox", "it_steal_vnc_password", "it_steal_rsync_modules", "it_steal_dicom_patients",
    "it_steal_elastic_docs", "it_steal_jenkins_jobs", "it_steal_kubelet_pods", "it_steal_smb_shares",
    "it_fuzz_dns_name", "it_fuzz_smb2_negotiate", "it_fuzz_ldap_filter", "it_fuzz_rtsp_method",
    "it_fuzz_mqtt_topic", "it_fuzz_modbus_function", "it_fuzz_snmp_varbind", "it_fuzz_sip_uri",
    "it_survey_mdns_services", "it_survey_ssdp_description", "it_survey_cwmp_parameters", "it_survey_rtsp_describe",
    "it_survey_opcua_endpoints", "it_survey_memcached_stats", "it_survey_mysql_handshake", "it_survey_spooler_banner",
    "it_mimic_dns_reverse", "it_mimic_ssh", "it_mimic_rdp", "it_mimic_coap_write",
    "it_impersonate_ssh_banner", "it_impersonate_sip_pbx", "it_impersonate_snmp_engine", "it_hijack_mysql_query",
    "it_hijack_sip_contact", "it_hijack_opcua_write", "it_poison_mdns_name", "it_poison_ssdp_location",
    "it_steal_memcached_keys", "it_steal_ldap_directory", "dhcp_lease_audit", "ipv6_prefix_audit",
    "iot_credential_audit", "iot_service_census", "ssdp_device_census", "dhcp_starvation",
    "dhcp_flood", "forged_dhcp_release", "dhcp_nak_injection", "dhcp_option_injection",
    "syn_flood", "udp_flood", "tcp_reset_injection", "udp_reflection",
    "icmp_redirect_injection", "icmp_unreachable_injection", "rogue_ra", "ra_flood",
    "ns_na_spoof", "llmnr_poisoning", "nbns_poisoning", "mdns_poisoning",
    "stp_root_takeover", "lldp_spoof", "cdp_spoof", "vlan_double_tag_hop",
    "mqtt_recon", "rtsp_camera_audit", "pjl_printer_audit", "bt_blueborne",
    "bt_bias", "bt_knob", "bt_bluebugging", "bt_blesa",
    "bt_sweyntooth", "bt_bluesnarf", "bt_bluesmack", "bt_hid_injection",
    "krack_replay", "fragattacks_inject", "airgeddon_portal", "it_http_discover",
    "it_http_banner", "it_http_version", "it_http_default_creds", "it_http_auth_bypass",
    "it_http_config_dump", "it_http_flood", "it_http_cleartext", "it_http_version_audit",
    "it_http_json_discover", "it_http_json_unauth_read", "it_http_json_unauth_write", "it_http_json_config_dump",
    "it_http_json_version_audit", "it_http_json_cluster_read", "it_http_json_jenkins_audit", "it_http_json_search_read",
    "it_http_json_cleartext_audit", "it_mqtt_discover", "it_mqtt_anonymous", "it_mqtt_default_creds",
    "it_mqtt_subscribe", "it_mqtt_publish", "it_mqtt_flood", "it_mqtt_version_audit",
    "it_mqtt_cleartext_audit", "it_coap_discover", "it_coap_unauth_read", "it_coap_unauth_write",
    "it_coap_flood", "it_coap_fuzz", "it_coap_version_audit", "it_coap_cleartext_audit",
    "it_modbus_discover", "it_modbus_unauth_read", "it_modbus_unauth_write", "it_modbus_config_dump",
    "it_modbus_flood", "it_modbus_fuzz", "it_modbus_version_audit", "it_modbus_cleartext_audit",
    "it_bacnet_discover", "it_bacnet_unauth_read", "it_bacnet_unauth_write", "it_bacnet_config_dump",
    "it_bacnet_flood", "it_bacnet_version_audit", "it_bacnet_cleartext_audit", "it_rtsp_discover",
    "it_rtsp_anonymous", "it_rtsp_default_creds", "it_rtsp_version", "it_rtsp_config_dump",
    "it_rtsp_flood", "it_rtsp_version_audit", "it_rtsp_cleartext_audit", "it_onvif_discover",
    "it_onvif_version", "it_onvif_config_dump", "it_onvif_default_creds", "it_onvif_stream_uri",
    "it_onvif_version_audit", "it_onvif_cleartext_audit", "it_ipp_discover", "it_ipp_version",
    "it_ipp_anonymous", "it_ipp_default_creds", "it_ipp_flood", "it_ipp_config_dump",
    "it_ipp_version_audit", "it_ipp_cleartext_audit", "it_pjl_discover", "it_pjl_version",
    "it_pjl_config_dump", "it_pjl_unauth_write", "it_pjl_filesys_audit", "it_pjl_flood",
    "it_pjl_version_audit", "it_pjl_cleartext_audit", "it_telnet_banner", "it_telnet_version",
    "it_telnet_default_creds", "it_telnet_cleartext", "it_telnet_version_audit", "it_sip_discover",
    "it_sip_challenge_audit", "it_sip_enum", "it_sip_default_creds", "it_sip_flood",
    "it_sip_cleartext", "it_sip_version_audit", "it_sip_cleartext_audit", "it_cwmp_discover",
    "it_cwmp_config_dump", "it_cwmp_unauth_write", "it_cwmp_version", "it_cwmp_version_audit",
    "it_cwmp_cleartext_audit", "it_smb_discover", "it_smb_version", "it_smb_signing_audit",
    "it_smb_null_session", "it_smb_flood", "it_smb_version_audit", "it_smb_cleartext_audit",
    "it_ldap_discover", "it_ldap_anonymous", "it_ldap_version", "it_ldap_default_creds",
    "it_ldap_unauth_read", "it_ldap_flood", "it_ldap_version_audit", "it_ldap_cleartext_audit",
    "it_redis_discover", "it_redis_anonymous", "it_redis_version", "it_redis_config_dump",
    "it_redis_unauth_write", "it_redis_flood", "it_redis_version_audit", "it_redis_cleartext_audit",
    "it_memcached_discover", "it_memcached_version", "it_memcached_unauth_read", "it_memcached_unauth_write",
    "it_memcached_flood", "it_memcached_version_audit", "it_memcached_cleartext_audit", "it_mongo_discover",
    "it_mongo_version", "it_mongo_anonymous", "it_mongo_unauth_read", "it_mongo_flood",
    "it_mongo_version_audit", "it_mongo_cleartext_audit", "it_kasa_discover", "it_kasa_anon_read",
    "it_kasa_unauth_write", "it_kasa_version", "it_kasa_flood", "it_kasa_version_audit",
    "it_kasa_cleartext_audit", "it_cast_discover", "it_cast_unauth_read", "it_cast_unauth_write",
    "it_cast_flood", "it_cast_version_audit", "it_cast_cleartext_audit", "it_airplay_discover",
    "it_airplay_version", "it_airplay_auth_audit", "it_airplay_version_audit", "it_airplay_cleartext_audit",
    "it_adb_discover", "it_adb_anonymous", "it_adb_version", "it_adb_unauth_read",
    "it_adb_flood", "it_adb_version_audit", "it_adb_cleartext_audit", "it_vnc_discover",
    "it_vnc_anonymous", "it_vnc_version", "it_vnc_default_creds", "it_vnc_flood",
    "it_vnc_version_audit", "it_vnc_cleartext_audit", "it_pjlink_discover", "it_pjlink_version",
    "it_pjlink_unauth_write", "it_pjlink_flood", "it_pjlink_version_audit", "it_pjlink_cleartext_audit",
    "it_dicom_discover", "it_dicom_echo", "it_dicom_config_dump", "it_dicom_version",
    "it_dicom_flood", "it_dicom_version_audit", "it_dicom_cleartext_audit", "it_s7comm_discover",
    "it_s7comm_version", "it_s7comm_unauth_read", "it_s7comm_config_dump", "it_s7comm_flood",
    "it_s7comm_version_audit", "it_s7comm_cleartext_audit", "it_cip_discover", "it_cip_version",
    "it_cip_unauth_read", "it_cip_flood", "it_cip_version_audit", "it_cip_cleartext_audit",
    "it_dnp3_discover", "it_dnp3_unauth_read", "it_dnp3_version", "it_dnp3_flood",
    "it_dnp3_version_audit", "it_dnp3_cleartext_audit", "it_iec104_discover", "it_iec104_unauth_read",
    "it_iec104_version", "it_iec104_flood", "it_iec104_version_audit", "it_iec104_cleartext_audit",
    "it_opcua_discover", "it_opcua_version", "it_opcua_endpoint_audit", "it_opcua_flood",
    "it_opcua_version_audit", "it_opcua_cleartext_audit", "it_ssh_banner", "it_ssh_version",
    "it_ssh_kex_audit", "it_ssh_default_creds", "it_ssh_flood", "it_ssh_version_audit",
    "it_rdp_discover", "it_rdp_nla_audit", "it_rdp_version", "it_rdp_flood",
    "it_rdp_version_audit", "it_postgres_discover", "it_postgres_anonymous", "it_postgres_version",
    "it_postgres_default_creds", "it_postgres_flood", "it_postgres_version_audit", "it_postgres_cleartext_audit",
    "it_mysql_discover", "it_mysql_version", "it_mysql_tls_audit", "it_mysql_default_creds",
    "it_mysql_version_audit", "it_mysql_cleartext_audit", "it_rsync_discover", "it_rsync_modules",
    "it_rsync_unauth_read", "it_rsync_version", "it_rsync_version_audit", "it_rsync_cleartext_audit",
    "it_ftp_banner", "it_ftp_version", "it_ftp_anonymous", "it_ftp_default_creds",
    "it_ftp_cleartext", "it_ftp_version_audit", "it_smtp_discover", "it_smtp_version",
    "it_smtp_open_relay", "it_smtp_starttls_audit", "it_smtp_cleartext", "it_smtp_version_audit",
    "it_miio_discover", "it_miio_token", "it_miio_version", "it_miio_flood",
    "it_miio_version_audit", "it_miio_cleartext_audit", "it_ssdp_discover", "it_ssdp_version",
    "it_ssdp_unauth_write", "it_ssdp_version_audit", "it_ssdp_cleartext_audit", "it_mdns_discover",
    "it_mdns_service_census", "it_mdns_config_dump", "it_mdns_version_audit", "it_mdns_cleartext_audit",
    "it_host_discovery", "it_device_inventory", "it_port_exposure", "it_cleartext_service_audit",
    "it_default_credential_sweep", "it_firmware_advisory_audit", "it_camera_exposure_audit", "it_printer_exposure_audit",
    "it_ot_exposure_audit", "it_medical_device_audit", "it_container_exposure_audit", "it_database_exposure_audit",
    "it_share_enumeration", "it_voip_exposure_audit", "it_smart_home_audit", "it_iot_service_census",
    "it_exposure_report",
]


_ATTACK_SET_CACHE: Dict[str, Any] = {"count": -1, "set": frozenset()}


def _all_attack_names() -> frozenset:
    """ATTACK_NAMES as a frozenset, rebuilt only when the registry grows."""
    if _ATTACK_SET_CACHE["count"] != len(ATTACK_NAMES):
        _ATTACK_SET_CACHE["count"] = len(ATTACK_NAMES)
        _ATTACK_SET_CACHE["set"] = frozenset(ATTACK_NAMES)
    return _ATTACK_SET_CACHE["set"]

STATUS_IDLE = "idle"
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"


@dataclass
class Client:
    """A station associated with (or probing) an access point."""

    mac: str
    bssid: str = ""            # AP it is associated with ("" when unassociated)
    signal: int = -100
    packets: int = 0
    probes: List[str] = field(default_factory=list)
    vendor: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    handshake: bool = False
    #: recent signal readings, oldest first (bounded): the tracker reads the trend
    signal_history: List[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.mac = mac_norm(self.mac) or self.mac
        if not self.vendor:
            self.vendor = oui_vendor(self.mac)

    def remember_signal(self, signal: int, keep: int = 60) -> None:
        """Record one signal reading, keeping the list bounded."""
        if not signal:
            return
        self.signal_history.append(int(signal))
        if len(self.signal_history) > keep:
            del self.signal_history[:-keep]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mac": self.mac, "bssid": self.bssid, "signal": self.signal,
            "packets": self.packets, "probes": self.probes[:5], "vendor": self.vendor,
            "handshake": self.handshake, "age": round(time.time() - self.last_seen, 1),
        }


@dataclass
class AccessPoint:
    """Everything we know about one BSSID."""

    bssid: str
    essid: str = ""
    channel: int = 0
    frequency: int = 0
    signal: int = -100
    encryption: str = "WPA2"
    cipher: str = "CCMP"
    auth: str = "PSK"
    privacy: bool = True
    wps: bool = False
    wps_version: str = ""
    wps_locked: str = ""
    wps_model: str = ""
    wps_device: str = ""
    wps_manufacturer: str = ""
    #: free-form operator tags (put in scope, out of scope, retest, ...)
    tags: List[str] = field(default_factory=list)
    #: what happened to this AP, oldest first (bounded; see ``remember``)
    history: List[Dict[str, Any]] = field(default_factory=list)
    #: a coarse classification, useful for filtering and reporting
    target_kind: str = ""
    #: vendor dossier key (see :mod:`wifipilot.vendors`), never a measurement
    vendor_profile: str = ""
    #: operator notes / advice attached to this AP
    notes: str = ""
    pmf: bool = False              # 802.11w management frame protection
    sae: bool = False              # WPA3-SAE
    sai: bool = False              # WPA3 transition mode indicator
    pmf_checked: bool = False      # the RSN/PMF audit has read this AP's elements
    hidden: bool = False
    beacon_count: int = 0
    data_count: int = 0
    vendor: str = ""
    band: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    clients: "OrderedDict[str, Client]" = field(default_factory=OrderedDict)
    captures: List["Capture"] = field(default_factory=list)
    attempts: List["Attempt"] = field(default_factory=list)
    status: str = STATUS_IDLE
    notes: str = ""
    # runtime bookkeeping
    handshake_ts: float = 0.0
    pmkid_ts: float = 0.0
    deauths_sent: int = 0
    score: float = 0.0
    picked_by: str = ""            # "heuristic" | "llm" | "operator"
    pick_reason: str = ""

    def __post_init__(self) -> None:
        self.bssid = mac_norm(self.bssid) or self.bssid
        if not self.vendor:
            self.vendor = oui_vendor(self.bssid)
        if not self.band:
            self.band = "5GHz" if self.frequency >= 4900 else "2.4GHz"

    # -- presentation ------------------------------------------------------
    @property
    def display_name(self) -> str:
        if self.essid:
            return self.essid
        if self.hidden:
            return "<hidden>"
        return f"<{self.bssid[-8:]}>"

    @property
    def signal_bar(self) -> str:
        if self.signal >= -50:
            return "▁▄█"
        if self.signal >= -60:
            return "▁▄▅"
        if self.signal >= -70:
            return "▁▄_"
        if self.signal >= -80:
            return "▁__"
        return "___"

    @property
    def quality(self) -> int:
        """0-100 signal quality, RSSI -> percentage."""
        return int(clamp(2 * (self.signal + 100), 0, 100))

    @property
    def security(self) -> str:
        if self.encryption == "WPA2/WPA3":
            return "WPA2+WPA3"
        return self.encryption

    @property
    def has_handshake(self) -> bool:
        return any(c.kind == "handshake" and c.valid for c in self.captures)

    @property
    def has_pmkid(self) -> bool:
        return any(c.kind == "pmkid" and c.valid for c in self.captures)

    @property
    def cracked(self) -> bool:
        return any(c.password for c in self.captures)

    @property
    def password(self) -> str:
        for cap in self.captures:
            if cap.password:
                return cap.password
        return ""

    @property
    def wps_open(self) -> bool:
        return self.wps and self.wps_locked not in ("locked", "configured")

    @property
    def client_list(self) -> List[Client]:
        return list(self.clients.values())

    def attackable(self, enabled: Optional[List[str]] = None) -> List[str]:
        """Which attack primitives make sense for this AP, best first.

        This is the *advisory* list shown next to a target (and in the report),
        ordered the way the planner would run them: read-only surveys first, the
        attacks that need no client before the ones that do, and the disruptive
        ones last.

        Cached on a fingerprint of everything the list depends on: it is
        serialised into every snapshot (once per AP per UI tick), and the
        naive build scanned the 848-name enabled list for every candidate.
        """
        has_pmkid = self.has_pmkid
        has_handshake = self.has_handshake
        if not enabled:
            enabled_set = _all_attack_names()
            enabled_ref = None
            enabled_key = (0, len(enabled_set))
        else:
            enabled_set = frozenset(enabled)
            enabled_ref = enabled          # pin it: its id() must stay unique
            enabled_key = (id(enabled), len(enabled))
        key = (enabled_key, self.essid, self.encryption, self.auth, self.sae,
               self.pmf, self.wps, self.wps_open, bool(self.clients),
               has_pmkid, has_handshake)
        cached = self.__dict__.get("_atk_cache")
        if cached is not None and cached[0] == key:
            return list(cached[1])

        out: List[str] = []
        seen = set()

        def add(name: str, when: bool = True) -> None:
            if when and name in enabled_set and name not in seen:
                seen.add(name)
                out.append(name)

        # read-only: these change what we know and transmit nothing
        add("ie_audit")
        add("pmf_audit")
        add("hidden_ssid", not (self.essid or "").strip())
        add("pnl_harvest")
        add("tracker", bool(self.clients))
        add("rogue_ap")
        enterprise = (self.encryption in ("WPA-ENTERPRISE", "WPA2-ENTERPRISE",
                                          "ENTERPRISE")
                      or (self.auth or "").upper() in ("MGT", "802.1X", "ENTERPRISE"))
        add("enterprise", enterprise)
        add("rogue_radius", enterprise)
        add("saewolf", bool(self.sae or "WPA3" in (self.encryption or "")))
        # capture
        if self.encryption in ("WPA", "WPA2", "WPA2/WPA3", "WPA3"):
            add("pmkid", not has_pmkid)
            add("pmkid_flood", bool(self.clients) and not has_pmkid)
            add("handshake", not self.sae and not has_handshake)
            add("eapol_logoff", bool(self.clients) and not self.pmf)
        if self.wps and self.wps_open:
            add("wps_pixie")
            add("wps_pin")
        if self.encryption == "WEP":
            add("wep_ivs")
            add("wep_p0841")
            add("wep_chopchop", not self.clients)
            add("wep_fragment", not self.clients)
            add("wep_hirte", bool(self.clients))
        # rogue infrastructure and the denial-of-service tests, last
        add("evil_twin", bool((self.essid or "").strip()) and not enterprise)
        add("karma", not enterprise)
        add("deauth_flood")
        add("auth_flood")
        add("probe_flood")
        add("beacon_flood")
        add("passive")
        self.__dict__["_atk_cache"] = (key, out, enabled_ref)
        return list(out)

    def add_client(self, client: Client) -> bool:
        key = client.mac
        existing = self.clients.get(key)
        if existing:
            existing.last_seen = client.last_seen
            existing.packets = max(existing.packets, client.packets)
            existing.signal = client.signal or existing.signal
            if client.bssid:
                existing.bssid = client.bssid
            for probe in client.probes:
                if probe and probe not in existing.probes:
                    existing.probes.append(probe)
            return False
        self.clients[key] = client
        return True

    # -- engagement bookkeeping (see Session.add_note / tag_ap) ---------- #
    def tag(self, name: str, add: bool = True) -> List[str]:
        """Add or remove a tag; returns the tags on this AP afterwards."""
        name = str(name).strip().lower()[:32]
        if not name:
            return list(self.tags)
        if add:
            if name not in self.tags:
                self.tags.append(name)
        else:
            self.tags = [existing for existing in self.tags if existing != name]
        return list(self.tags)

    def remember(self, kind: str, detail: str = "", **extra: Any) -> Dict[str, Any]:
        """Append one line to this AP's history (newest last, bounded at 50)."""
        entry = {"ts": time.time(), "kind": kind, "detail": detail, **extra}
        self.history.append(entry)
        del self.history[:-50]
        return entry

    @property
    def vendor_key(self) -> str:
        """Dossier key for this AP's vendor (``"AVM"``, ``"TP-Link"``, ...)."""
        from .vendors import _key_for
        return _key_for(self.vendor or "")

    def enrich(self) -> Dict[str, Any]:
        """Add everything that can be derived from the OUI and the SSID.

        Idempotent: safe to call on every scan round.  Returns what it added so
        the caller can log it.
        """
        from .analytics import guess_vendor, identify
        from .vendors import vendor_dossier
        added: Dict[str, Any] = {}
        if not self.vendor:
            guess = guess_vendor(self.essid, self.bssid)
            if guess:
                self.vendor = guess
                added["vendor"] = guess
        if not self.vendor_key:
            key = vendor_dossier(self.bssid).get("key", "") if self.bssid else ""
            if key:
                added["vendor"] = self.vendor or key
        if not self.target_kind:
            self.target_kind = classify_target(self)
            added["target_kind"] = self.target_kind
        if not self.vendor_profile:
            profile = vendor_dossier(self.vendor or self.bssid)
            if profile.get("matched"):
                self.vendor_profile = str(profile.get("key", ""))
                added["vendor_profile"] = self.vendor_profile
        if not self.notes:
            info = identify(self.essid, self.vendor or "")
            if info.get("scheme"):
                self.notes = str(info.get("advice") or info.get("scheme_note") or "")
                added["notes"] = self.notes[:80]
        return added

    def touch(self) -> None:
        self.last_seen = time.time()

    def to_dict(self, detail: bool = False,
                enabled: Optional[List[str]] = None) -> Dict[str, Any]:
        now = time.time()
        data: Dict[str, Any] = {
            "bssid": self.bssid,
            "essid": self.essid,
            "display_name": self.display_name,
            "channel": self.channel,
            "frequency": self.frequency,
            "band": self.band,
            "signal": self.signal,
            "quality": self.quality,
            "encryption": self.encryption,
            "security": self.security,
            "cipher": self.cipher,
            "auth": self.auth,
            "wps": self.wps,
            "wps_locked": self.wps_locked,
            "wps_version": self.wps_version,
            "wps_model": self.wps_model,
            "pmf": self.pmf,
            "sae": self.sae,
            "sai": self.sai,
            "pmf_checked": self.pmf_checked,
            "hidden": self.hidden,
            "vendor": self.vendor,
            "clients": len(self.clients),
            "beacons": self.beacon_count,
            "data": self.data_count,
            "handshake": self.has_handshake,
            "pmkid": self.has_pmkid,
            "cracked": self.cracked,
            "password": self.password,
            "status": self.status,
            "score": round(self.score, 2),
            "picked_by": self.picked_by,
            "pick_reason": self.pick_reason,
            "deauths_sent": self.deauths_sent,
            "age": round(now - self.last_seen, 1),
            "age_first": round(now - self.first_seen, 1),
            "attacks": self.attackable(enabled),
            "captures": [c.to_dict() for c in self.captures],
            "notes": self.notes,
            "tags": list(self.tags),
            "target_kind": self.target_kind,
            "vendor_profile": self.vendor_profile,
        }
        if detail:
            data["clients_list"] = [c.to_dict() for c in self.clients.values()]
            data["attempts"] = [a.to_dict() for a in self.attempts[-25:]]
            data["history"] = list(self.history)
        return data


def classify_target(ap: "AccessPoint") -> str:
    """A coarse label: what *kind* of network this looks like.

    Used for filtering (``wifipilot targets --kind guest``) and reporting; it is
    a heuristic over the data already collected, not a measurement.
    """
    essid = (ap.essid or "").lower()
    if not ap.essid:
        return "hidden"
    if any(token in essid for token in ("guest", "gast", "visitor", "_vip")):
        return "guest"
    if any(token in essid for token in ("iot", "smart", "camera", "cam-", "printer",
                                        "thermostat", "light", "plug")):
        return "iot"
    if "tetra" in essid or "police" in essid or "eduroam" in essid:
        return "public-safety"
    if ap.vendor_key in ("AVM", "TP-Link", "Netgear", "D-Link", "ASUS", "Huawei",
                         "Zyxel", "ARRIS", "Cisco") or ap.encryption in ("WPA2", "WPA", "WPA2/WPA3"):
        if len(ap.clients) > 8:
            return "small-business"
        return "home-router"
    if ap.encryption == "OPEN":
        return "open"
    if ap.encryption == "WPA3":
        return "wpa3-only"
    return "wireless"


@dataclass
class Capture:
    """An artifact: handshake, PMKID or WEP IV dump."""

    kind: str                     # handshake | pmkid | wep_ivs
    bssid: str
    essid: str = ""
    path: str = ""
    valid: bool = False
    tool: str = ""
    created: float = field(default_factory=time.time)
    eapol: int = 0
    size: int = 0
    password: str = ""
    crack_tool: str = ""
    crack_seconds: float = 0.0
    crack_attempts: int = 0
    hash_path: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    #: which stage produced this: attack | manual | imported | demo
    found_in: str = ""
    #: operator note attached to this capture
    note: str = ""

    @property
    def label(self) -> str:
        bits = [self.kind.upper(), self.essid or self.bssid]
        if self.password:
            bits.append(f"PSK={self.password}")
        return " · ".join(x for x in bits if x)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "bssid": self.bssid, "essid": self.essid,
            "found_in": self.found_in, "note": self.note,
            "path": self.path, "hash_path": self.hash_path, "valid": self.valid,
            "tool": self.tool, "created": _iso_of(self.created),
            "created_ts": self.created, "eapol": self.eapol, "size": self.size,
            "password": self.password, "crack_tool": self.crack_tool,
            "crack_seconds": round(self.crack_seconds, 2),
            "crack_attempts": self.crack_attempts, "label": self.label,
            "extra": self.extra,
        }


@dataclass
class Attempt:
    """One run of one attack primitive against one AP."""

    attack: str
    bssid: str
    started: float = field(default_factory=time.time)
    ended: float = 0.0
    status: str = STATUS_RUNNING
    result: str = ""
    capture: Optional[Capture] = None
    tool: str = ""
    command: str = ""
    detail: str = ""
    chosen_by: str = "heuristic"
    reason: str = ""
    #: structured payload the attack produced (survey findings, PIN candidates...)
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return (self.ended or time.time()) - self.started

    @property
    def succeeded(self) -> bool:
        return self.status == STATUS_SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack": self.attack, "bssid": self.bssid,
            "started": self.started, "duration": round(self.duration, 1),
            "status": self.status, "result": self.result, "tool": self.tool,
            "command": self.command, "detail": self.detail,
            "chosen_by": self.chosen_by, "reason": self.reason,
            "capture": self.capture.to_dict() if self.capture else None,
            "extra": self.extra,
        }


@dataclass
class Finding:
    """Something the operator (or the LLM) should care about."""

    kind: str                     # loot | risk | note | advice | error
    title: str
    detail: str = ""
    severity: str = "info"        # info | low | medium | high | critical
    bssid: str = ""
    created: float = field(default_factory=time.time)
    source: str = "core"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "title": self.title, "detail": self.detail,
            "severity": self.severity, "bssid": self.bssid,
            "source": self.source, "created": _iso_of(self.created), "created_ts": self.created,
        }


@dataclass
class SessionStats:
    started: float = field(default_factory=time.time)
    aps_seen: int = 0
    clients_seen: int = 0
    handshakes: int = 0
    pmkids: int = 0
    wps_cracks: int = 0
    wep_cracks: int = 0
    passwords: int = 0
    attacks_run: int = 0
    attacks_failed: int = 0
    deauths: int = 0
    crack_attempts: int = 0
    # -- intelligence gathered without a single injection ------------------
    hidden_revealed: int = 0           # SSIDs learned from hidden networks
    probes_seen: int = 0               # probe requests from clients (PNL)
    rogue_twins: int = 0               # twin/rogue patterns reported
    enterprise_surveys: int = 0        # 802.1X exchanges captured
    rogue_radius: int = 0              # rogue-RADIUS attempts that reached a client
    sae_captures: int = 0              # SAE exchanges captured for the report
    pmf_audits: int = 0                # RSN/PMF audits run
    twins_run: int = 0                 # evil twins that lured at least one station
    floods_run: int = 0                # denial-of-service tests run
    wep_enablers: int = 0              # WEP injection techniques that succeeded
    ie_audits: int = 0                 # beacon-element configuration audits run
    pnl_harvests: int = 0              # preferred-network-list harvests
    logoffs: int = 0                   # EAPOL-Logoff attempts delivered
    offline_audits: int = 0            # analyses that never transmitted anything
    rogue_detections: int = 0          # rogue/twin patterns found in a capture
    lure_runs: int = 0                 # channel-switch / SSID-confusion lures sent
    wps_probes: int = 0                # WPS lockout/PIN probes answered maybe
    wps_lockouts_missing: int = 0      # APs found without a WPS lockout policy
    karma_runs: int = 0                # Karma attempts run
    stations_tracked: int = 0          # stations followed for a signal trend
    probing_clients: int = 0           # clients whose PNL was read out of a capture
    pmk_hits: int = 0                  # captures "cracked" from the PMK cache
    llm_calls: int = 0
    llm_tokens: int = 0
    llm_errors: int = 0
    llm_cost: float = 0.0              # USD spent on a paid provider (OpenRouter)

    @property
    def uptime(self) -> float:
        return time.time() - self.started

    @property
    def loot(self) -> int:
        return self.handshakes + self.pmkids + self.wps_cracks + self.wep_cracks

    def to_dict(self) -> Dict[str, Any]:
        # shallow field walk, not asdict(): asdict deep-copies the whole
        # object (~170µs) and this runs on every snapshot tick, while every
        # field here is a scalar.  "started" is the session's real start —
        # it used to be stamped with the serialisation moment.
        global _STATS_FIELD_NAMES
        if _STATS_FIELD_NAMES is None:
            _STATS_FIELD_NAMES = tuple(f.name for f in fields(self))
        data = {name: getattr(self, name) for name in _STATS_FIELD_NAMES}
        data["uptime"] = round(self.uptime, 1)
        data["loot"] = self.loot
        data["started"] = _iso_of(self.started)
        return data


def loot_filename(ap: AccessPoint, cap: Capture, ext: str = ".cap") -> str:
    base = slugify(f"{cap.essid or 'hidden'}_{ap.bssid.replace(':', '')}")
    return base + ext
