// GENERATED FILE — do not edit by hand.
// Regenerate with: node scripts/generate-ocsf-reference.mjs 1.9.0
// Source: https://schema.ocsf.io/api/1.9.0 (OCSF 1.9.0, fetched at generation time)
//
// Committed rather than fetched at runtime: the MCP server runs next to
// deployments that have no outbound internet, and a schema catalog that
// silently changes underneath a session is worse than one that changes in a
// reviewed diff.

export const OCSF_VERSION = "1.9.0";

export interface OcsfClassSummary {
  uid: number;
  caption: string;
  name: string;
  category: string;
  categoryUid: number;
  /** Set when the class comes from an OCSF extension (e.g. `win`), not core. */
  extension?: string | null;
  /** Present when OCSF retired this class. Do not emit it from a new parser. */
  deprecated?: { since: string | null; supersededBy: string[]; message: string };
}

export interface OcsfActivity {
  id: number;
  caption: string;
}

export interface OcsfClassDetail extends OcsfClassSummary {
  description: string;
  activities: OcsfActivity[];
}

export const OCSF_CATEGORIES: { uid: number; caption: string }[] = [
  {
    "uid": 1,
    "caption": "System Activity"
  },
  {
    "uid": 2,
    "caption": "Findings"
  },
  {
    "uid": 3,
    "caption": "Identity & Access Management"
  },
  {
    "uid": 4,
    "caption": "Network Activity"
  },
  {
    "uid": 5,
    "caption": "Discovery"
  },
  {
    "uid": 6,
    "caption": "Application Activity"
  },
  {
    "uid": 7,
    "caption": "Remediation"
  },
  {
    "uid": 8,
    "caption": "Unmanned Systems"
  }
];

/** Every class in OCSF 1.9.0. Retired ones carry a `deprecated` marker. */
export const OCSF_CLASSES: OcsfClassSummary[] = [
  {
    "uid": 1001,
    "caption": "File System Activity",
    "name": "file_activity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 1002,
    "caption": "Kernel Extension Activity",
    "name": "kernel_extension_activity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 1003,
    "caption": "Kernel Activity",
    "name": "kernel_activity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 1004,
    "caption": "Memory Activity",
    "name": "memory_activity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 1005,
    "caption": "Module Activity",
    "name": "module_activity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 1006,
    "caption": "Scheduled Job Activity",
    "name": "scheduled_job_activity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 1007,
    "caption": "Process Activity",
    "name": "process_activity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 1008,
    "caption": "Event Log Activity",
    "name": "event_log_actvity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 1009,
    "caption": "Script Activity",
    "name": "script_activity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 1010,
    "caption": "Peripheral Activity",
    "name": "peripheral_activity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 1011,
    "caption": "Device Power State Activity",
    "name": "device_power_state_activity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 1012,
    "caption": "Clipboard Activity",
    "name": "clipboard_activity",
    "category": "System Activity",
    "categoryUid": 1
  },
  {
    "uid": 2001,
    "caption": "Security Finding",
    "name": "security_finding",
    "category": "Findings",
    "categoryUid": 2,
    "deprecated": {
      "since": "1.1.0",
      "supersededBy": [
        "vulnerability_finding",
        "compliance_finding",
        "detection_finding",
        "incident_finding",
        "data_security_finding"
      ],
      "message": "Use the new specific classes according to the use-case: vulnerability_finding, compliance_finding, detection_finding, incident_finding, data_security_finding."
    }
  },
  {
    "uid": 2002,
    "caption": "Vulnerability Finding",
    "name": "vulnerability_finding",
    "category": "Findings",
    "categoryUid": 2
  },
  {
    "uid": 2003,
    "caption": "Compliance Finding",
    "name": "compliance_finding",
    "category": "Findings",
    "categoryUid": 2
  },
  {
    "uid": 2004,
    "caption": "Detection Finding",
    "name": "detection_finding",
    "category": "Findings",
    "categoryUid": 2
  },
  {
    "uid": 2005,
    "caption": "Incident Finding",
    "name": "incident_finding",
    "category": "Findings",
    "categoryUid": 2
  },
  {
    "uid": 2006,
    "caption": "Data Security Finding",
    "name": "data_security_finding",
    "category": "Findings",
    "categoryUid": 2
  },
  {
    "uid": 2007,
    "caption": "Application Security Posture Finding",
    "name": "application_security_posture_finding",
    "category": "Findings",
    "categoryUid": 2
  },
  {
    "uid": 2008,
    "caption": "IAM Analysis Finding",
    "name": "iam_analysis_finding",
    "category": "Findings",
    "categoryUid": 2
  },
  {
    "uid": 3001,
    "caption": "Account Change",
    "name": "account_change",
    "category": "Identity & Access Management",
    "categoryUid": 3,
    "deprecated": {
      "since": "1.9.0",
      "supersededBy": [
        "user_management"
      ],
      "message": "Use the user_management class instead."
    }
  },
  {
    "uid": 3002,
    "caption": "Authentication",
    "name": "authentication",
    "category": "Identity & Access Management",
    "categoryUid": 3
  },
  {
    "uid": 3003,
    "caption": "Authorize Session",
    "name": "authorize_session",
    "category": "Identity & Access Management",
    "categoryUid": 3
  },
  {
    "uid": 3004,
    "caption": "Entity Management",
    "name": "entity_management",
    "category": "Identity & Access Management",
    "categoryUid": 3
  },
  {
    "uid": 3005,
    "caption": "User Access Management",
    "name": "user_access",
    "category": "Identity & Access Management",
    "categoryUid": 3,
    "deprecated": {
      "since": "1.9.0",
      "supersededBy": [
        "user_management"
      ],
      "message": "Use the user_management class instead."
    }
  },
  {
    "uid": 3006,
    "caption": "Group Management",
    "name": "group_management",
    "category": "Identity & Access Management",
    "categoryUid": 3
  },
  {
    "uid": 3007,
    "caption": "User Management",
    "name": "user_management",
    "category": "Identity & Access Management",
    "categoryUid": 3
  },
  {
    "uid": 3008,
    "caption": "Role Management",
    "name": "role_management",
    "category": "Identity & Access Management",
    "categoryUid": 3
  },
  {
    "uid": 4001,
    "caption": "Network Activity",
    "name": "network_activity",
    "category": "Network Activity",
    "categoryUid": 4
  },
  {
    "uid": 4002,
    "caption": "HTTP Activity",
    "name": "http_activity",
    "category": "Network Activity",
    "categoryUid": 4
  },
  {
    "uid": 4003,
    "caption": "DNS Activity",
    "name": "dns_activity",
    "category": "Network Activity",
    "categoryUid": 4
  },
  {
    "uid": 4004,
    "caption": "DHCP Activity",
    "name": "dhcp_activity",
    "category": "Network Activity",
    "categoryUid": 4
  },
  {
    "uid": 4005,
    "caption": "RDP Activity",
    "name": "rdp_activity",
    "category": "Network Activity",
    "categoryUid": 4
  },
  {
    "uid": 4006,
    "caption": "SMB Activity",
    "name": "smb_activity",
    "category": "Network Activity",
    "categoryUid": 4
  },
  {
    "uid": 4007,
    "caption": "SSH Activity",
    "name": "ssh_activity",
    "category": "Network Activity",
    "categoryUid": 4
  },
  {
    "uid": 4008,
    "caption": "FTP Activity",
    "name": "ftp_activity",
    "category": "Network Activity",
    "categoryUid": 4
  },
  {
    "uid": 4009,
    "caption": "Email Activity",
    "name": "email_activity",
    "category": "Network Activity",
    "categoryUid": 4
  },
  {
    "uid": 4010,
    "caption": "Network File Activity",
    "name": "network_file_activity",
    "category": "Network Activity",
    "categoryUid": 4,
    "deprecated": {
      "since": "1.1.0",
      "supersededBy": [
        "file_hosting"
      ],
      "message": "Use the new file_hosting class in the Application category."
    }
  },
  {
    "uid": 4011,
    "caption": "Email File Activity",
    "name": "email_file_activity",
    "category": "Network Activity",
    "categoryUid": 4,
    "deprecated": {
      "since": "1.3.0",
      "supersededBy": [
        "email_activity"
      ],
      "message": "Use the email_activity class with the email.files[] array instead."
    }
  },
  {
    "uid": 4012,
    "caption": "Email URL Activity",
    "name": "email_url_activity",
    "category": "Network Activity",
    "categoryUid": 4,
    "deprecated": {
      "since": "1.3.0",
      "supersededBy": [
        "email_activity"
      ],
      "message": "Use the email_activity class with the email.urls[] array instead."
    }
  },
  {
    "uid": 4013,
    "caption": "NTP Activity",
    "name": "ntp_activity",
    "category": "Network Activity",
    "categoryUid": 4
  },
  {
    "uid": 4014,
    "caption": "Tunnel Activity",
    "name": "tunnel_activity",
    "category": "Network Activity",
    "categoryUid": 4
  },
  {
    "uid": 5001,
    "caption": "Device Inventory Info",
    "name": "inventory_info",
    "category": "Discovery",
    "categoryUid": 5
  },
  {
    "uid": 5002,
    "caption": "Device Config State",
    "name": "config_state",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "compliance_finding"
      ],
      "message": "Use compliance_finding class."
    }
  },
  {
    "uid": 5003,
    "caption": "User Inventory Info",
    "name": "user_inventory",
    "category": "Discovery",
    "categoryUid": 5
  },
  {
    "uid": 5004,
    "caption": "Operating System Patch State",
    "name": "patch_state",
    "category": "Discovery",
    "categoryUid": 5
  },
  {
    "uid": 5006,
    "caption": "Kernel Object Query",
    "name": "kernel_object_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5007,
    "caption": "File Query",
    "name": "file_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5008,
    "caption": "Folder Query",
    "name": "folder_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5009,
    "caption": "Admin Group Query",
    "name": "admin_group_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5010,
    "caption": "Job Query",
    "name": "job_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5011,
    "caption": "Module Query",
    "name": "module_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5012,
    "caption": "Network Connection Query",
    "name": "network_connection_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5013,
    "caption": "Networks Query",
    "name": "networks_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5014,
    "caption": "Peripheral Device Query",
    "name": "peripheral_device_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5015,
    "caption": "Process Query",
    "name": "process_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5016,
    "caption": "Service Query",
    "name": "service_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5017,
    "caption": "User Session Query",
    "name": "session_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5018,
    "caption": "User Query",
    "name": "user_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5019,
    "caption": "Device Config State Change",
    "name": "device_config_state_change",
    "category": "Discovery",
    "categoryUid": 5
  },
  {
    "uid": 5020,
    "caption": "Software Inventory Info",
    "name": "software_info",
    "category": "Discovery",
    "categoryUid": 5
  },
  {
    "uid": 5021,
    "caption": "OSINT Inventory Info",
    "name": "osint_inventory_info",
    "category": "Discovery",
    "categoryUid": 5
  },
  {
    "uid": 5022,
    "caption": "Startup Item Query",
    "name": "startup_item_query",
    "category": "Discovery",
    "categoryUid": 5,
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class."
    }
  },
  {
    "uid": 5023,
    "caption": "Cloud Resources Inventory Info",
    "name": "cloud_resources_inventory_info",
    "category": "Discovery",
    "categoryUid": 5
  },
  {
    "uid": 5040,
    "caption": "Live Evidence Info",
    "name": "evidence_info",
    "category": "Discovery",
    "categoryUid": 5
  },
  {
    "uid": 6001,
    "caption": "Web Resources Activity",
    "name": "web_resources_activity",
    "category": "Application Activity",
    "categoryUid": 6
  },
  {
    "uid": 6002,
    "caption": "Application Lifecycle",
    "name": "application_lifecycle",
    "category": "Application Activity",
    "categoryUid": 6
  },
  {
    "uid": 6003,
    "caption": "API Activity",
    "name": "api_activity",
    "category": "Application Activity",
    "categoryUid": 6
  },
  {
    "uid": 6004,
    "caption": "Web Resource Access Activity",
    "name": "web_resource_access_activity",
    "category": "Application Activity",
    "categoryUid": 6,
    "deprecated": {
      "since": "1.1.0",
      "supersededBy": [
        "web_resources_activity"
      ],
      "message": "Use the web_resources_activity class with the security_control and/or network_proxy profile instead."
    }
  },
  {
    "uid": 6005,
    "caption": "Datastore Activity",
    "name": "datastore_activity",
    "category": "Application Activity",
    "categoryUid": 6
  },
  {
    "uid": 6006,
    "caption": "File Hosting Activity",
    "name": "file_hosting",
    "category": "Application Activity",
    "categoryUid": 6
  },
  {
    "uid": 6007,
    "caption": "Scan Activity",
    "name": "scan_activity",
    "category": "Application Activity",
    "categoryUid": 6
  },
  {
    "uid": 6008,
    "caption": "Application Error",
    "name": "application_error",
    "category": "Application Activity",
    "categoryUid": 6
  },
  {
    "uid": 7001,
    "caption": "Remediation Activity",
    "name": "remediation_activity",
    "category": "Remediation",
    "categoryUid": 7
  },
  {
    "uid": 7002,
    "caption": "File Remediation Activity",
    "name": "file_remediation_activity",
    "category": "Remediation",
    "categoryUid": 7
  },
  {
    "uid": 7003,
    "caption": "Process Remediation Activity",
    "name": "process_remediation_activity",
    "category": "Remediation",
    "categoryUid": 7
  },
  {
    "uid": 7004,
    "caption": "Network Remediation Activity",
    "name": "network_remediation_activity",
    "category": "Remediation",
    "categoryUid": 7
  },
  {
    "uid": 8001,
    "caption": "Drone Flights Activity",
    "name": "drone_flights_activity",
    "category": "Unmanned Systems",
    "categoryUid": 8
  },
  {
    "uid": 8002,
    "caption": "Airborne Broadcast Activity",
    "name": "airborne_broadcast_activity",
    "category": "Unmanned Systems",
    "categoryUid": 8
  },
  {
    "uid": 201001,
    "caption": "Registry Key Activity",
    "name": "registry_key_activity",
    "category": "System Activity",
    "categoryUid": 1,
    "extension": "win"
  },
  {
    "uid": 201002,
    "caption": "Registry Value Activity",
    "name": "registry_value_activity",
    "category": "System Activity",
    "categoryUid": 1,
    "extension": "win"
  },
  {
    "uid": 201003,
    "caption": "Windows Resource Activity",
    "name": "windows_resource_activity",
    "category": "System Activity",
    "categoryUid": 1,
    "extension": "win"
  },
  {
    "uid": 201004,
    "caption": "Windows Service Activity",
    "name": "windows_service_activity",
    "category": "System Activity",
    "categoryUid": 1,
    "extension": "win"
  },
  {
    "uid": 205004,
    "caption": "Registry Key Query",
    "name": "registry_key_query",
    "category": "Discovery",
    "categoryUid": 5,
    "extension": "win",
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class instead. Populate query_evidence.reg_key and set query_type_id to Registry Key."
    }
  },
  {
    "uid": 205005,
    "caption": "Registry Value Query",
    "name": "registry_value_query",
    "category": "Discovery",
    "categoryUid": 5,
    "extension": "win",
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class instead. Populate query_evidence.reg_value and set query_type_id to Registry Value."
    }
  },
  {
    "uid": 205019,
    "caption": "Prefetch Query",
    "name": "prefetch_query",
    "category": "Discovery",
    "categoryUid": 5,
    "extension": "win",
    "deprecated": {
      "since": "1.5.0",
      "supersededBy": [
        "evidence_info"
      ],
      "message": "Use the evidence_info class instead. Populate query_evidence.file and set query_type_id to Prefetch."
    }
  }
];

/** Classes nano's own parsers emit, expanded with their activity enums. */
export const OCSF_DETAILED_CLASSES: OcsfClassDetail[] = [
  {
    "uid": 1001,
    "caption": "File System Activity",
    "name": "file_activity",
    "extension": null,
    "category": "System Activity",
    "categoryUid": 1,
    "description": "File System Activity events report when a process performs an action on a file or folder.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Create"
      },
      {
        "id": 2,
        "caption": "Read"
      },
      {
        "id": 3,
        "caption": "Update"
      },
      {
        "id": 4,
        "caption": "Delete"
      },
      {
        "id": 5,
        "caption": "Rename"
      },
      {
        "id": 6,
        "caption": "Set Attributes"
      },
      {
        "id": 7,
        "caption": "Set Security"
      },
      {
        "id": 8,
        "caption": "Get Attributes"
      },
      {
        "id": 9,
        "caption": "Get Security"
      },
      {
        "id": 10,
        "caption": "Encrypt"
      },
      {
        "id": 11,
        "caption": "Decrypt"
      },
      {
        "id": 12,
        "caption": "Mount"
      },
      {
        "id": 13,
        "caption": "Unmount"
      },
      {
        "id": 14,
        "caption": "Open"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 1005,
    "caption": "Module Activity",
    "name": "module_activity",
    "extension": null,
    "category": "System Activity",
    "categoryUid": 1,
    "description": "Module Activity events report when an endpoint process acts on a module.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Load"
      },
      {
        "id": 2,
        "caption": "Unload"
      },
      {
        "id": 3,
        "caption": "Invoke"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 1007,
    "caption": "Process Activity",
    "name": "process_activity",
    "extension": null,
    "category": "System Activity",
    "categoryUid": 1,
    "description": "Process Activity events report when a process launches, injects, opens or terminates another process, successful or otherwise.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Launch"
      },
      {
        "id": 2,
        "caption": "Terminate"
      },
      {
        "id": 3,
        "caption": "Open"
      },
      {
        "id": 4,
        "caption": "Inject"
      },
      {
        "id": 5,
        "caption": "Set User ID"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 2004,
    "caption": "Detection Finding",
    "name": "detection_finding",
    "extension": null,
    "category": "Findings",
    "categoryUid": 2,
    "description": "A Detection Finding describes detections or alerts generated by security products using correlation engines, detection engines or other methodologies. Note: If the event producer is a security control, the Security Control profile should be applied and its attacks information, if present, should be duplicated into the finding_info object. Note: If the Finding is an incident, i.e. requires incident workflow, also apply the Incident profile or aggregate the finding into an Incident Finding.Note: Findings are mutable and as such have a lifecycle, via Update activities. When modeling atomic alerts, you are encouraged to consider using the Security Control profile with the activity event associated with the alert. See the referenced article below.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Create"
      },
      {
        "id": 2,
        "caption": "Update"
      },
      {
        "id": 3,
        "caption": "Close"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 3001,
    "caption": "Account Change",
    "name": "account_change",
    "extension": null,
    "category": "Identity & Access Management",
    "categoryUid": 3,
    "description": "Account Change events report when specific user account management tasks are performed, such as a user/role being created or role assigned, changed, deleted, renamed, disabled, enabled, locked out or unlocked.",
    "deprecated": {
      "since": "1.9.0",
      "supersededBy": [
        "user_management"
      ],
      "message": "Use the user_management class instead."
    },
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Create"
      },
      {
        "id": 2,
        "caption": "Enable"
      },
      {
        "id": 3,
        "caption": "Password Change"
      },
      {
        "id": 4,
        "caption": "Password Reset"
      },
      {
        "id": 5,
        "caption": "Disable"
      },
      {
        "id": 6,
        "caption": "Delete"
      },
      {
        "id": 7,
        "caption": "Attach Policy"
      },
      {
        "id": 8,
        "caption": "Detach Policy"
      },
      {
        "id": 9,
        "caption": "Lock"
      },
      {
        "id": 10,
        "caption": "MFA Factor Enable"
      },
      {
        "id": 11,
        "caption": "MFA Factor Disable"
      },
      {
        "id": 12,
        "caption": "Unlock"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 3002,
    "caption": "Authentication",
    "name": "authentication",
    "extension": null,
    "category": "Identity & Access Management",
    "categoryUid": 3,
    "description": "Authentication events report authentication session activities, including user attempts to log on or log off, regardless of success, as well as other key stages within the authentication process. These events are typically generated by authentication services, such as Kerberos, OIDC, or SAML, and may include information about the user, the authentication method used, and the status of the authentication attempt.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Logon"
      },
      {
        "id": 2,
        "caption": "Logoff"
      },
      {
        "id": 3,
        "caption": "Authentication Ticket"
      },
      {
        "id": 4,
        "caption": "Service Ticket Request"
      },
      {
        "id": 5,
        "caption": "Service Ticket Renew"
      },
      {
        "id": 6,
        "caption": "Preauth"
      },
      {
        "id": 7,
        "caption": "Account Switch"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 3004,
    "caption": "Entity Management",
    "name": "entity_management",
    "extension": null,
    "category": "Identity & Access Management",
    "categoryUid": 3,
    "description": "Entity Management events report activity by a managed client, a micro service, or a user at a management console. The activity can be a create, read, update, and delete operation on a managed entity.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Create"
      },
      {
        "id": 2,
        "caption": "Read"
      },
      {
        "id": 3,
        "caption": "Update"
      },
      {
        "id": 4,
        "caption": "Delete"
      },
      {
        "id": 5,
        "caption": "Move"
      },
      {
        "id": 6,
        "caption": "Enroll"
      },
      {
        "id": 7,
        "caption": "Unenroll"
      },
      {
        "id": 8,
        "caption": "Enable"
      },
      {
        "id": 9,
        "caption": "Disable"
      },
      {
        "id": 10,
        "caption": "Activate"
      },
      {
        "id": 11,
        "caption": "Deactivate"
      },
      {
        "id": 12,
        "caption": "Suspend"
      },
      {
        "id": 13,
        "caption": "Resume"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 3007,
    "caption": "User Management",
    "name": "user_management",
    "extension": null,
    "category": "Identity & Access Management",
    "categoryUid": 3,
    "description": "User Management events report lifecycle management of a user and account management tasks that are performed, such as a password change or reset, a user being created, updated, deleted, disabled, enabled, locked out or unlocked. There are two ways updates to the state of a user may be expressed: Using the Update activity, for example when updating multiple items at one time, the updated_user reflects the changes made to user. Using discrete activities, such as Assign Privileges the state change is expressed by the privileges attribute. Optionally, on successful changes, the updated_user reflects the new state of the user.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Create"
      },
      {
        "id": 2,
        "caption": "Update"
      },
      {
        "id": 3,
        "caption": "Delete"
      },
      {
        "id": 4,
        "caption": "Enable"
      },
      {
        "id": 5,
        "caption": "Disable"
      },
      {
        "id": 6,
        "caption": "Lock"
      },
      {
        "id": 7,
        "caption": "Unlock"
      },
      {
        "id": 8,
        "caption": "Password Change"
      },
      {
        "id": 9,
        "caption": "Password Reset"
      },
      {
        "id": 10,
        "caption": "Attach Policies"
      },
      {
        "id": 11,
        "caption": "Detach Policies"
      },
      {
        "id": 12,
        "caption": "Enable MFA Factors"
      },
      {
        "id": 13,
        "caption": "Disable MFA Factors"
      },
      {
        "id": 14,
        "caption": "Assign Privileges"
      },
      {
        "id": 15,
        "caption": "Remove Privileges"
      },
      {
        "id": 16,
        "caption": "Assign Roles"
      },
      {
        "id": 17,
        "caption": "Remove Roles"
      },
      {
        "id": 18,
        "caption": "Add Programmatic Credentials"
      },
      {
        "id": 19,
        "caption": "Remove Programmatic Credentials"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 4001,
    "caption": "Network Activity",
    "name": "network_activity",
    "extension": null,
    "category": "Network Activity",
    "categoryUid": 4,
    "description": "Network Activity events report network connection and traffic activity.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Open"
      },
      {
        "id": 2,
        "caption": "Close"
      },
      {
        "id": 3,
        "caption": "Reset"
      },
      {
        "id": 4,
        "caption": "Fail"
      },
      {
        "id": 5,
        "caption": "Refuse"
      },
      {
        "id": 6,
        "caption": "Traffic"
      },
      {
        "id": 7,
        "caption": "Listen"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 4002,
    "caption": "HTTP Activity",
    "name": "http_activity",
    "extension": null,
    "category": "Network Activity",
    "categoryUid": 4,
    "description": "HTTP Activity events report HTTP connection and traffic information.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Connect"
      },
      {
        "id": 2,
        "caption": "Delete"
      },
      {
        "id": 3,
        "caption": "Get"
      },
      {
        "id": 4,
        "caption": "Head"
      },
      {
        "id": 5,
        "caption": "Options"
      },
      {
        "id": 6,
        "caption": "Post"
      },
      {
        "id": 7,
        "caption": "Put"
      },
      {
        "id": 8,
        "caption": "Trace"
      },
      {
        "id": 9,
        "caption": "Patch"
      },
      {
        "id": 10,
        "caption": "ACL"
      },
      {
        "id": 11,
        "caption": "Baseline Control"
      },
      {
        "id": 12,
        "caption": "Bind"
      },
      {
        "id": 13,
        "caption": "Check In"
      },
      {
        "id": 14,
        "caption": "Check Out"
      },
      {
        "id": 15,
        "caption": "Copy"
      },
      {
        "id": 16,
        "caption": "Label"
      },
      {
        "id": 17,
        "caption": "Link"
      },
      {
        "id": 18,
        "caption": "Lock"
      },
      {
        "id": 19,
        "caption": "Merge"
      },
      {
        "id": 20,
        "caption": "Make Activity"
      },
      {
        "id": 21,
        "caption": "Make Calendar"
      },
      {
        "id": 22,
        "caption": "Make Collection"
      },
      {
        "id": 23,
        "caption": "Make Redirect Reference"
      },
      {
        "id": 24,
        "caption": "Make Workspace"
      },
      {
        "id": 25,
        "caption": "Move"
      },
      {
        "id": 26,
        "caption": "Order Patch"
      },
      {
        "id": 27,
        "caption": "PRI"
      },
      {
        "id": 28,
        "caption": "Property Find"
      },
      {
        "id": 29,
        "caption": "Property Patch"
      },
      {
        "id": 30,
        "caption": "Query"
      },
      {
        "id": 31,
        "caption": "Rebind"
      },
      {
        "id": 32,
        "caption": "Report"
      },
      {
        "id": 33,
        "caption": "Search"
      },
      {
        "id": 34,
        "caption": "Unbind"
      },
      {
        "id": 35,
        "caption": "Un-Check Out"
      },
      {
        "id": 36,
        "caption": "Unlink"
      },
      {
        "id": 37,
        "caption": "Unlock"
      },
      {
        "id": 38,
        "caption": "Update"
      },
      {
        "id": 39,
        "caption": "Update Redirect Reference"
      },
      {
        "id": 40,
        "caption": "Version Control"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 4003,
    "caption": "DNS Activity",
    "name": "dns_activity",
    "extension": null,
    "category": "Network Activity",
    "categoryUid": 4,
    "description": "DNS Activity events report DNS queries and answers as seen on the network.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Query"
      },
      {
        "id": 2,
        "caption": "Response"
      },
      {
        "id": 6,
        "caption": "Traffic"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 4004,
    "caption": "DHCP Activity",
    "name": "dhcp_activity",
    "extension": null,
    "category": "Network Activity",
    "categoryUid": 4,
    "description": "DHCP Activity events report MAC to IP assignment via DHCP from a client or server.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Discover"
      },
      {
        "id": 2,
        "caption": "Offer"
      },
      {
        "id": 3,
        "caption": "Request"
      },
      {
        "id": 4,
        "caption": "Decline"
      },
      {
        "id": 5,
        "caption": "Ack"
      },
      {
        "id": 6,
        "caption": "Nak"
      },
      {
        "id": 7,
        "caption": "Release"
      },
      {
        "id": 8,
        "caption": "Inform"
      },
      {
        "id": 9,
        "caption": "Expire"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 6003,
    "caption": "API Activity",
    "name": "api_activity",
    "extension": null,
    "category": "Application Activity",
    "categoryUid": 6,
    "description": "API events describe general CRUD (Create, Read, Update, Delete) API activities, e.g. (AWS Cloudtrail)",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Create"
      },
      {
        "id": 2,
        "caption": "Read"
      },
      {
        "id": 3,
        "caption": "Update"
      },
      {
        "id": 4,
        "caption": "Delete"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 201001,
    "caption": "Registry Key Activity",
    "name": "registry_key_activity",
    "extension": "win",
    "category": "System Activity",
    "categoryUid": 1,
    "description": "Registry Key Activity events report when a process performs an action on a Windows registry key.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Create"
      },
      {
        "id": 2,
        "caption": "Read"
      },
      {
        "id": 3,
        "caption": "Modify"
      },
      {
        "id": 4,
        "caption": "Delete"
      },
      {
        "id": 5,
        "caption": "Rename"
      },
      {
        "id": 6,
        "caption": "Set Security"
      },
      {
        "id": 7,
        "caption": "Restore"
      },
      {
        "id": 8,
        "caption": "Import"
      },
      {
        "id": 9,
        "caption": "Export"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  },
  {
    "uid": 201002,
    "caption": "Registry Value Activity",
    "name": "registry_value_activity",
    "extension": "win",
    "category": "System Activity",
    "categoryUid": 1,
    "description": "Registry Value Activity events reports when a process performs an action on a Windows registry value.",
    "activities": [
      {
        "id": 0,
        "caption": "Unknown"
      },
      {
        "id": 1,
        "caption": "Get"
      },
      {
        "id": 2,
        "caption": "Set"
      },
      {
        "id": 3,
        "caption": "Modify"
      },
      {
        "id": 4,
        "caption": "Delete"
      },
      {
        "id": 99,
        "caption": "Other"
      }
    ]
  }
];
