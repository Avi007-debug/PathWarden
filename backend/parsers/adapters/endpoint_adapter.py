"""Windows Security Event Log adapter for Winlogbeat/ECS JSONL format.

What this adapter covers:
    Windows Security Event Logs exported via Winlogbeat produce deeply nested
    JSONL records. This adapter flattens and maps them to canonical fields,
    handling each critical Event ID individually because the `event_data`
    structure is completely different per event type.

    Event IDs handled (directly relevant to the 29 planted incidents):
      4624 — Successful logon      (lateral movement, impossible travel)
      4625 — Failed logon          (brute-force, password spray, Kerberos failures)
      4648 — Explicit credential   (pass-the-hash, RunAs)
      4688 — Process creation      (web shell execution, C2 agent, cmd/powershell)
      4697 — Service installed     (remote service execution T1569.002)
      4720 — User account created  (rogue admin T1136.001)
      4728 — Member added to group (privilege escalation, domain admin creation)
      4769 — Kerberos TGS request  (Kerberoasting T1558.003)
      4776 — NTLM auth             (Pass-the-Hash, credential stuffing)
      5140 — Network share access  (DCERPC named pipe enumeration T1135)
      5145 — Share object access   (named pipe access: srvsvc, samr, lsarpc)
      7045 — Service installed     (SC Manager, PsExec service creation)

Winlogbeat/ECS structure:
    {
      "@timestamp"   : "2026-10-26T21:29:21.000Z",
      "winlog": {
        "event_id"     : 4769,
        "computer_name": "DC01",
        "channel"      : "Security",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "record_id"    : 12345,
        "event_data"   : {
          "TargetUserName"      : "Rakes",
          "ServiceName"         : "MSSQLSvc/sqlserver.corp.local",
          "TicketEncryptionType": "0x17",
          "IpAddress"           : "::ffff:10.10.10.77",
        }
      },
      "host": {"name": "DC01"},
      "user": {"name": "Rakes", "domain": "CORP"},
      "log" : {"level": "information"}
    }
"""

from typing import Any, Dict, Optional, Tuple

from common.enums import ParseStatus, Outcome


class EndpointAdapter:
    """Maps Winlogbeat/ECS JSONL records to canonical PathWarden event fields.

    The adapt() method dispatches to an event-ID-specific handler. Each handler
    knows exactly which event_data fields carry the relevant information for
    that Windows event type.
    """

    def adapt(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a parsed Windows JSONL record to canonical-ready fields.

        Args:
            parsed: Output of JSONLParser.parse_record() — a raw Python dict
                    representing one Windows log event in Winlogbeat/ECS format.

        Returns:
            Dict with canonical field names + preserved unknown fields for `extra`.
        """
        if parsed.get("parse_status") == ParseStatus.MALFORMED.value:
            # Pass through malformed records unchanged
            return parsed

        # ── Extract Winlogbeat/ECS common fields ──────────────────────────────
        winlog     = parsed.get("winlog") or {}
        event_data = winlog.get("event_data") or {}
        user_obj   = parsed.get("user") or {}
        host_obj   = parsed.get("host") or {}
        log_obj    = parsed.get("log") or {}

        # Primary fields always available across all event IDs
        event_id    = self._to_int(winlog.get("event_id") or parsed.get("event_id"))
        computer    = winlog.get("computer_name") or host_obj.get("name")
        channel     = winlog.get("channel")
        provider    = winlog.get("provider_name")
        record_id   = winlog.get("record_id") or winlog.get("record_number")
        process_pid = self._to_int(winlog.get("process", {}).get("pid"))

        # Timestamp
        event_ts_original = parsed.get("@timestamp") or parsed.get("timestamp")

        # ── Dispatch to event-specific handler ────────────────────────────────
        specific = self._handle_event(event_id, event_data, user_obj, winlog)

        # ── Build base canonical dict ─────────────────────────────────────────
        result: Dict[str, Any] = {
            "event_ts_original"  : event_ts_original,
            "event_ts"           : event_ts_original,
            "source_event_id"    : str(event_id) if event_id else None,
            "event_category"     : specific.get("event_category"),
            "event_type"         : specific.get("event_type"),
            "action"             : specific.get("action"),
            "outcome"            : specific.get("outcome"),
            "host_name"          : computer,
            "user_name"          : specific.get("user_name") or user_obj.get("name"),
            "user_id"            : specific.get("user_id"),
            "src_ip"             : self._clean_ip(specific.get("src_ip")),
            "src_port"           : specific.get("src_port"),
            "dst_ip"             : specific.get("dst_ip"),
            "dst_port"           : specific.get("dst_port"),
            "network_protocol"   : specific.get("network_protocol"),
            "process_id"         : specific.get("process_id"),
            "parent_process_id"  : specific.get("parent_process_id"),
            "process_entity_id"  : specific.get("process_entity_id"),
            "session_id"         : specific.get("session_id"),
            "sensor_id"          : parsed.get("agent", {}).get("id") if isinstance(parsed.get("agent"), dict) else None,
            "parse_status"       : parsed.get("parse_status", ParseStatus.PARSED.value),
            # Windows-specific fields for detection rules — go into extra
            "win_event_id"       : event_id,
            "win_channel"        : channel,
            "win_provider"       : provider,
            "win_record_id"      : record_id,
            "win_process_pid"    : process_pid,
            "win_logon_type"     : specific.get("logon_type"),
            "win_service_name"   : specific.get("service_name"),
            "win_share_name"     : specific.get("share_name"),
            "win_pipe_name"      : specific.get("pipe_name"),
            "win_ticket_type"    : specific.get("ticket_encryption_type"),
            "win_target_user"    : specific.get("target_user_name"),
            "win_subject_user"   : specific.get("subject_user_name"),
            "win_image_path"     : specific.get("image_path"),
            "win_command_line"   : specific.get("command_line"),
            "win_parent_image"   : specific.get("parent_image"),
            "win_new_process_id" : specific.get("new_process_id"),
        }

        return result

    # ── Event-ID-specific handlers ────────────────────────────────────────────
    # Each handler extracts the relevant fields from event_data for that event type.
    # The structure of event_data is completely different per event ID.

    def _handle_event(
        self,
        event_id  : Optional[int],
        event_data: Dict[str, Any],
        user_obj  : Dict[str, Any],
        winlog    : Dict[str, Any],
    ) -> Dict[str, Any]:
        """Dispatch to the correct event handler and return extracted fields."""
        handlers = {
            4624: self._ev_logon_success,
            4625: self._ev_logon_failure,
            4648: self._ev_explicit_cred,
            4688: self._ev_process_create,
            4697: self._ev_service_install,
            4720: self._ev_user_created,
            4728: self._ev_group_member_add,
            4756: self._ev_group_member_add,
            4732: self._ev_group_member_add,
            4769: self._ev_kerberos_tgs,
            4771: self._ev_kerberos_failure,
            4776: self._ev_ntlm_auth,
            5140: self._ev_share_access,
            5145: self._ev_share_object,
            7045: self._ev_service_install,
        }
        handler = handlers.get(event_id, self._ev_generic)
        return handler(event_data, user_obj, winlog)

    def _ev_logon_success(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """4624 — An account was successfully logged on."""
        return {
            "event_category": "authentication",
            "event_type"    : "AUTH_LOGIN",
            "action"        : "logon",
            "outcome"       : Outcome.SUCCESS.value,
            "user_name"     : ed.get("TargetUserName") or u.get("name"),
            "user_id"       : ed.get("TargetUserSid"),
            "src_ip"        : ed.get("IpAddress"),
            "src_port"      : self._to_int(ed.get("IpPort")),
            "logon_type"    : ed.get("LogonType"),
            "session_id"    : ed.get("TargetLogonId"),
            "target_user_name": ed.get("TargetUserName"),
            "subject_user_name": ed.get("SubjectUserName"),
        }

    def _ev_logon_failure(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """4625 — An account failed to log on."""
        return {
            "event_category": "authentication",
            "event_type"    : "AUTH_FAILURE",
            "action"        : "logon",
            "outcome"       : Outcome.FAILURE.value,
            "user_name"     : ed.get("TargetUserName") or u.get("name"),
            "src_ip"        : ed.get("IpAddress"),
            "src_port"      : self._to_int(ed.get("IpPort")),
            "logon_type"    : ed.get("LogonType"),
            "target_user_name": ed.get("TargetUserName"),
            "subject_user_name": ed.get("SubjectUserName"),
        }

    def _ev_explicit_cred(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """4648 — Explicit credentials used (RunAs, PtH precursor)."""
        return {
            "event_category": "authentication",
            "event_type"    : "AUTH_EXPLICIT_CRED",
            "action"        : "logon",
            "outcome"       : None,
            "user_name"     : ed.get("SubjectUserName") or u.get("name"),
            "target_user_name": ed.get("TargetUserName"),
            "src_ip"        : ed.get("TargetServerName"),
            "win_image_path": ed.get("ProcessName"),
        }

    def _ev_process_create(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """4688 — A new process was created."""
        return {
            "event_category": "process",
            "event_type"    : "PROCESS_CREATE",
            "action"        : "process_create",
            "outcome"       : None,
            "user_name"     : ed.get("SubjectUserName") or u.get("name"),
            "process_id"    : ed.get("NewProcessId"),
            "parent_process_id": ed.get("ProcessId"),
            "image_path"    : ed.get("NewProcessName"),
            "command_line"  : ed.get("CommandLine"),
            "parent_image"  : ed.get("ParentProcessName"),
            "new_process_id": ed.get("NewProcessId"),
        }

    def _ev_service_install(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """4697/7045 — A service was installed in the system."""
        return {
            "event_category": "process",
            "event_type"    : "SERVICE_INSTALL",
            "action"        : "service_install",
            "outcome"       : None,
            "user_name"     : ed.get("SubjectUserName") or u.get("name"),
            "service_name"  : ed.get("ServiceName"),
            "image_path"    : ed.get("ServiceFileName") or ed.get("ImagePath"),
        }

    def _ev_user_created(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """4720 — A user account was created."""
        return {
            "event_category": "iam",
            "event_type"    : "USER_ACCOUNT_CREATED",
            "action"        : "user_create",
            "outcome"       : Outcome.SUCCESS.value,
            "user_name"     : ed.get("SubjectUserName") or u.get("name"),
            "target_user_name": ed.get("TargetUserName"),
        }

    def _ev_group_member_add(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """4728/4732/4756 — A member was added to a privileged group."""
        return {
            "event_category": "iam",
            "event_type"    : "GROUP_MEMBER_ADDED",
            "action"        : "group_membership_change",
            "outcome"       : Outcome.SUCCESS.value,
            "user_name"     : ed.get("SubjectUserName") or u.get("name"),
            "target_user_name": ed.get("MemberName"),
            "win_group_name": ed.get("GroupName"),
        }

    def _ev_kerberos_tgs(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """4769 — A Kerberos service ticket was requested (Kerberoasting indicator)."""
        # RC4 encryption (0x17) on a service ticket request is the Kerberoasting signal
        ticket_type = ed.get("TicketEncryptionType", "")
        return {
            "event_category"      : "authentication",
            "event_type"          : "KERBEROS_TGS_REQUEST",
            "action"              : "kerberos_tgs",
            "outcome"             : Outcome.SUCCESS.value,
            "user_name"           : ed.get("TargetUserName") or u.get("name"),
            "src_ip"              : ed.get("IpAddress"),
            "src_port"            : self._to_int(ed.get("IpPort")),
            "service_name"        : ed.get("ServiceName"),
            "ticket_encryption_type": ticket_type,
            "target_user_name"    : ed.get("TargetUserName"),
        }

    def _ev_kerberos_failure(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """4771 — Kerberos pre-authentication failed."""
        return {
            "event_category": "authentication",
            "event_type"    : "KERBEROS_PREAUTH_FAILURE",
            "action"        : "kerberos_auth",
            "outcome"       : Outcome.FAILURE.value,
            "user_name"     : ed.get("TargetUserName") or u.get("name"),
            "src_ip"        : ed.get("IpAddress"),
            "target_user_name": ed.get("TargetUserName"),
        }

    def _ev_ntlm_auth(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """4776 — NTLM credential validation attempt (domain controller)."""
        return {
            "event_category": "authentication",
            "event_type"    : "NTLM_AUTH",
            "action"        : "ntlm_logon",
            "outcome"       : Outcome.SUCCESS.value if ed.get("Status") == "0x0" else Outcome.FAILURE.value,
            "user_name"     : ed.get("TargetUserName") or u.get("name"),
            "src_ip"        : ed.get("Workstation"),
            "target_user_name": ed.get("TargetUserName"),
        }

    def _ev_share_access(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """5140 — A network share object was accessed."""
        return {
            "event_category": "file",
            "event_type"    : "NETWORK_SHARE_ACCESS",
            "action"        : "share_access",
            "outcome"       : None,
            "user_name"     : ed.get("SubjectUserName") or u.get("name"),
            "src_ip"        : ed.get("IpAddress"),
            "src_port"      : self._to_int(ed.get("IpPort")),
            "share_name"    : ed.get("ShareName"),
        }

    def _ev_share_object(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """5145 — A network share object (pipe/file) was checked for access."""
        return {
            "event_category": "file",
            "event_type"    : "NAMED_PIPE_ACCESS",
            "action"        : "named_pipe_access",
            "outcome"       : None,
            "user_name"     : ed.get("SubjectUserName") or u.get("name"),
            "src_ip"        : ed.get("IpAddress"),
            "src_port"      : self._to_int(ed.get("IpPort")),
            "share_name"    : ed.get("ShareName"),
            "pipe_name"     : ed.get("RelativeTargetName"),
        }

    def _ev_generic(self, ed: Dict, u: Dict, w: Dict) -> Dict:
        """Fallback for unmapped event IDs — preserve what we can."""
        return {
            "event_category": None,
            "event_type"    : None,
            "action"        : None,
            "outcome"       : None,
            "user_name"     : (
                ed.get("SubjectUserName") or ed.get("TargetUserName") or u.get("name")
            ),
            "src_ip"        : ed.get("IpAddress"),
        }

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _to_int(self, value: Any) -> Optional[int]:
        """Convert hex or decimal string to int; return None on failure."""
        if value is None:
            return None
        try:
            s = str(value).strip()
            return int(s, 16) if s.startswith("0x") or s.startswith("0X") else int(s)
        except (ValueError, TypeError):
            return None

    def _clean_ip(self, raw: Optional[str]) -> Optional[str]:
        """Strip IPv6-mapped IPv4 prefix (::ffff:) and return clean IP string."""
        if not raw:
            return None
        s = str(raw).strip()
        if s.startswith("::ffff:") or s.startswith("::FFFF:"):
            s = s[7:]
        # Return None for placeholder values Windows uses
        if s in ("-", "::1", "LOCAL", "127.0.0.1", "0.0.0.0"):
            return None
        return s if s else None
