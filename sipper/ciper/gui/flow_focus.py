"""Point at the SIP messages that carry the evidence of the probable culprit."""


def _evidence_value(finding, key):
    prefix = f"{key}: "
    for item in finding.get("evidence", []):
        if item.startswith(prefix):
            return item[len(prefix):]
    return None


def _message_kind(message):
    if message.is_request:
        return message.method or ""
    return f"{message.status_code} {message.reason_phrase or ''}".strip()


def culprit_messages(flow, findings, verdict=None):
    """Map message index -> {"title", "rank", "lines"} for messages to highlight.

    ``findings`` are viewmodel findings of the call. The verdict's root cause
    gets rank 0 so the dialog opens on it.
    """
    root_type = (verdict or {}).get("root_type")
    focus = {}
    for finding in findings:
        index = _locate(flow, finding)
        if index is None:
            continue
        rank = 0 if finding.get("type") == root_type else (1 if finding.get("severity") == "high" else 2)
        current = focus.get(index)
        if current is None or rank < current["rank"]:
            focus[index] = {
                "title": finding.get("title") or finding.get("type", ""),
                "rank": rank,
                "lines": list(finding.get("offending_lines") or []),
            }
    return focus


def _locate(flow, finding):
    start_line = _evidence_value(finding, "Message")
    sender = _evidence_value(finding, "Sender")
    if start_line:
        for index, message in enumerate(flow.messages):
            if message.start_line != start_line:
                continue
            if sender and sender != f"{message.source_ip}:{message.source_port}":
                continue
            return index
    status = _evidence_value(finding, "Status")
    if status and finding.get("type") == "sip_error_response":
        for index, message in enumerate(flow.messages):
            if not message.is_request and _message_kind(message) == status:
                return index
    if finding.get("type") == "sip_abnormal_hangup":
        for index, message in enumerate(flow.messages):
            if message.is_request and message.method == "BYE":
                return index
    if finding.get("type") in {"sip_ok_without_ack", "sip_contact_private_address"}:
        for index, message in enumerate(flow.messages):
            if not message.is_request and message.status_code and 200 <= message.status_code < 300:
                return index
    if finding.get("type") == "sip_invite_no_response":
        for index, message in enumerate(flow.messages):
            if message.is_request and message.method == "INVITE":
                return index
    return None


def _normalize(line):
    """Compare header lines case-insensitively, ignoring spacing around ':'."""
    name, separator, value = line.strip().partition(":")
    if not separator:
        return line.strip().lower()
    return f"{name.strip().lower()}:{value.strip()}"


def message_html(message, focus, palette, escape):
    """Raw SIP message with the offending lines highlighted."""
    offending = {_normalize(line) for line in (focus or {}).get("lines") or []}
    lines = []
    if focus:
        lines.append(
            f"<div style='color:{palette['danger']}; font-weight:700; margin-bottom:6px;'>"
            f"! {escape(focus['title'])}</div>"
        )
    for line in (message.header_text or message.start_line).splitlines():
        text = escape(line)
        if line.strip() and _normalize(line) in offending:
            text = f"<span style='background:{palette['danger']}; color:#FFFFFF;'>{text}</span>"
        lines.append(text)
    body = message.body_text.strip() if getattr(message, "body_text", "") else ""
    if body:
        lines.append("")
        lines.extend(escape(line) for line in body.splitlines())
    return f"<pre style='font-family:Consolas; font-size:9pt;'>{'<br>'.join(lines)}</pre>"
