"""Link the two call legs of a B2BUA such as FreeSWITCH.

A B2BUA receives leg A (carrier -> FreeSWITCH) and originates leg B
(FreeSWITCH -> extension or gateway) with a new Call-ID. When leg B fails,
FreeSWITCH answers leg A with a translated error, so the verdict of leg A
alone would blame FreeSWITCH. Linking the legs moves the blame to where the
failure really started.

Two dialogs are linked when the host that received the INVITE of leg A sends
the INVITE of leg B shortly after, for the same dialed number or caller.
"""

import re

from ciper.diagnosis import confidence_label

LEG_MAX_DELAY_SECONDS = 15.0
_DIGITS = re.compile(r"\D")


def _initial_invite(flow):
    return next((message for message in flow.messages if message.is_request and message.method == "INVITE"), None)


def _uri_user(value):
    if not value:
        return ""
    candidate = value
    if "<" in candidate and ">" in candidate:
        candidate = candidate.split("<", 1)[1].split(">", 1)[0]
    if ":" in candidate:
        candidate = candidate.split(":", 1)[1]
    return candidate.split("@", 1)[0].split(";", 1)[0]


def _digits(value):
    return _DIGITS.sub("", value or "")


def _numbers_match(first, second):
    first, second = _digits(first), _digits(second)
    if len(first) < 3 or len(second) < 3:
        return False
    size = min(8, len(first), len(second))
    return first[-size:] == second[-size:]


def _leg_score(invite_a, invite_b):
    """Smaller is better; None when the two INVITEs are unrelated."""
    delay = invite_b.packet_time - invite_a.packet_time
    if delay < -0.05 or delay > LEG_MAX_DELAY_SECONDS:
        return None
    dialed_a = _uri_user(invite_a.request_uri) or _uri_user(invite_a.headers.get("to"))
    dialed_b = _uri_user(invite_b.request_uri) or _uri_user(invite_b.headers.get("to"))
    caller_a = _uri_user(invite_a.headers.get("from"))
    caller_b = _uri_user(invite_b.headers.get("from"))
    if _numbers_match(dialed_a, dialed_b):
        return delay
    if _numbers_match(caller_a, caller_b) and delay <= 3.0:
        return delay + 5.0
    return None


def link_call_legs(sip_flows, call_summaries, namer=None):
    """Annotate summaries with ``legs`` and propagate leg-B failures to leg A."""
    by_key = {summary.get("dialog_key", summary["call_id"]): summary for summary in call_summaries}
    invites = {}
    for key, flow in sip_flows.items():
        invite = _initial_invite(flow)
        if invite is not None and key in by_key:
            invites[key] = invite

    candidates = []
    for key_a, invite_a in invites.items():
        b2bua = invite_a.destination_ip
        if namer is not None and namer.targets and not namer.is_platform(b2bua):
            continue
        for key_b, invite_b in invites.items():
            if key_b == key_a or invite_b.call_id == invite_a.call_id or invite_b.source_ip != b2bua:
                continue
            score = _leg_score(invite_a, invite_b)
            if score is not None:
                candidates.append((score, key_a, key_b, b2bua))

    linked_b = set()
    for score, key_a, key_b, b2bua in sorted(candidates):
        if key_b in linked_b:
            continue
        summary_a, summary_b = by_key[key_a], by_key[key_b]
        if summary_a.get("legs", {}).get("role") == "B":
            continue
        linked_b.add(key_b)
        summary_a.setdefault("legs", {"role": "A", "b2bua_ip": b2bua, "peers": []})
        summary_a["legs"]["peers"].append(
            {"call_id": summary_b["call_id"], "dialog_key": key_b, "start_time": invites[key_b].packet_time}
        )
        summary_b["legs"] = {
            "role": "B",
            "b2bua_ip": b2bua,
            "peers": [{"call_id": summary_a["call_id"], "dialog_key": key_a, "start_time": invites[key_a].packet_time}],
        }

    for summary in call_summaries:
        legs = summary.get("legs")
        if not legs or legs["role"] != "A":
            continue
        _propagate_leg_failure(summary, [by_key[peer["dialog_key"]] for peer in legs["peers"]], namer)

    return call_summaries


def _propagate_leg_failure(summary_a, summaries_b, namer):
    verdict_a = summary_a.get("verdict") or {}
    if summary_a.get("signaling_state") not in {"failed", "no_response", "cancelled"}:
        return
    failing = [
        summary_b
        for summary_b in summaries_b
        if (summary_b.get("verdict") or {}).get("status") in {"fail", "user"}
        and summary_b.get("signaling_state") in {"failed", "no_response", "cancelled", "missing_ack"}
    ]
    if not failing:
        return
    # The last attempt is the one whose failure FreeSWITCH reported back.
    leg_b = max(failing, key=lambda item: item.get("start_time") or 0.0)
    verdict_b = leg_b["verdict"]
    b2bua = summary_a["legs"]["b2bua_ip"]
    b2bua_name = namer.describe(b2bua) if namer is not None else b2bua
    attempts = len(failing)
    reasons = [
        f"Esta e a perna A. {b2bua_name} originou {len(summaries_b)} perna(s) B; a falha da perna A e consequencia "
        f"da perna B (Call-ID {leg_b['call_id']}).",
        f"Perna B: {verdict_b.get('headline', '-')}",
        *verdict_b.get("reasons", [])[1:3],
    ]
    if attempts > 1:
        reasons.append(f"Houve {attempts} tentativas de perna B com falha (failover/fork); a ultima foi considerada.")
    confidence = round(min(verdict_a.get("confidence", 0.9), verdict_b.get("confidence", 0.9)) * 0.95, 2)
    original = verdict_a.get("headline")
    if original:
        reasons.append(f"Visto so pela perna A: {original}")
    summary_a["verdict"] = {
        **verdict_a,
        "status": verdict_b.get("status", verdict_a.get("status")),
        "headline": f"{verdict_a.get('outcome', 'Chamada recusada')} - causa na perna B: "
        f"{verdict_b.get('root_title') or verdict_b.get('headline', '-')}",
        "root_type": verdict_b.get("root_type"),
        "root_title": verdict_b.get("root_title"),
        "culprit": f"{verdict_b.get('culprit', '-')} (perna B)",
        "culprit_ip": verdict_b.get("culprit_ip"),
        "confidence": confidence,
        "confidence_label": confidence_label(confidence),
        "reasons": reasons,
        "actions": verdict_b.get("actions", []) or verdict_a.get("actions", []),
        "confirmed_by": verdict_b.get("confirmed_by"),
        "offending_lines": verdict_b.get("offending_lines", []),
        "propagated_from": leg_b["call_id"],
    }
    summary_a["primary_issue"] = verdict_b.get("root_type") or summary_a.get("primary_issue")
