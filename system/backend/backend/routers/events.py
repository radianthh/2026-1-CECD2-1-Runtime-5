import logging
import os

import httpx
from fastapi import APIRouter
from database import get_connection
from services.playbook_service import get_playbook, get_similar_playbooks, save_playbook
from services.llm_service import analyze_event
from services.semantic_cache import semantic_cache
from time_utils import now_iso

router = APIRouter()
logger = logging.getLogger("backend.events")
BRIDGE_URL = os.getenv("BRIDGE_URL", "http://bridge:5000")


def _request_remediation(container_name: str, action: str = "stop"):
    if not container_name:
        logger.info("Remediation skipped: empty container name")
        return None

    try:
        resp = httpx.post(
            f"{BRIDGE_URL}/remediate",
            json={"container_name": container_name, "action": action},
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as exc:
        logger.error("Remediation request failed for %s: %s", container_name, exc)
        return None


@router.get("/events")
def get_events():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@router.get("/events/{event_id}")
def get_event_detail(event_id: str):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM events WHERE id = %s", (event_id,)
    ).fetchone()
    conn.close()
    if not row:
        return {"error": "not found"}
    return {
        "attackType": row["rule_name"],
        "aiInsight":  row["llm_insight"],
        "action":     row["llm_action"],
        "status":     row["status"],
    }


@router.post("/events/ingest")
def ingest_event(body: dict):
    conn = get_connection()
    conn.execute("""
        INSERT INTO events
        (id, rule_name, priority, container, cmdline, output,
         llm_action, manual_action, llm_insight, from_playbook, status, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (id) DO UPDATE SET
            rule_name = excluded.rule_name,
            priority = excluded.priority,
            container = excluded.container,
            cmdline = excluded.cmdline,
            output = excluded.output,
            llm_action = excluded.llm_action,
            manual_action = excluded.manual_action,
            llm_insight = excluded.llm_insight,
            from_playbook = excluded.from_playbook,
            status = excluded.status,
            timestamp = excluded.timestamp
    """, (
        body["id"], body["rule_name"], body["priority"],
        body.get("container", ""), body.get("cmdline", ""),
        body.get("output", ""), body.get("llm_action", ""),
        body.get("manual_action", ""), body.get("llm_insight", ""),
        bool(body.get("from_playbook", False)), body.get("status", "PENDING"),
        body.get("timestamp", now_iso())
    ))
    conn.commit()
    conn.close()
    return {"ok": True}


@router.patch("/events/{event_id}/decision")
def patch_decision(event_id: str, body: dict):
    decision = body.get("decision")
    manual_action = body.get("manual_action")
    conn = get_connection()
    remediation_container = None
    remediation_action = "stop"

    if decision == "CONFIRMED":
        row = conn.execute(
            "SELECT * FROM events WHERE id = %s", (event_id,)
        ).fetchone()
        if row:
            save_playbook(
                rule_name=row["rule_name"],
                action=row["llm_action"],
                insight=row["llm_insight"]
            )
            semantic_cache.delete(row["rule_name"], row["priority"])
            actions = {row["llm_action"], row["manual_action"], manual_action}
            if "restart" in actions:
                remediation_container = row["container"]
                remediation_action = "restart"
            elif "stop" in actions:
                remediation_container = row["container"]
        conn.execute(
            "UPDATE events SET status = 'CONFIRMED', manual_action = NULL WHERE id = %s", (event_id,)
        )
    elif decision == "ROLLED_BACK":
        row = None
        if manual_action:
            row = conn.execute(
                "SELECT * FROM events WHERE id = %s", (event_id,)
            ).fetchone()
            if row:
                if manual_action in {"stop", "ignore", "alert"}:
                    save_playbook(
                        rule_name=row["rule_name"],
                        action=manual_action,
                        insight=row["llm_insight"],
                        approved_by="security_engineer",
                    )
                if manual_action in {"restart", "stop"}:
                    remediation_container = row["container"]
                    remediation_action = manual_action
        conn.execute(
            "UPDATE events SET status = 'ROLLED_BACK', manual_action = %s WHERE id = %s",
            (manual_action, event_id),
        )

    conn.commit()
    conn.close()
    remediation_result = (
        _request_remediation(remediation_container, remediation_action)
        if remediation_container
        else None
    )
    return {
        "ok": True,
        "decision": decision,
        "manual_action": manual_action,
        "remediation": remediation_result,
    }


@router.post("/llm/analyze")
def llm_analyze(body: dict):
    rule     = body.get("rule", "")
    priority = body.get("priority", "")
    output   = body.get("output", "")
    cmdline  = body.get("cmdline", "")

    # 1. 플레이북 존재 → action + insight 모두 재사용, LLM 스킵
    playbook = get_playbook(rule)
    if playbook:
        return {
            "action":        playbook["action"],
            "insight":       playbook["insight"],
            "from_playbook": True,
            "from_cache":    False,
            "approved_by":   playbook["approved_by"],
        }

    cached = semantic_cache.get(rule, priority)
    if cached:
        return {
            **cached,
            "from_cache": True,
        }

    # 캐시 미스: 같은 rule+priority는 한 요청만 LLM을 호출하고, 나머지는 락을 기다렸다가 캐시 결과를 받는다.
    with semantic_cache.lock_for(rule, priority):
        cached = semantic_cache.get(rule, priority)
        if cached:
            return {
                **cached,
                "from_cache": True,
            }

        # 2. 정확 매칭 실패 + 캐시 미스 → playbook VectorDB top-k 검색 결과를 근거로 LLM이 action 추천
        similar_playbooks = get_similar_playbooks(rule, output, cmdline)
        result = analyze_event(rule, priority, output, cmdline, similar_playbooks)
        response = {
            **result,
            "from_playbook": False,
            "from_playbook_vectordb": True,
            "from_cache": False,
            "referenced_playbooks": [
                {
                    "rule_name": item["rule_name"],
                    "action": item["action"],
                    "similarity": item["similarity"],
                    "vector_distance": item["vector_distance"],
                    "approved_by": item["approved_by"],
                }
                for item in similar_playbooks
            ],
        }
        semantic_cache.set(rule, priority, response)
    return response


@router.get("/playbook")
def get_playbook_api(rule_name: str):
    playbook = get_playbook(rule_name)
    if not playbook:
        return {}
    return playbook


@router.get("/playbooks")
def get_playbooks():
    conn = get_connection()
    rows = conn.execute("""
        SELECT rule_name, action, insight, approved_by, created_at
        FROM playbooks
        ORDER BY created_at DESC, rule_name ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]
