"""CRUD endpoints for security scanning rules."""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.core.models import SecurityRule, SecurityRuleCreate, SecurityRuleUpdate
from app.services import rules_store


class BulkEnableBody(BaseModel):
    enabled: bool

router = APIRouter()


@router.patch("/rules", response_model=list[SecurityRule])
def bulk_update_rules(body: BulkEnableBody):
    return rules_store.bulk_update_enabled(body.enabled)


@router.get("/rules", response_model=list[SecurityRule])
def list_rules(scanner: str | None = Query(None)):
    rules = rules_store.get_all_rules()
    if scanner:
        rules = [r for r in rules if r.scanner == scanner]
    return rules


@router.post("/rules", response_model=SecurityRule, status_code=201)
def create_rule(body: SecurityRuleCreate):
    try:
        return rules_store.add_rule(body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/rules/{rule_id}", response_model=SecurityRule)
def get_rule(rule_id: str):
    for rule in rules_store.get_all_rules():
        if rule.id == rule_id:
            return rule
    raise HTTPException(status_code=404, detail="Rule not found")


@router.put("/rules/{rule_id}", response_model=SecurityRule)
def update_rule(rule_id: str, body: SecurityRuleUpdate):
    try:
        return rules_store.update_rule(rule_id, body)
    except KeyError:
        raise HTTPException(status_code=404, detail="Rule not found") from None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str):
    try:
        rules_store.delete_rule(rule_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Rule not found") from None
