import pytest

from app.api.endpoints import parser
from app.schemas.cir import CIRSpecification

CIR = {"scenario_id": "ws", "attack_graph": {"nodes": [
    {"step_id": "s1", "tactic": "TA0002", "technique": "T1059.001", "target": "WS01", "action_type": "Execution",
     "evidence": [{"type": "process", "image": "powershell.exe"}]}], "edges": []}}


@pytest.fixture()
def team(api_client, make_user, monkeypatch):
    async def fake_llm(_):
        return CIRSpecification(**CIR)

    monkeypatch.setattr(parser, "parse_narrative_to_cir", fake_llm)
    users = {name: make_user(name) for name in ("alice", "bob", "carol", "mallory")}
    workspace = api_client.post("/api/v1/workspaces", json={"name": "SOC Team"}, headers=users["alice"]).json()
    for name, role in (("bob", "editor"), ("carol", "viewer")):
        added = api_client.post(f"/api/v1/workspaces/{workspace['id']}/members", json={"username": name, "role": role}, headers=users["alice"])
        assert added.status_code == 201, added.text
    scenario_id = api_client.post("/api/v1/parse", json={"scenario": "alice's"}, headers=users["alice"]).json()["id"]
    return users, workspace["id"], scenario_id


def share(client, headers, scenario_id, workspace_id):
    return client.put(f"/api/v1/scenarios/{scenario_id}/workspace", json={"workspace_id": workspace_id}, headers=headers)


def test_sharing_grants_members_access_by_role(api_client, team):
    users, workspace_id, scenario_id = team
    assert api_client.get(f"/api/v1/scenarios/{scenario_id}", headers=users["bob"]).status_code == 404  # not shared yet
    shared = share(api_client, users["alice"], scenario_id, workspace_id)
    assert shared.status_code == 200 and shared.json()["workspace_name"] == "SOC Team"

    for name in ("bob", "carol"):
        assert api_client.get(f"/api/v1/graph-analysis/{scenario_id}", headers=users[name]).status_code == 200
        listed = api_client.get("/api/v1/scenarios", headers=users[name]).json()
        assert listed[0]["id"] == scenario_id and listed[0]["owner_username"] == "alice" and not listed[0]["is_owner"]
    assert api_client.get(f"/api/v1/scenarios/{scenario_id}", headers=users["mallory"]).status_code == 404
    assert api_client.get(f"/api/v1/scenarios?workspace={workspace_id}", headers=users["mallory"]).json() == []

    # viewer cannot delete or re-share; editor may delete; only the creator re-shares
    assert api_client.delete(f"/api/v1/scenarios/{scenario_id}", headers=users["carol"]).status_code == 403
    assert share(api_client, users["bob"], scenario_id, None).status_code == 403
    assert api_client.get("/api/v1/scenarios?workspace=personal", headers=users["alice"]).json() == []
    assert api_client.delete(f"/api/v1/scenarios/{scenario_id}", headers=users["bob"]).status_code == 200


def test_cannot_share_into_foreign_or_read_only_workspace(api_client, make_user, team):
    users, workspace_id, scenario_id = team
    carol_scenario = api_client.post("/api/v1/parse", json={"scenario": "carol's"}, headers=users["carol"]).json()["id"]
    assert share(api_client, users["carol"], carol_scenario, workspace_id).status_code == 403  # viewer role
    other = api_client.post("/api/v1/workspaces", json={"name": "Mallory"}, headers=users["mallory"]).json()
    assert share(api_client, users["alice"], scenario_id, other["id"]).status_code == 403
    assert share(api_client, users["mallory"], scenario_id, other["id"]).status_code == 404  # cannot see it at all


def test_membership_management_rules(api_client, team):
    users, workspace_id, _ = team
    members = api_client.get(f"/api/v1/workspaces/{workspace_id}/members", headers=users["carol"]).json()
    assert [m["username"] for m in members] == ["alice", "bob", "carol"]
    assert api_client.get(f"/api/v1/workspaces/{workspace_id}/members", headers=users["mallory"]).status_code == 404
    assert api_client.post(f"/api/v1/workspaces/{workspace_id}/members", json={"username": "mallory"}, headers=users["bob"]).status_code == 403
    assert api_client.post(f"/api/v1/workspaces/{workspace_id}/members", json={"username": "ghost"}, headers=users["alice"]).status_code == 404
    assert api_client.post(f"/api/v1/workspaces/{workspace_id}/members", json={"username": "bob"}, headers=users["alice"]).status_code == 409

    alice_id = next(m["user_id"] for m in members if m["username"] == "alice")
    carol_id = next(m["user_id"] for m in members if m["username"] == "carol")
    # the last owner can neither be demoted nor leave
    assert api_client.patch(f"/api/v1/workspaces/{workspace_id}/members/{alice_id}", json={"role": "viewer"}, headers=users["alice"]).status_code == 400
    assert api_client.delete(f"/api/v1/workspaces/{workspace_id}/members/{alice_id}", headers=users["alice"]).status_code == 400
    # members may leave; non-owners cannot remove others
    assert api_client.delete(f"/api/v1/workspaces/{workspace_id}/members/{alice_id}", headers=users["bob"]).status_code == 403
    assert api_client.delete(f"/api/v1/workspaces/{workspace_id}/members/{carol_id}", headers=users["carol"]).status_code == 200
    assert api_client.get("/api/v1/workspaces", headers=users["carol"]).json() == []


def test_deleting_workspace_returns_scenarios_to_their_creators(api_client, team):
    users, workspace_id, scenario_id = team
    share(api_client, users["alice"], scenario_id, workspace_id)
    assert api_client.delete(f"/api/v1/workspaces/{workspace_id}", headers=users["bob"]).status_code == 403
    deleted = api_client.delete(f"/api/v1/workspaces/{workspace_id}", headers=users["alice"])
    assert deleted.json()["scenarios_unshared"] == 1
    assert api_client.get(f"/api/v1/scenarios/{scenario_id}", headers=users["bob"]).status_code == 404
    assert api_client.get(f"/api/v1/scenarios/{scenario_id}", headers=users["alice"]).status_code == 200
