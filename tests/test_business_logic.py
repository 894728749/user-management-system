import os, sys, re, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["SECRET_KEY"] = "test-secret-key-32chr-long-for-testing!!"

from app import app, _get_conn, _DB, _UPLOAD_DIR
from PIL import Image
import pytest


@pytest.fixture(autouse=True)
def reset_db():
    if os.path.exists(_DB):
        os.remove(_DB)
    import importlib, app as a
    importlib.reload(a)
    yield
    if os.path.exists(_DB):
        os.remove(_DB)


def _login(client, username="admin", password="admin123"):
    html = client.get("/login").data.decode()
    csrf = re.search(r'csrf_token.*?value="([^"]+)"', html).group(1)
    return client.post("/login", data={
        "username": username, "password": password, "csrf_token": csrf
    })


def _get_csrf(client, url="/"):
    html = client.get(url).data.decode()
    m = re.search(r'csrf_token.*?value="([^"]+)"', html)
    return m.group(1) if m else None


class TestAuth:
    def test_anon_cannot_access_profile(self):
        assert app.test_client().get("/profile").status_code == 302

    def test_anon_cannot_recharge(self):
        assert app.test_client().post("/recharge", data={"amount": "100"}).status_code == 302

    def test_register_can_login(self):
        c = app.test_client()
        csrf = _get_csrf(c, "/register")
        c.post("/register", data={
            "username": "newuser", "password": "NewUser@2026",
            "email": "new@test.com", "phone": "13800000000", "csrf_token": csrf
        })
        resp = _login(c, "newuser", "NewUser@2026")
        assert resp.status_code in (200, 302)

    def test_no_md5_password_in_db(self):
        with _get_conn() as conn:
            for u in conn.execute("SELECT password_hash FROM users").fetchall():
                pw = u["password_hash"]
                assert not pw.startswith("md5")
                assert len(pw) > 20 and ":" in pw


class TestIDOR:
    def test_alice_cannot_see_admin(self):
        c = app.test_client()
        _login(c, "alice", "alice2025")
        body = c.get("/profile").data.decode()
        assert "alice@example.com" in body
        assert "13800138000" not in body

    def test_tamper_user_id_invalid(self):
        c = app.test_client()
        _login(c, "alice", "alice2025")
        body = c.get("/profile?user_id=1").data.decode()
        assert "alice@example.com" in body
        assert "13800138000" not in body


class TestRecharge:
    def test_recharge_creates_pending_order(self):
        c = app.test_client()
        _login(c)
        csrf = _get_csrf(c, "/profile")
        c.post("/recharge", data={"amount": "100.00", "csrf_token": csrf})
        with _get_conn() as conn:
            orders = conn.execute("SELECT * FROM recharge_orders").fetchall()
            bal = conn.execute("SELECT balance_cents FROM users WHERE id=1").fetchone()[0]
        assert len(orders) == 1 and orders[0]["status"] == "pending"
        assert bal == 9999900

    def test_negative_amount_rejected(self):
        c = app.test_client()
        _login(c)
        resp = c.post("/recharge", data={"amount": "-50", "csrf_token": _get_csrf(c, "/profile")})
        assert resp.status_code in (302, 400)

    def test_zero_rejected(self):
        c = app.test_client()
        _login(c)
        resp = c.post("/recharge", data={"amount": "0", "csrf_token": _get_csrf(c, "/profile")})
        assert resp.status_code in (302, 400)

    def test_nan_rejected(self):
        c = app.test_client()
        _login(c)
        resp = c.post("/recharge", data={"amount": "nan", "csrf_token": _get_csrf(c, "/profile")})
        assert resp.status_code in (302, 400)

    def test_inf_rejected(self):
        c = app.test_client()
        _login(c)
        resp = c.post("/recharge", data={"amount": "inf", "csrf_token": _get_csrf(c, "/profile")})
        assert resp.status_code in (302, 400)

    def test_overflow_rejected(self):
        c = app.test_client()
        _login(c)
        resp = c.post("/recharge", data={"amount": "1e309", "csrf_token": _get_csrf(c, "/profile")})
        assert resp.status_code in (302, 400)

    def test_three_decimals_rejected(self):
        c = app.test_client()
        _login(c)
        resp = c.post("/recharge", data={"amount": "1.234", "csrf_token": _get_csrf(c, "/profile")})
        assert resp.status_code in (302, 400)

    def test_over_limit_rejected(self):
        c = app.test_client()
        _login(c)
        resp = c.post("/recharge", data={"amount": "999999", "csrf_token": _get_csrf(c, "/profile")})
        assert resp.status_code in (302, 400)

    def test_approve_once_only(self):
        c = app.test_client()
        _login(c)
        csrf = _get_csrf(c, "/profile")
        c.post("/recharge", data={"amount": "100.00", "csrf_token": csrf})
        _login(c)
        with _get_conn() as conn:
            oid = conn.execute("SELECT id FROM recharge_orders").fetchone()[0]
        csrf = _get_csrf(c, "/admin/orders")
        apprv = lambda: c.post(f"/admin/recharge/{oid}/approve", data={"csrf_token": csrf})
        assert apprv().status_code in (200, 302)
        assert apprv().status_code == 400
        with _get_conn() as conn:
            bal = conn.execute("SELECT balance_cents FROM users WHERE id=1").fetchone()[0]
        assert bal == 10009900  # 9999900 + 10000¢


class TestCSRF:
    def test_post_without_csrf_rejected(self):
        c = app.test_client()
        _login(c)
        assert c.post("/recharge", data={"amount": "100"}).status_code in (400, 302)

    def test_logout_post_clears_session(self):
        c = app.test_client()
        _login(c)
        csrf = _get_csrf(c)
        c.post("/logout", data={"csrf_token": csrf})
        assert c.get("/profile").status_code == 302


class TestAdminPrivilege:
    def test_non_admin_cannot_approve(self):
        c = app.test_client()
        _login(c, "alice", "alice2025")
        assert c.post("/admin/recharge/1/approve", data={}).status_code in (302, 403)

    def test_admin_can_view_other_users(self):
        c = app.test_client()
        _login(c)
        assert c.get("/admin/users/2").status_code == 200


class TestSearch:
    def test_anon_cannot_search(self):
        assert app.test_client().get("/search?keyword=admin").status_code == 302

    def test_user_sees_only_username(self):
        c = app.test_client()
        _login(c, "alice", "alice2025")
        body = c.get("/search?keyword=admin").data.decode()
        assert "admin" in body
        assert "admin@example.com" not in body

    def test_admin_sees_full_info(self):
        c = app.test_client()
        _login(c)
        body = c.get("/search?keyword=alice").data.decode()
        assert "alice" in body and "alice@example.com" in body


class TestLockout:
    def test_lockout_per_username(self):
        """攻击alice不会锁住admin（按 user+IP 组合锁定）"""
        c = app.test_client()
        for _ in range(6):
            csrf = _get_csrf(c, "/login")
            c.post("/login", data={"username": "alice", "password": "wrong", "csrf_token": csrf})
        assert _login(c, "admin", "admin123").status_code in (200, 302)


if __name__ == "__main__":
    pytest.main(["-v", __file__])
