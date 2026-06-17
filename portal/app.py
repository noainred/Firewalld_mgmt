"""
firewalld 프록시 관리 포탈 (Flask).

A 서버 <-> B 서버 간 직접 통신이 불가능할 때, 프록시 서버의 firewalld
포트포워딩 규칙을 웹에서 쉽게 추가/수정/삭제하고 로그를 확인할 수 있습니다.
인증은 OS 계정(PAM) 을 사용합니다.
"""
import ipaddress
import subprocess

from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   session, url_for)

import auth
import firewall
import models
import monitor
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

PROTOCOLS = ("tcp", "udp")
ROLES = ("client", "target", "proxy")


@app.before_request
def _ensure_db():
    if not getattr(app, "_db_ready", False):
        models.init_db()
        app._db_ready = True


# ---------------- 유효성 검증 ----------------
def _validate_rule(form):
    errors = []
    name = (form.get("name") or "").strip()
    if not name:
        errors.append("이름은 필수입니다.")

    protocol = (form.get("protocol") or "tcp").strip().lower()
    if protocol not in PROTOCOLS:
        errors.append("프로토콜은 tcp 또는 udp 여야 합니다.")

    def _port(field, label):
        try:
            v = int(form.get(field, ""))
            if not (1 <= v <= 65535):
                raise ValueError
            return v
        except (TypeError, ValueError):
            errors.append(f"{label} 는 1~65535 사이의 숫자여야 합니다.")
            return None

    listen_port = _port("listen_port", "수신 포트")
    dest_port = _port("dest_port", "목적지 포트")

    dest_addr = (form.get("dest_addr") or "").strip()
    try:
        ipaddress.ip_address(dest_addr)
    except ValueError:
        errors.append("목적지 주소(B 서버) 는 유효한 IP 여야 합니다.")

    source_addr = (form.get("source_addr") or "").strip()
    if source_addr:
        try:
            # 단일 IP 또는 CIDR 허용
            if "/" in source_addr:
                ipaddress.ip_network(source_addr, strict=False)
            else:
                ipaddress.ip_address(source_addr)
        except ValueError:
            errors.append("출발지 주소(A 서버) 는 유효한 IP 또는 CIDR 여야 합니다.")

    data = {
        "name": name,
        "protocol": protocol,
        "listen_port": listen_port,
        "dest_addr": dest_addr,
        "dest_port": dest_port,
        "source_addr": source_addr,
        "description": (form.get("description") or "").strip(),
        "enabled": 1 if form.get("enabled") in ("1", "on", "true") else 0,
    }
    return data, errors


# ---------------- 인증 ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ok, msg = auth.authenticate(username, password)
        if ok:
            session.permanent = True
            session["user"] = username
            models.add_audit(username, "login", "-", "포탈 로그인", "성공")
            return redirect(url_for("dashboard"))
        models.add_audit(username or "-", "login", "-", "포탈 로그인", f"실패: {msg}")
        flash(msg, "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    user = auth.current_user()
    if user:
        models.add_audit(user, "logout", "-", "포탈 로그아웃", "성공")
    session.clear()
    return redirect(url_for("login"))


# ---------------- 대시보드 ----------------
@app.route("/")
@auth.login_required
def dashboard():
    rules = models.list_rules()
    servers = models.list_servers()
    try:
        status = firewall.runtime_status()
        fw_error = None
    except firewall.FirewallError as e:
        status = None
        fw_error = str(e)
    return render_template(
        "dashboard.html", rules=rules, servers=servers,
        status=status, fw_error=fw_error,
        active_count=sum(1 for r in rules if r["enabled"]),
    )


# ---------------- 실시간 통신 상태 (AJAX) ----------------
@app.route("/api/live")
@auth.login_required
def api_live():
    """대시보드 실시간 통신 상태 JSON. (3초 주기 폴링)"""
    return jsonify(monitor.get_live_stats(models.list_rules()))


# ---------------- 규칙 관리 ----------------
@app.route("/rules")
@auth.login_required
def rules():
    return render_template("rules.html", rules=models.list_rules())


@app.route("/rules/new", methods=["GET", "POST"])
@auth.login_required
def rule_new():
    if request.method == "POST":
        data, errors = _validate_rule(request.form)
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("rule_form.html", rule=request.form,
                                   protocols=PROTOCOLS, mode="new")
        rule_id = models.create_rule(data, auth.current_user())
        data["id"] = rule_id
        try:
            if data["enabled"]:
                firewall.apply_rule(data)
            models.add_audit(auth.current_user(), "create_rule",
                             f"rule#{rule_id}", _rule_summary(data), "성공")
            flash("규칙이 생성되고 적용되었습니다.", "success")
        except firewall.FirewallError as e:
            models.add_audit(auth.current_user(), "create_rule",
                             f"rule#{rule_id}", _rule_summary(data), f"실패: {e}")
            flash(f"규칙은 저장되었으나 적용 실패: {e}", "error")
        return redirect(url_for("rules"))
    return render_template("rule_form.html", rule={"protocol": "tcp", "enabled": 1},
                           protocols=PROTOCOLS, mode="new")


@app.route("/rules/<int:rule_id>/edit", methods=["GET", "POST"])
@auth.login_required
def rule_edit(rule_id):
    old = models.get_rule(rule_id)
    if not old:
        flash("규칙을 찾을 수 없습니다.", "error")
        return redirect(url_for("rules"))
    if request.method == "POST":
        data, errors = _validate_rule(request.form)
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("rule_form.html", rule=request.form,
                                   protocols=PROTOCOLS, mode="edit", rule_id=rule_id)
        # 기존 규칙 제거 후 새 규칙 적용
        try:
            firewall.remove_rule(old)
        except firewall.FirewallError:
            pass
        models.update_rule(rule_id, data)
        data["id"] = rule_id
        try:
            if data["enabled"]:
                firewall.apply_rule(data)
            models.add_audit(auth.current_user(), "update_rule",
                             f"rule#{rule_id}", _rule_summary(data), "성공")
            flash("규칙이 수정되었습니다.", "success")
        except firewall.FirewallError as e:
            models.add_audit(auth.current_user(), "update_rule",
                             f"rule#{rule_id}", _rule_summary(data), f"실패: {e}")
            flash(f"규칙은 저장되었으나 적용 실패: {e}", "error")
        return redirect(url_for("rules"))
    return render_template("rule_form.html", rule=old, protocols=PROTOCOLS,
                           mode="edit", rule_id=rule_id)


@app.route("/rules/<int:rule_id>/delete", methods=["POST"])
@auth.login_required
def rule_delete(rule_id):
    rule = models.get_rule(rule_id)
    if rule:
        try:
            firewall.remove_rule(rule)
            result = "성공"
        except firewall.FirewallError as e:
            result = f"적용 제거 실패: {e}"
        models.delete_rule(rule_id)
        models.add_audit(auth.current_user(), "delete_rule",
                         f"rule#{rule_id}", _rule_summary(rule), result)
        flash("규칙이 삭제되었습니다.", "success")
    return redirect(url_for("rules"))


@app.route("/rules/<int:rule_id>/toggle", methods=["POST"])
@auth.login_required
def rule_toggle(rule_id):
    rule = models.get_rule(rule_id)
    if rule:
        new_state = 0 if rule["enabled"] else 1
        rule["enabled"] = new_state
        models.update_rule(rule_id, rule)
        try:
            if new_state:
                firewall.apply_rule(rule)
            else:
                firewall.remove_rule(rule)
            models.add_audit(auth.current_user(), "toggle_rule",
                             f"rule#{rule_id}",
                             f"enabled={new_state}", "성공")
        except firewall.FirewallError as e:
            flash(f"상태 변경 적용 실패: {e}", "error")
    return redirect(url_for("rules"))


@app.route("/rules/sync", methods=["POST"])
@auth.login_required
def rules_sync():
    """DB 의 모든 규칙을 firewalld 에 일괄 재적용."""
    try:
        firewall.sync_all(models.list_rules())
        models.add_audit(auth.current_user(), "sync", "-", "전체 규칙 동기화", "성공")
        flash("모든 규칙을 firewalld 에 재적용했습니다.", "success")
    except firewall.FirewallError as e:
        flash(f"동기화 실패: {e}", "error")
    return redirect(url_for("dashboard"))


# ---------------- 서버 인벤토리 ----------------
@app.route("/servers", methods=["GET", "POST"])
@auth.login_required
def servers():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        address = (request.form.get("address") or "").strip()
        role = (request.form.get("role") or "client").strip()
        if not name or not address or role not in ROLES:
            flash("서버 이름/주소/역할을 올바르게 입력하세요.", "error")
        else:
            models.create_server({
                "name": name, "address": address, "role": role,
                "description": (request.form.get("description") or "").strip(),
            })
            models.add_audit(auth.current_user(), "create_server",
                             name, f"{role} {address}", "성공")
            flash("서버가 등록되었습니다.", "success")
        return redirect(url_for("servers"))
    return render_template("servers.html", servers=models.list_servers(),
                           roles=ROLES)


@app.route("/servers/<int:server_id>/delete", methods=["POST"])
@auth.login_required
def server_delete(server_id):
    models.delete_server(server_id)
    models.add_audit(auth.current_user(), "delete_server",
                     f"server#{server_id}", "-", "성공")
    flash("서버가 삭제되었습니다.", "success")
    return redirect(url_for("servers"))


# ---------------- 로그 ----------------
@app.route("/logs")
@auth.login_required
def logs():
    audit = models.list_audit(limit=300)
    # firewalld 시스템 로그 (journalctl) - 권한 없으면 빈 결과
    syslog = []
    try:
        proc = subprocess.run(
            ["journalctl", "-u", "firewalld", "-n", "100", "--no-pager"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            syslog = proc.stdout.splitlines()
        else:
            syslog = [proc.stderr.strip() or "firewalld 로그를 읽을 수 없습니다."]
    except Exception as e:  # noqa: BLE001
        syslog = [f"시스템 로그 조회 불가: {e}"]
    return render_template("logs.html", audit=audit, syslog=syslog)


# ---------------- helpers ----------------
def _rule_summary(r):
    src = r.get("source_addr") or "any"
    return (f'{r.get("name")}: {src} -> :{r.get("listen_port")}/'
            f'{r.get("protocol")} -> {r.get("dest_addr")}:{r.get("dest_port")}')


app.jinja_env.globals.update(current_user=auth.current_user, zone=Config.FIREWALL_ZONE)


if __name__ == "__main__":
    models.init_db()
    app.run(host="0.0.0.0", port=int(__import__("os").environ.get("FWPORTAL_PORT", "8080")))
