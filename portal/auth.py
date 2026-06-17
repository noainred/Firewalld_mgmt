"""
OS 인증 모듈 (PAM 기반).

리눅스 OS 계정/비밀번호로 인증합니다. python-pam 패키지를 사용하며,
설치되어 있지 않으면 `pamtester`/`su` 대체 경로를 사용하지 않고 명확히 오류를
반환합니다. 선택적으로 특정 OS 그룹 소속만 허용할 수 있습니다.
"""
import grp
import pwd
from functools import wraps

from flask import redirect, session, url_for

from config import Config

try:
    import pam as _pam  # python-pam
    _HAVE_PAM = True
except Exception:  # pragma: no cover
    _HAVE_PAM = False


def _user_groups(username):
    """사용자가 속한 모든 그룹명 집합 반환 (primary + secondary)."""
    groups = set()
    try:
        info = pwd.getpwnam(username)
        primary = grp.getgrgid(info.pw_gid).gr_name
        groups.add(primary)
    except KeyError:
        return groups
    for g in grp.getgrall():
        if username in g.gr_mem:
            groups.add(g.gr_name)
    return groups


def group_allowed(username):
    """ALLOWED_GROUPS 가 비어있으면 모두 허용, 아니면 교집합 확인."""
    if not Config.ALLOWED_GROUPS:
        return True
    return bool(_user_groups(username) & set(Config.ALLOWED_GROUPS))


def authenticate(username, password):
    """
    (성공여부, 메시지) 반환.
    PAM 으로 OS 인증 후 그룹 정책 확인.
    """
    if not username or not password:
        return False, "사용자명과 비밀번호를 입력하세요."
    if not _HAVE_PAM:
        return False, "서버에 python-pam 이 설치되어 있지 않습니다. requirements.txt 를 설치하세요."
    p = _pam.pam()
    ok = p.authenticate(username, password, service=Config.PAM_SERVICE)
    if not ok:
        return False, f"인증 실패: {p.reason or '잘못된 자격증명'}"
    if not group_allowed(username):
        return False, "허용된 그룹에 속해 있지 않습니다."
    return True, "ok"


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    return session.get("user")
