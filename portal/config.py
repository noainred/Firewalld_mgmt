"""
포탈 설정 모듈
환경변수로 동작을 재정의할 수 있습니다.
"""
import os


class Config:
    # Flask
    SECRET_KEY = os.environ.get("FWPORTAL_SECRET_KEY", os.urandom(32).hex())
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # HTTPS 환경에서는 1 로 설정하세요.
    SESSION_COOKIE_SECURE = os.environ.get("FWPORTAL_COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("FWPORTAL_SESSION_TTL", "3600"))

    # 데이터베이스 (SQLite) - 규칙 및 감사 로그 저장
    DB_PATH = os.environ.get(
        "FWPORTAL_DB", "/var/lib/firewalld-portal/portal.db"
    )

    # firewalld 적용 대상 zone
    FIREWALL_ZONE = os.environ.get("FWPORTAL_ZONE", "public")

    # firewall-cmd 실행 시 sudo 사용 여부 (포탈을 root 로 실행하면 0)
    USE_SUDO = os.environ.get("FWPORTAL_USE_SUDO", "0") == "1"

    # PAM 인증에 사용할 서비스 이름 (/etc/pam.d/<service>)
    PAM_SERVICE = os.environ.get("FWPORTAL_PAM_SERVICE", "login")

    # 로그인 허용 그룹 (비우면 모든 OS 사용자 허용).
    # 콤마로 여러 그룹 지정 가능. 예) "wheel,fwadmin"
    ALLOWED_GROUPS = [
        g.strip()
        for g in os.environ.get("FWPORTAL_ALLOWED_GROUPS", "").split(",")
        if g.strip()
    ]

    # 데모/개발 모드: firewall-cmd 를 실제로 실행하지 않고 결과만 기록.
    DRY_RUN = os.environ.get("FWPORTAL_DRY_RUN", "0") == "1"
