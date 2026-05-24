from __future__ import annotations
from functools import lru_cache
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )
    app_name: str = Field(default="DNS Security Analyzer", alias="APP_NAME")
    app_version: str = Field(default="0.1.0", alias="APP_VERSION")
    app_env: str = Field(default="development", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_secret_key: str = Field(default="dev-secret-key", alias="APP_SECRET_KEY")
    app_api_prefix: str = Field(default="/api/v1", alias="APP_API_PREFIX")
    app_allowed_hosts: str = Field(default="localhost,127.0.0.1", alias="APP_ALLOWED_HOSTS")
    app_cors_origins: str = Field(default="http://localhost:3000", alias="APP_CORS_ORIGINS")
    server_host: str = Field(default="127.0.0.1", alias="SERVER_HOST")
    server_port: int = Field(default=8000, alias="SERVER_PORT")
    database_url: str = Field(default="sqlite+aiosqlite:///./dns_analyzer_dev.db", alias="DATABASE_URL")
    database_pool_size: int = Field(default=5, alias="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(default=10, alias="DATABASE_MAX_OVERFLOW")
    database_pool_timeout: int = Field(default=30, alias="DATABASE_POOL_TIMEOUT")
    database_echo: bool = Field(default=False, alias="DATABASE_ECHO")
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    redis_cache_ttl: int = Field(default=3600, alias="REDIS_CACHE_TTL")
    redis_job_queue_db: int = Field(default=1, alias="REDIS_JOB_QUEUE_DB")
    api_key_header: str = Field(default="X-API-Key", alias="API_KEY_HEADER")
    api_key_length: int = Field(default=32, alias="API_KEY_LENGTH")
    jwt_secret_key: str = Field(default="dev-jwt-secret", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    jwt_expire_minutes: int = Field(default=60, alias="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    rate_limit_enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")
    rate_limit_per_minute: int = Field(default=60, alias="RATE_LIMIT_REQUESTS_PER_MINUTE")
    rate_limit_burst: int = Field(default=10, alias="RATE_LIMIT_BURST")
    dns_resolvers: str = Field(default="8.8.8.8,8.8.4.4,1.1.1.1", alias="DNS_RESOLVERS")
    dns_timeout: float = Field(default=5.0, alias="DNS_TIMEOUT")
    dns_retries: int = Field(default=2, alias="DNS_RETRIES")
    dns_max_concurrent_resolvers: int = Field(default=5, alias="DNS_MAX_CONCURRENT_RESOLVERS")
    subdomain_wordlist_path: str = Field(default="wordlists/subdomains-small.txt", alias="SUBDOMAIN_WORDLIST_PATH")
    subdomain_max_concurrent: int = Field(default=50, alias="SUBDOMAIN_MAX_CONCURRENT")
    subdomain_timeout: float = Field(default=3.0, alias="SUBDOMAIN_TIMEOUT")
    dkim_selectors_path: str = Field(default="wordlists/dkim-selectors.txt", alias="DKIM_SELECTORS_PATH")
    virustotal_api_key: str = Field(default="", alias="VIRUSTOTAL_API_KEY")
    virustotal_base_url: str = Field(default="https://www.virustotal.com/api/v3", alias="VIRUSTOTAL_BASE_URL")
    virustotal_enabled: bool = Field(default=False, alias="VIRUSTOTAL_ENABLED")
    abuseipdb_api_key: str = Field(default="", alias="ABUSEIPDB_API_KEY")
    abuseipdb_base_url: str = Field(default="https://api.abuseipdb.com/api/v2", alias="ABUSEIPDB_BASE_URL")
    abuseipdb_enabled: bool = Field(default=False, alias="ABUSEIPDB_ENABLED")
    shodan_api_key: str = Field(default="", alias="SHODAN_API_KEY")
    shodan_base_url: str = Field(default="https://api.shodan.io", alias="SHODAN_BASE_URL")
    shodan_enabled: bool = Field(default=False, alias="SHODAN_ENABLED")
    ipinfo_api_key: str = Field(default="", alias="IPINFO_API_KEY")
    ipinfo_base_url: str = Field(default="https://ipinfo.io", alias="IPINFO_BASE_URL")
    ipinfo_enabled: bool = Field(default=False, alias="IPINFO_ENABLED")
    intel_rate_limit_virustotal: int = Field(default=4, alias="INTEL_RATE_LIMIT_VIRUSTOTAL")
    intel_rate_limit_abuseipdb: int = Field(default=60, alias="INTEL_RATE_LIMIT_ABUSEIPDB")
    intel_rate_limit_shodan: int = Field(default=1, alias="INTEL_RATE_LIMIT_SHODAN")
    intel_rate_limit_ipinfo: int = Field(default=100, alias="INTEL_RATE_LIMIT_IPINFO")
    scheduler_enabled: bool = Field(default=False, alias="SCHEDULER_ENABLED")
    scheduler_default_interval_hours: int = Field(default=24, alias="SCHEDULER_DEFAULT_INTERVAL_HOURS")
    scheduler_max_concurrent_jobs: int = Field(default=5, alias="SCHEDULER_MAX_CONCURRENT_JOBS")
    scheduler_timezone: str = Field(default="UTC", alias="SCHEDULER_TIMEZONE")
    smtp_enabled: bool = Field(default=False, alias="SMTP_ENABLED")
    smtp_host: str = Field(default="smtp.gmail.com", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_use_tls: bool = Field(default=True, alias="SMTP_USE_TLS")
    smtp_username: str = Field(default="", alias="SMTP_USERNAME")
    smtp_password: str = Field(default="", alias="SMTP_PASSWORD")
    smtp_from_address: str = Field(default="", alias="SMTP_FROM_ADDRESS")
    smtp_from_name: str = Field(default="DNS Security Analyzer", alias="SMTP_FROM_NAME")
    slack_enabled: bool = Field(default=False, alias="SLACK_ENABLED")
    slack_webhook_url: str = Field(default="", alias="SLACK_WEBHOOK_URL")
    slack_channel: str = Field(default="#security-alerts", alias="SLACK_CHANNEL")
    webhook_enabled: bool = Field(default=False, alias="WEBHOOK_ENABLED")
    webhook_url: str = Field(default="", alias="WEBHOOK_URL")
    webhook_secret: str = Field(default="", alias="WEBHOOK_SECRET")
    reports_output_dir: str = Field(default="reports/output", alias="REPORTS_OUTPUT_DIR")
    reports_template_dir: str = Field(default="src/dns_analyzer/reporting/templates", alias="REPORTS_TEMPLATE_DIR")
    reports_max_age_days: int = Field(default=90, alias="REPORTS_MAX_AGE_DAYS")
    reports_default_format: str = Field(default="html", alias="REPORTS_DEFAULT_FORMAT")
    log_level: str = Field(default="DEBUG", alias="LOG_LEVEL")
    log_format: str = Field(default="console", alias="LOG_FORMAT")
    log_output: str = Field(default="stdout", alias="LOG_OUTPUT")
    log_file_path: str = Field(default="logs/dns_analyzer.log", alias="LOG_FILE_PATH")
    feature_dnssec_check: bool = Field(default=True, alias="FEATURE_DNSSEC_CHECK")
    feature_axfr_check: bool = Field(default=True, alias="FEATURE_AXFR_CHECK")
    feature_subdomain_enumeration: bool = Field(default=True, alias="FEATURE_SUBDOMAIN_ENUMERATION")
    feature_threat_intel: bool = Field(default=False, alias="FEATURE_THREAT_INTEL")
    feature_scheduled_monitoring: bool = Field(default=False, alias="FEATURE_SCHEDULED_MONITORING")
    feature_pdf_export: bool = Field(default=False, alias="FEATURE_PDF_EXPORT")

    @property
    def is_production(self): return self.app_env == "production"
    @property
    def is_development(self): return self.app_env == "development"
    @property
    def is_sqlite(self): return self.database_url.startswith("sqlite")
    @property
    def dns_resolver_list(self): return [r.strip() for r in self.dns_resolvers.split(",") if r.strip()]
    @property
    def allowed_hosts_list(self): return [h.strip() for h in self.app_allowed_hosts.split(",") if h.strip()]
    @property
    def cors_origins_list(self): return [o.strip() for o in self.app_cors_origins.split(",") if o.strip()]
    @property
    def enabled_intel_providers(self):
        p = []
        if self.virustotal_enabled and self.virustotal_api_key: p.append("virustotal")
        if self.abuseipdb_enabled and self.abuseipdb_api_key: p.append("abuseipdb")
        return p
    @property
    def app(self): return _Compat(self, "app")
    @property
    def database(self): return _Compat(self, "database")
    @property
    def redis(self): return _Compat(self, "redis")
    @property
    def auth(self): return _Compat(self, "auth")
    @property
    def dns(self): return _Compat(self, "dns")
    @property
    def intel(self): return _Compat(self, "intel")
    @property
    def logging(self): return _Compat(self, "logging")
    @property
    def reporting(self): return _Compat(self, "reporting")
    @property
    def features(self): return _Compat(self, "features")
    @property
    def notifications(self): return _Compat(self, "notifications")
    @property
    def scheduler(self): return _Compat(self, "scheduler")
    def ensure_dirs(self):
        Path(self.reports_output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.log_file_path).parent.mkdir(parents=True, exist_ok=True)

class _Compat:
    """Universal compatibility shim — maps settings.app.name -> settings.app_name etc."""
    _MAP = {
        "app": {"name":"app_name","version":"app_version","env":"app_env","debug":"app_debug",
                "secret_key":"app_secret_key","api_prefix":"app_api_prefix",
                "is_production":"is_production","is_development":"is_development",
                "cors_origins":"cors_origins_list","allowed_hosts":"allowed_hosts_list"},
        "database": {"url":"database_url","pool_size":"database_pool_size","max_overflow":"database_max_overflow",
                     "pool_timeout":"database_pool_timeout","echo":"database_echo","is_sqlite":"is_sqlite"},
        "redis": {"url":"redis_url","cache_ttl":"redis_cache_ttl","job_queue_db":"redis_job_queue_db"},
        "auth": {"api_key_header":"api_key_header","api_key_length":"api_key_length",
                 "rate_limit_enabled":"rate_limit_enabled","rate_limit_per_minute":"rate_limit_per_minute",
                 "rate_limit_burst":"rate_limit_burst"},
        "dns": {"resolvers":"dns_resolver_list","timeout":"dns_timeout","retries":"dns_retries",
                "max_concurrent_resolvers":"dns_max_concurrent_resolvers",
                "subdomain_wordlist_path":"_subdomain_wordlist_path",
                "subdomain_max_concurrent":"subdomain_max_concurrent",
                "subdomain_timeout":"subdomain_timeout",
                "dkim_selectors_path":"_dkim_selectors_path"},
        "intel": {"virustotal_api_key":"virustotal_api_key","virustotal_base_url":"virustotal_base_url",
                  "virustotal_enabled":"virustotal_enabled","abuseipdb_api_key":"abuseipdb_api_key",
                  "abuseipdb_base_url":"abuseipdb_base_url","abuseipdb_enabled":"abuseipdb_enabled",
                  "shodan_api_key":"shodan_api_key","shodan_base_url":"shodan_base_url",
                  "shodan_enabled":"shodan_enabled","ipinfo_api_key":"ipinfo_api_key",
                  "ipinfo_base_url":"ipinfo_base_url","ipinfo_enabled":"ipinfo_enabled",
                  "rate_limit_virustotal":"intel_rate_limit_virustotal",
                  "rate_limit_abuseipdb":"intel_rate_limit_abuseipdb",
                  "rate_limit_shodan":"intel_rate_limit_shodan",
                  "rate_limit_ipinfo":"intel_rate_limit_ipinfo",
                  "enabled_providers":"enabled_intel_providers"},
        "logging": {"level":"log_level","format":"log_format","output":"log_output"},
        "reporting": {"output_dir":"_reports_output_dir","template_dir":"_reports_template_dir",
                      "max_age_days":"reports_max_age_days","default_format":"reports_default_format"},
        "features": {"dnssec_check":"feature_dnssec_check","axfr_check":"feature_axfr_check",
                     "subdomain_enumeration":"feature_subdomain_enumeration",
                     "threat_intel":"feature_threat_intel","scheduled_monitoring":"feature_scheduled_monitoring",
                     "pdf_export":"feature_pdf_export"},
        "notifications": {"smtp_enabled":"smtp_enabled","slack_enabled":"slack_enabled","webhook_enabled":"webhook_enabled"},
        "scheduler": {"enabled":"scheduler_enabled","default_interval_hours":"scheduler_default_interval_hours",
                      "timezone":"scheduler_timezone"},
    }
    def __init__(self, s: Settings, group: str):
        self._s = s
        self._group = group
    def __getattr__(self, name: str):
        mapping = self._MAP.get(self._group, {})
        key = mapping.get(name)
        if key is None:
            raise AttributeError(f"No setting '{name}' in group '{self._group}'")
        if key == "_subdomain_wordlist_path":
            from pathlib import Path
            return Path(self._s.subdomain_wordlist_path)
        if key == "_dkim_selectors_path":
            from pathlib import Path
            return Path(self._s.dkim_selectors_path)
        if key == "_reports_output_dir":
            from pathlib import Path
            return Path(self._s.reports_output_dir)
        if key == "_reports_template_dir":
            from pathlib import Path
            return Path(self._s.reports_template_dir)
        return getattr(self._s, key)

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
