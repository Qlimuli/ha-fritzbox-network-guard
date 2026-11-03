WHITELIST_FILE = DATA_DIR / "whitelist.json"
_force_scan = threading.Event()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("network-guard")


def load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Could not load %s: %s", path, exc)
    return default


def save_json(path: Path, data: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        log.error("Could not save %s: %s", path, exc)


blocked_devices: dict[str, dict] = load_json(BLOCKED_FILE, {})
known_devices: dict[str, dict] = load_json(KNOWN_FILE, {})
whitelist: set[str] = set(load_json(WHITELIST_FILE, []))
scan_stats: dict[str, Any] = {
    "last_scan": None,
    "last_count": 0,
    "total_scans": 0,
    "fritz_ok": None,
    "last_error": None,
    "mac_filter_active": False,
}
_lock = threading.Lock()
_fc = None
_mac_q: MacQuarantine | None = None
_security: SecurityEngine | None = None


def get_fritz():
    global _fc
    if _fc is None:
        log.info("Connecting to FritzBox at %s …", FRITZBOX_HOST)
        _fc = FritzConnection(
            address=FRITZBOX_HOST,
            user=FRITZBOX_USER or None,
            password=FRITZBOX_PASSWORD,
            timeout=15,
        )
        log.info("Connected: %s", _fc)
    return _fc


def block_ip(ip: str, reason: str = "security alert") -> bool:
    try:
        get_fritz().call_action(
            "X_AVM-DE_HostFilter1",
            "DisallowWANAccessByIP",
