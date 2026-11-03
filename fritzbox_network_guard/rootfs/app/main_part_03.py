            arguments={"NewIPv4Address": ip, "NewDisallow": True},
        )
        log.info("Blocked WAN for %s (%s)", ip, reason)
        return True
    except Exception as exc:
        log.error("Block %s failed: %s", ip, exc)
        return False


def unblock_ip(ip: str) -> bool:
    try:
        get_fritz().call_action(
            "X_AVM-DE_HostFilter1",
            "DisallowWANAccessByIP",
            arguments={"NewIPv4Address": ip, "NewDisallow": False},
        )
        log.info("Unblocked WAN for %s", ip)
        return True
    except Exception as exc:
        log.error("Unblock %s failed: %s", ip, exc)
        return False


def notify_ha(title: str, message: str) -> None:
    if not SUPERVISOR_TOKEN or not NOTIFY_ON_BLOCK:
        return
    try:
        requests.post(
            "http://supervisor/core/api/services/persistent_notification/create",
            headers={
                "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
                "Content-Type": "application/json",
            },
            json={
                "title": title,
                "message": message,
                "notification_id": f"network_guard_{int(time.time())}",
            },
            timeout=5,
        )
    except Exception as exp:
        log.warning("HA notify failed: %s", exp)


def get_security() -> SecurityEngine:
    global _security
    if _security is None:
        _security = SecurityEngine(
            DATA_DIR,
            block_ip_fn=block_ip,
            notify_fn=notify_ha,
            auto_block=AUTO_BLOCK_THREAT_INTEL,
            perimeter_interval=PERIMETER_INTERVAL,
            threat_intel_interval=THREAT_INTEL_INTERVAL,
        )
    return _security


def get_mac_q() -> MacQuarantine:
    global _mac_q
    if _mac_q is None:
