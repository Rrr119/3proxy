"""Per-user bandwidth and the audit log, through three client protocols.

The audit log is deliberately configured without an ordinary "log" line: it
has to stand on its own. The bucket-isolation check runs two users at once,
where a shared bucket would make the second one wait for the first.
"""

import os
import threading
import time


def run(t):
    if not t.skip_unless("httpsrv"):
        return

    origin = t.free_port()
    t.start("userlimits_origin", f"""
        auth iponly
        allow *
        http data * /data
        httpsrv -p{origin}
    """, ports=[origin])

    http_proxy = t.free_port()
    socks_proxy = t.free_port()
    socks4_proxy = t.free_port()
    audit_path = os.path.join(t.tmpdir, "userlimits.audit")
    users = "alice,bob,carol,dave,erin"

    t.start("userlimits_audit", f"""
        audit {audit_path}
        auth strong
        users alice:CL:secret bob:CL:secret carol:CL:secret dave:CL:secret erin:CL:secret mallory:CL:secret
        allow {users}
        userbandlimin 512000 {users}
        userbandlimout 512000 {users}
        proxy -p{http_proxy}
        socks -p{socks_proxy}

        # SOCKS4 carries a user name but no password, so this service uses
        # useronly while the rules above still select a bucket by user.
        flush
        auth useronly
        allow {users}
        socks -p{socks4_proxy}
    """, ports=[http_proxy, socks_proxy, socks4_proxy])

    def audit_text():
        try:
            with open(audit_path, "r") as fp:
                return fp.read()
        except OSError:
            return ""

    def wait_audit(*needles, timeout=5):
        deadline = time.time() + timeout
        while True:
            records = [line for line in audit_text().splitlines()
                       if all(needle in line for needle in needles)]
            if records or time.time() > deadline:
                return "\n".join(records)
            time.sleep(0.05)

    url = f"http://127.0.0.1:{origin}"
    data = url + "/data?size=96000&block=4096&delay=2"

    # --- HTTP proxy ------------------------------------------------------
    started = time.monotonic()
    r = t.http(data, proxy=f"127.0.0.1:{http_proxy}",
               proxy_auth=("alice", "secret"))
    elapsed = int((time.monotonic() - started) * 1000)
    t.eq(96000, r.length, "the HTTP client gets its whole body")
    t.in_range(elapsed, 500, 5000, "the HTTP client is throttled")
    text = wait_audit("user=alice", "service=proxy", "result=allow")
    t.contains(text, "user=alice",
               "the HTTP session is audited")
    t.contains(text, f"target=127.0.0.1:{origin}",
               "the audit names the destination")
    t.contains(text, "throttled=1", "the audit says the session was throttled")
    t.contains(text, "rate_in=512000", "the audit carries the applied rate")
    t.contains(text, "request=", "the audit records the request line")

    # --- SOCKS5 ----------------------------------------------------------
    started = time.monotonic()
    r = t.socks_http(f"127.0.0.1:{socks_proxy}", data,
                     auth=("bob", "secret"))
    elapsed = int((time.monotonic() - started) * 1000)
    t.eq(96000, r.length, "the SOCKS5 client gets its whole body")
    t.in_range(elapsed, 500, 5000, "the SOCKS5 client is throttled")
    text = wait_audit("user=bob", "service=socks5", "result=allow")
    t.contains(text, "user=bob",
               "the SOCKS5 session is audited")
    t.contains(text, "throttled=1", "the SOCKS5 session records throttling")

    # --- SOCKS4 ----------------------------------------------------------
    started = time.monotonic()
    r = t.socks_http(f"127.0.0.1:{socks4_proxy}", data, socks4=True,
                     socks4_user="erin")
    elapsed = int((time.monotonic() - started) * 1000)
    t.eq(96000, r.length, "the SOCKS4 client gets its whole body")
    t.in_range(elapsed, 500, 5000, "the SOCKS4 client is throttled")
    text = wait_audit("user=erin", "service=socks4", "result=allow")
    t.contains(text, "user=erin",
               "the SOCKS4 session is audited")
    t.contains(text, "throttled=1", "the SOCKS4 session records throttling")

    # --- one bucket per user --------------------------------------------
    # A shared 512 kbps bucket would queue the second 200 KB body behind the
    # first and take about twice as long as either one alone.
    results = {}
    big = url + "/data?size=200000&block=4096&delay=2"

    def download(user):
        begin = time.monotonic()
        reply = t.http(big, proxy=f"127.0.0.1:{http_proxy}",
                       proxy_auth=(user, "secret"))
        results[user] = (reply.length, time.monotonic() - begin)

    threads = [threading.Thread(target=download, args=(user,))
               for user in ("carol", "dave")]
    started = time.monotonic()
    threads[0].start()
    time.sleep(0.15)
    threads[1].start()
    for thread in threads:
        thread.join()
    wall = int((time.monotonic() - started) * 1000)

    t.eq((200000, 200000), (results["carol"][0], results["dave"][0]),
         "both concurrent users get their whole body")
    t.eq(True, wall < 5500,
         "the two users have independent bandwidth buckets")

    # --- failures are audited too ---------------------------------------
    t.eq(407, t.http(data, proxy=f"127.0.0.1:{http_proxy}",
                     proxy_auth=("alice", "wrong")).status,
         "a wrong password is refused")
    text = wait_audit("user=alice", "service=proxy", "result=auth_failed")
    t.contains(text, "user=alice",
               "a failed authentication is audited by user")
    t.not_contains(text, "wrong", "the audit never contains a password")
    t.not_contains(text, "secret", "no configured password leaks into the audit")

    t.ne(200, t.http(data, proxy=f"127.0.0.1:{http_proxy}",
                     proxy_auth=("mallory", "secret")).status,
         "a user outside the access rule is refused")
    text = wait_audit("user=mallory", "service=proxy", "result=deny")
    t.contains(text, "user=mallory",
               "the access-rule refusal is audited")

    # --- the original shared command still behaves as before -------------
    legacy_proxy = t.free_port()
    t.start("userlimits_legacy", f"""
        auth iponly
        allow *
        bandlimin 512000 *
        proxy -p{legacy_proxy}
    """, ports=[legacy_proxy])
    started = time.monotonic()
    r = t.http(data, proxy=f"127.0.0.1:{legacy_proxy}")
    elapsed = int((time.monotonic() - started) * 1000)
    t.eq(96000, r.length, "the shared rule still serves the whole body")
    t.in_range(elapsed, 500, 5000,
               "the existing shared bandlim rule is still applied")
