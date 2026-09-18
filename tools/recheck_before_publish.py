#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""发文前复核 —— **每一条要对外说的话,都在这里重新跑一遍**。

跑:  python tools/recheck_before_publish.py

═══════════════════════════════════════════════════════════════════════
为什么需要它
═══════════════════════════════════════════════════════════════════════
本注要对外说的话全部建立在**上游此刻的状态**上,而上游会变:

  · Jetty 可能把 9.4.60 / 10.0.28 / 11.0.29 发到 Central —— 一发,「公开修复版不存在」就没了。
  · GitHub 可能给 6790 / 11143 老线补上 first_patched —— 一补,「官方连版本号都没给」就变了。
  · advisory 可能调评级 / 区间 —— 一调,判定表就得重生成。

**这些主张失效时,不会有任何东西报错,文章会安静地变成假话。**
→ 发文当天必须重跑这个脚本;失效了就改文案,别改判据。
☠️ 每一条都尽量带阳性对照 —— 判据本身坏了(比如网络挂了)要能看出来,
   否则「全 404」和「网断了」长得一模一样(tomcat-line-check 踩过这个坑)。
"""
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from gen_table import MAIN_CVE, collect, probe_central  # noqa: E402

OK, BAD = "✅", "🔴"
fails = []


def check(name, cond, detail=""):
    print("  %s %s%s" % (OK if cond else BAD, name, ("  —— " + detail) if detail else ""))
    if not cond:
        fails.append(name)


def main():
    print("=" * 72)
    print("发文前复核 —— jetty-line-check(5 条 CVE,主打 %s)" % MAIN_CVE)
    print("=" * 72)

    cve_meta, rows = collect()

    def rows_for(cve, line, coord="org.eclipse.jetty:jetty-http"):
        return [r for r in rows if r["cve"] == cve and r["line"] == line and r["coordinate"] == coord]

    print("\n【主张 ①】主打 2332:9.4/10/11 老线官方点名了修复版,但 Central 上 404")
    for line in ("9.4", "10.0", "11.0"):
        rr = rows_for(MAIN_CVE, line)
        assert rr, "2332 缺 %s 线" % line
        fp = rr[0]["firstPatched"]
        exists = probe_central(rr[0]["group"], rr[0]["artifact"], fp) if fp else None
        check("2332 %s 线修复版 %s 仍是 Central 404" % (line, fp), fp and exists is False,
              "first_patched=%s exists=%s" % (fp, exists))
    # 阳性对照:12 线公开修复版必须在
    r12 = rows_for(MAIN_CVE, "12.0")[0]
    check("阳性对照:2332 的 %s 仍在 Central 上" % r12["firstPatched"],
          probe_central(r12["group"], r12["artifact"], r12["firstPatched"]) is True,
          "对照不过说明 200 判据坏了,上面几条不算数")

    print("\n【主张 ②】6790 / 11143 老线:官方连版本号都没给(first_patched 为空)")
    for cve, coord in (("CVE-2026-6790", "org.eclipse.jetty:jetty-server"),
                       ("CVE-2025-11143", "org.eclipse.jetty:jetty-http")):
        for line in ("9.4", "10.0", "11.0"):
            rr = [r for r in rows if r["cve"] == cve and r["line"] == line and r["coordinate"] == coord]
            check("%s %s 线仍无 first_patched" % (cve, line),
                  bool(rr) and rr[0]["firstPatched"] is None,
                  "实际:%s" % (rr[0]["firstPatched"] if rr else "缺行"))

    print("\n【主张 ③】老线终版仍在 Central(证明 404 是「那版没发」,不是「整个坐标没了」)")
    for v in ("9.4.58.v20250814", "10.0.26", "11.0.26"):
        check("jetty-http %s 仍在 Central 上" % v,
              probe_central("org.eclipse.jetty", "jetty-http", v) is True)

    print("\n【主张 ④】评级别渲染成「统称高危」")
    check("2332 仍是 high / CVSS v3 7.4",
          cve_meta[MAIN_CVE]["severity"] == "high" and cve_meta[MAIN_CVE]["cvss_v3"] == 7.4,
          "%s / v3=%s" % (cve_meta[MAIN_CVE]["severity"], cve_meta[MAIN_CVE]["cvss_v3"]))
    check("11143 仍是 low", cve_meta["CVE-2025-11143"]["severity"] == "low")
    check("6790 仍是 medium", cve_meta["CVE-2026-6790"]["severity"] == "medium")
    check("10050 就是第 15 注判死那条(Digest,受影响面小),只当判定表一行",
          any(r["cve"] == "CVE-2026-10050" for r in rows), "别把它当主卖点")

    print("\n【主张 ⑤】19203(2332 同族续作,本轮新增):官方叫升的老线版本 Central 404,"
          "而全局库(Dependabot 用)拿不到区间")
    # 5a 独立再查一次全局 advisory(不复用 collect)—— 证明 Dependabot 报不出「升到哪」
    import json as _json
    import urllib.request as _u
    _g = _json.load(_u.urlopen(_u.Request(
        "https://api.github.com/advisories?cve_id=CVE-2026-19203",
        headers={"User-Agent": "jetty-line-check-recheck/0.2"})))
    check("19203 全局 advisory 的 vulnerabilities 仍为空(Dependabot 给不出版本区间)",
          bool(_g) and not _g[0].get("vulnerabilities"),
          "🔴 全局库一旦补上区间,文案「Dependabot 说不清升到哪」要改")
    # 5b 9.4/10/11 官方点名版本 Central 404(核心信息差)
    for line, fp in (("9.4", "9.4.64"), ("10.0", "10.0.32"), ("11.0", "11.0.32")):
        rr = rows_for("CVE-2026-19203", line)
        check("19203 %s 线官方点名 %s,Central 仍 404" % (line, fp),
              bool(rr) and rr[0]["firstPatched"] == fp
              and probe_central("org.eclipse.jetty", "jetty-http", fp) is False,
              "实际 fp=%s" % (rr[0]["firstPatched"] if rr else "缺行"))
    # 5c 9.4 线上界=9.4.63(后台原话搜的就是这个版本)
    rr94 = rows_for("CVE-2026-19203", "9.4")
    check("19203 jetty-http 9.4 线上界仍是 9.4.63(后台原话搜的版本)",
          bool(rr94) and rr94[0]["vulnUpper"] == "9.4.63")
    # 5d 12.x 阳性对照:官方点名版本在 Central(证明「老线 404」不是网络坏了)
    for line, fp in (("12.0", "12.0.38"), ("12.1", "12.1.12")):
        rr = rows_for("CVE-2026-19203", line)
        check("阳性对照:19203 %s 线修复版 %s 在 Central 上(200)" % (line, fp),
              bool(rr) and probe_central("org.eclipse.jetty", "jetty-http", rr[0]["firstPatched"]) is True)
    # 5e 12.1 线默认 RFC9110 不受影响,判定表必须带 condition(防对默认用户误报)
    rr121 = rows_for("CVE-2026-19203", "12.1")
    check("19203 12.1 线带默认路径 condition(默认 RFC9110 不受影响,防误报默认用户)",
          bool(rr121) and rr121[0].get("condition"))
    check("19203 是 high", cve_meta["CVE-2026-19203"]["severity"] == "high")

    print("\n" + "=" * 72)
    if fails:
        print("🔴 %d 条不过 —— **别发,先改文案或重生成判定表**:" % len(fails))
        for f in fails:
            print("   ·", f)
        return 1
    print("✅ 全部通过 —— 文案里的主张此刻仍然成立")
    print("🔴 但仍有三件只能人做:")
    print("   ① jetty.org/security.html 是否仍写 \"see details for availability\"(文案硬引这句)")
    print("   ② 文案红线:走私要前置代理才谈得上危害;别写「藏补丁卖钱」;别统称高危")
    print("   ③ 建库前复跑 aggregator_probe,确认 %s 的聚合位仍独占" % MAIN_CVE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
