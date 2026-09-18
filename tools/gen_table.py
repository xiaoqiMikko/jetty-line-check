#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""从一手源生成 CveTable.java —— **判定表不手抄**。

跑:  python tools/gen_table.py            # 生成 + 全部断言
     python tools/gen_table.py --dry      # 只打印,不写文件

═══════════════════════════════════════════════════════════════════════
🔴 为什么判据是「模块坐标 + 版本号 → 判定表」,而不是「jar 里有没有某个类」
═══════════════════════════════════════════════════════════════════════
姊妹项目 tomcat-line-check 的判据是「jar 里有没有 ChunkExtension.class」——
因为 Tomcat 那次修复**新增了一个类**,可以靠类的存在判定。

**Jetty 这条(CVE-2026-2332)不行**:2026-09-11 建造第一步用 `gh api compare`
+ `javap` 坐实,修复改的是 `HttpParser.java` 的**方法体**,没有新增任何类
(`isChunking()` / `_chunkLength` 等成员在修复前后都在)。
→ 靠「有没有某个 class」判不了,只能靠**模块坐标 + 版本号 → 判定表**(同 shiro-check)。

⚠️ 版本号比大小正是 tomcat-line-check 要打的那个错。这里之所以能用版本号,是因为:
本注的价值不在「你的版本号可不可信」,而在「**官方叫你升的那一版,在 Maven Central 上根本不存在**」——
判据的硬核是**探测 Central 真 jar 的 404/200**,版本号只用来定位你在哪条线。

═══════════════════════════════════════════════════════════════════════
🔬 断言(不过就拒绝出表 —— 抄 tomcat-line-check/tools/gen_table.py 的做法)
═══════════════════════════════════════════════════════════════════════
  A1 阳性对照:12 线的公开修复版(如 jetty-http 12.0.33)**必须** 200
              —— 证明「200 判据」本身没坏。
  A2 核心主张:三条 EOL 老线(9.4/10/11)advisory 点名的修复版,在 Central 上**必须** 404
              —— 这就是「官方叫你升到一个不存在的版本」。
  A3 老线终版仍在:9.4.58.v20250814 / 10.0.26 / 11.0.26 **必须** 200
              —— 证明 404 不是「整个坐标都没了」,而是「那个修复版没发」。
  A4 哨兵:一个不存在的版本必须 404 —— 证明 404 判据没坏(否则「全 404」和「网络坏了」一样)。
  A5 主打那条(2332)结构没变:severity=high、cvss_v3=7.4、覆盖 jetty-http 9.4/10/11。
  A6 裂开的模块没被吞掉:5795 的 ee-jaspi、10050 的 ee-security 必须在坐标表里。
  A7 评级别渲染:11143=low、6790=medium 必须如实(防「统称高危」)。
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

UA = {"User-Agent": "jetty-line-check/0.1 (+https://github.com/xiaoqiMikko/jetty-line-check)"}

# 六条 CVE → GHSA。主打是 CVE-2026-2332(jetty-http chunked 走私,high)。
# 🔴 CVE-2026-19203(2026-09-17 新发)是 2332 的同族续作(LF EXT.TERM 走私)。
#    ☠️ 它的**全局** advisory(GHSA-p2j5-5566-vpv9)vulnerabilities 为空、first_patched 为 null ——
#    区间与修复版只在**仓库级** advisory(GHSA-xc35-c22g-239h)里,用 `patched_versions` 键(不是 first_patched_version)。
#    → collect() 对全局 vulns 为空的 CVE 自动回退到仓库级源(REPO_ADVISORY_SRC)。
CVES = [
    ("CVE-2026-2332", "GHSA-355h-qmc2-wpwf"),   # jetty-http CRLF-quoted 走私 high —— 主打(元老)
    ("CVE-2026-19203", "GHSA-p2j5-5566-vpv9"),  # jetty-http LF EXT.TERM 走私 high —— 2332 同族续作(09-17)
    ("CVE-2026-5795", "GHSA-r7p8-xq5m-436c"),   # jaspi ThreadLocal 未清 high
    ("CVE-2026-6790", "GHSA-7p3p-8qv8-m2vh"),   # jetty-server HTTP/2·3 Host 混淆 medium
    ("CVE-2026-10050", "GHSA-2fvj-hgj9-j2gr"),  # jetty-security Digest ISO-8859-1 high(v4)
    ("CVE-2025-11143", "GHSA-wjpw-4j6x-6rwh"),  # jetty-http URI 解析差异 low
]
MAIN_CVE = "CVE-2026-2332"
# 全局 advisory 的 vulnerabilities 为空时,从这个仓库级源补区间(键名 patched_versions,不是 first_patched_version)。
REPO_ADVISORY_SRC = "jetty/jetty.project"
SENTINEL = ("org.eclipse.jetty", "jetty-http", "9.9.999")  # A4 哨兵:必须 404

# 🔴 「默认路径」条件 —— 只对纯版本号判不出的那条线用(19203 的 12.1 线默认 RFC9110 不受影响)。
#    key = (cve, line);value = 一句话条件。别的线为空 = 默认路径中招。
#    由来:19203 advisory 原文实测 —— 12.0.36 默认中招(Responses: 2);12.1.x 因 PR 12564 默认 RFC9110
#    不允许 LF,只有配 RFC7230/RFC2616 才中(此时最新的 12.1.11 也中,升 12.1.12)。
ROW_CONDITIONS = {
    ("CVE-2026-19203", "12.1"): "默认 RFC9110 合规模式不受影响;仅当显式配置 RFC7230 / RFC2616 时命中(此时升 12.1.12)",
}


def get(url, timeout=60):
    return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout)


def advisory(cve):
    d = json.load(get("https://api.github.com/advisories?cve_id=" + cve))
    return d[0] if d else None


_repo_adv_cache = None


def repo_advisory(cve):
    """仓库级 published advisory 按 cve_id 反查。匿名可读 published 的。
    ⚠️ 键名与全局 advisory 不同:修复版是 `patched_versions`(可能逗号分隔),不是 `first_patched_version`。"""
    global _repo_adv_cache
    if _repo_adv_cache is None:
        _repo_adv_cache = json.load(get(
            "https://api.github.com/repos/%s/security-advisories?per_page=100" % REPO_ADVISORY_SRC))
    for a in _repo_adv_cache:
        if a.get("cve_id") == cve:
            return a
    return None


def vulns_of(cve, a_global):
    """统一取一条 CVE 的受影响项,归一成 [{pkg, range, fp}]。
    全局 advisory 的 vulnerabilities 为空时(新发 CVE 常见)回退到仓库级源。"""
    gv = a_global.get("vulnerabilities") or []
    if gv:
        return [{"pkg": (v.get("package") or {}).get("name"),
                 "range": v.get("vulnerable_version_range") or "",
                 "fp": v.get("first_patched_version")} for v in gv]
    ra = repo_advisory(cve)
    if ra is None:
        return []
    out = []
    for v in ra.get("vulnerabilities") or []:
        pv = v.get("patched_versions")
        fp = pv.split(",")[0].strip() if pv else None  # 仓库级偶尔逗号分隔,取第一个
        out.append({"pkg": (v.get("package") or {}).get("name"),
                    "range": v.get("vulnerable_version_range") or "", "fp": fp})
    return out


def central_url(group, artifact, version):
    gp = group.replace(".", "/")
    return "https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar" % (gp, artifact, version, artifact, version)


_probe_cache = {}


def probe_central(group, artifact, version):
    """真 jar 在不在 Central。HEAD 优先,失败退 GET。结果缓存,避免重复网络往返。"""
    key = (group, artifact, version)
    if key in _probe_cache:
        return _probe_cache[key]
    url = central_url(group, artifact, version)
    ok = None
    try:
        req = urllib.request.Request(url, headers=UA, method="HEAD")
        with urllib.request.urlopen(req, timeout=60) as r:
            ok = 200 <= r.status < 300
    except urllib.error.HTTPError as e:
        if e.code == 404:
            ok = False
        else:
            # 某些镜像不认 HEAD → 退 GET 探一小段
            try:
                get(url).read(64)
                ok = True
            except urllib.error.HTTPError as e2:
                ok = False if e2.code == 404 else None
    except Exception:
        ok = None
    _probe_cache[key] = ok
    return ok


def split_coord(pkg_name):
    """'org.eclipse.jetty.ee10:jetty-ee10-jaspi' → (group, artifact)。"""
    g, a = pkg_name.split(":", 1)
    return g, a


def line_of(version):
    """版本号 → 大版本线(major.minor)。忽略 .vTIMESTAMP 尾巴。
    '9.4.58.v20250814' → '9.4';'12.0.32' → '12.0';'12.1.6' → '12.1'。"""
    m = re.match(r"(\d+)\.(\d+)", version)
    return "%s.%s" % (m.group(1), m.group(2)) if m else version


def parse_upper(rng):
    """'>= 9.4.0, <= 9.4.59' → '9.4.59';'>= 9.4.0.v..., <= 9.4.58.v20250814' → '9.4.58.v20250814'。"""
    m = re.search(r"<=?\s*([0-9][0-9A-Za-z_.\-]*)", rng)
    return m.group(1) if m else None


def collect():
    """拉全部 advisory,摊平成 rows。每 row = 一个 (cve, coordinate, line)。"""
    cve_meta = {}
    rows = []
    for cve, ghsa in CVES:
        a = advisory(cve)
        if a is None:
            raise SystemExit("🔴 %s advisory API 返回空,拒绝出表" % cve)
        cvss = (a.get("cvss_severities") or {})
        cve_meta[cve] = {
            "ghsa": a.get("ghsa_id"),
            "severity": a.get("severity"),
            "cvss_v3": cvss.get("cvss_v3", {}).get("score"),
            "cvss_v4": cvss.get("cvss_v4", {}).get("score"),
        }
        for v in vulns_of(cve, a):
            pkg = v["pkg"]
            if not pkg or ":" not in pkg:
                continue
            g, art = split_coord(pkg)
            if not g.startswith("org.eclipse.jetty"):
                continue
            upper = parse_upper(v["range"])
            if upper is None:
                continue
            line = line_of(upper)
            rows.append({
                "cve": cve, "group": g, "artifact": art, "coordinate": pkg,
                "line": line, "vulnUpper": upper, "firstPatched": v["fp"],
                "condition": ROW_CONDITIONS.get((cve, line)),
            })
    return cve_meta, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    print("拉一手源(5 条 advisory)…")
    cve_meta, rows = collect()
    for cve in CVES:
        m = cve_meta[cve[0]]
        print("  %s  sev=%s v3=%s v4=%s" % (cve[0], m["severity"], m["cvss_v3"], m["cvss_v4"]))

    print("\n探 Central(每个 firstPatched + 每条老线终版)…")
    # 探每个非空 firstPatched
    for r in rows:
        if r["firstPatched"]:
            r["fixOnCentral"] = probe_central(r["group"], r["artifact"], r["firstPatched"])
        else:
            r["fixOnCentral"] = None
    # 老线终版(A3):对每条老线的 jetty-http 探终版在不在
    tails = {
        "9.4": "9.4.58.v20250814", "10.0": "10.0.26", "11.0": "11.0.26",
    }
    tail_ok = {ln: probe_central("org.eclipse.jetty", "jetty-http", v) for ln, v in tails.items()}
    sent_ok = probe_central(*SENTINEL)

    for r in rows:
        fp = r["firstPatched"]
        mark = "" if fp is None else ("200" if r["fixOnCentral"] else ("404" if r["fixOnCentral"] is False else "??"))
        print("  %-15s %-42s line=%-5s <=%-22s fp=%-12s %s"
              % (r["cve"], r["coordinate"], r["line"], r["vulnUpper"], fp, mark))

    # ── 断言 ──────────────────────────────────────────────────────────────
    errs = []

    def need(cond, msg):
        if not cond:
            errs.append(msg)

    # A1 阳性对照:主打那条在 12.0 / 12.1 的公开修复版必须 200
    a1 = [r for r in rows if r["cve"] == MAIN_CVE and r["line"] in ("12.0", "12.1") and r["firstPatched"]]
    need(a1 and all(r["fixOnCentral"] is True for r in a1),
         "A1 阳性对照:2332 的 12.x 公开修复版竟然不是 200 —— 200 判据坏了,整表不算数")

    # A2 核心主张:三条老线中「advisory 给了版本号」的那些,在 Central 上必须 404
    a2 = [r for r in rows if r["line"] in ("9.4", "10.0", "11.0") and r["firstPatched"]]
    need(a2, "A2 三条老线一个 firstPatched 都没有 —— 核心主张的形态变了,重核")
    for r in a2:
        need(r["fixOnCentral"] is False,
             "A2 %s 老线修复版 %s 竟然在 Central 上存在(%s)—— 「公开修复版不存在」这条主张对它不成立"
             % (r["cve"], r["firstPatched"], r["coordinate"]))

    # A3 老线终版仍在(证明 404 不是「整个坐标没了」)
    for ln, v in tails.items():
        need(tail_ok[ln] is True, "A3 老线终版 %s 竟然不在 Central 上 —— 404 判据可能是坐标错" % v)

    # A4 哨兵
    need(sent_ok is False, "A4 哨兵版本 %s 竟然存在 —— 404 判据本身坏了" % SENTINEL[2])

    # A5 主打那条结构没变
    mm = cve_meta[MAIN_CVE]
    need(mm["severity"] == "high", "A5 2332 severity 不再是 high(实际 %s)" % mm["severity"])
    need(mm["cvss_v3"] == 7.4, "A5 2332 cvss_v3 不再是 7.4(实际 %s)" % mm["cvss_v3"])
    main_lines = {r["line"] for r in rows if r["cve"] == MAIN_CVE and r["coordinate"] == "org.eclipse.jetty:jetty-http"}
    need({"9.4", "10.0", "11.0"} <= main_lines,
         "A5 2332 不再覆盖 jetty-http 的 9.4/10/11 三条老线(实际 %s)" % sorted(main_lines))

    # A6 裂开的模块没被吞掉
    coords = {r["coordinate"] for r in rows}
    need(any("ee" in c and "jaspi" in c for c in coords), "A6 5795 的 ee-jaspi 模块没进表 —— 坐标被吞了")
    need(any("ee" in c and "security" in c for c in coords), "A6 10050 的 ee-security 模块没进表 —— 坐标被吞了")

    # A7 评级别渲染
    need(cve_meta["CVE-2025-11143"]["severity"] == "low", "A7 11143 不再是 low —— 文案「统称高危」的红线要重看")
    need(cve_meta["CVE-2026-6790"]["severity"] == "medium", "A7 6790 不再是 medium")

    # A8 19203(2332 同族续作,本轮新增)—— 全局库 vulns 空,靠仓库级回退,结构逐条钉死
    r19 = [r for r in rows if r["cve"] == "CVE-2026-19203"]
    need(r19, "A8 19203 一条 row 都没有 —— 仓库级回退源(REPO_ADVISORY_SRC)可能挂了(全局 advisory vulns 为空)")
    m19 = cve_meta.get("CVE-2026-19203", {})
    need(m19.get("severity") == "high", "A8 19203 severity 不再是 high(实际 %s)" % m19.get("severity"))
    r19_94 = [r for r in r19 if r["coordinate"] == "org.eclipse.jetty:jetty-http" and r["line"] == "9.4"]
    need(r19_94 and all(r["vulnUpper"] == "9.4.63" for r in r19_94),
         "A8 19203 jetty-http 9.4 线上界不再是 9.4.63(后台原话搜的就是它;实际 %s)"
         % [r["vulnUpper"] for r in r19_94])
    # 老线(9.4/10/11):官方给了修复版但 Central 404(核心信息差);12.x:给了且 200(可升)
    for r in r19:
        if r["line"] in ("9.4", "10.0", "11.0"):
            need(r["firstPatched"] and r["fixOnCentral"] is False,
                 "A8 19203 %s 线期望「官方给版本号 %s 且 Central 404」,实际 fp=%s central=%s"
                 % (r["line"], r["firstPatched"], r["firstPatched"], r["fixOnCentral"]))
        elif r["line"] in ("12.0", "12.1"):
            need(r["firstPatched"] and r["fixOnCentral"] is True,
                 "A8 19203 %s 线期望「官方给版本号且 Central 200」,实际 fp=%s central=%s"
                 % (r["line"], r["firstPatched"], r["fixOnCentral"]))
    # 12.1 线必须带默认路径 condition;9.4 线必须无(默认就中招)—— 防对默认 RFC9110 的 12.1.x 误报
    r19_121 = [r for r in r19 if r["line"] == "12.1"]
    need(r19_121 and all(r.get("condition") for r in r19_121),
         "A8 19203 12.1 线丢了默认路径 condition —— 会对默认 RFC9110 的 12.1.x 用户误报")
    need(all(not r.get("condition") for r in r19_94),
         "A8 19203 9.4 线不该有 condition(它默认就中招)")

    if errs:
        print("\n🔴 断言不过,拒绝出表:")
        for e in errs:
            print("   ·", e)
        return 1
    print("\n✅ 断言全过(A1 阳性 / A2 核心主张 / A3 老线终版 / A4 哨兵 / A5 主打结构 / A6 裂模块 / A7 评级 / A8 19203)")

    if args.dry:
        return 0

    out = Path(__file__).resolve().parents[1] / "src/main/java/dev/mikko/jettylinecheck/CveTable.java"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(cve_meta, rows), encoding="utf-8")
    print("✅ 已写 %s" % out)
    return 0


def j(s):
    if s is None:
        return "null"
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(cve_meta, rows):
    cve_src = []
    for cve, _ in CVES:
        m = cve_meta[cve]
        cve_src.append(
            "            new Cve(%s, %s, %s, %s, %s)"
            % (j(cve), j(m["ghsa"]), j(m["severity"]),
               "null" if m["cvss_v3"] is None else str(m["cvss_v3"]),
               "null" if m["cvss_v4"] is None else str(m["cvss_v4"])))
    row_src = []
    for r in sorted(rows, key=lambda x: (x["coordinate"], x["line"], x["cve"])):
        fp = r["firstPatched"]
        # fixOnCentral 三态:true=公开有 / false=404 / null=没给版本号(fp 为 null 时无意义)
        if fp is None:
            fox = "FixState.NO_VERSION_GIVEN"
        elif r["fixOnCentral"] is True:
            fox = "FixState.PUBLIC"
        elif r["fixOnCentral"] is False:
            fox = "FixState.CENTRAL_404"
        else:
            fox = "FixState.UNKNOWN"
        row_src.append(
            "            new Row(%s, %s, %s, %s, %s, %s, %s)"
            % (j(r["cve"]), j(r["coordinate"]), j(r["line"]),
               j(r["vulnUpper"]), j(fp), fox, j(r.get("condition"))))
    return TEMPLATE % {
        "main": MAIN_CVE,
        "cves": ",\n".join(cve_src),
        "rows": ",\n".join(row_src),
    }


TEMPLATE = '''package dev.mikko.jettylinecheck;

import java.util.List;

/**
 * 🔴 本文件由 {@code tools/gen_table.py} 从一手源生成 —— <b>不要手改</b>。
 * 改了下次生成会被覆盖,而且手抄一批版本号正是这个项目要打的那个错。
 *
 * <p>一手源:5 条 GitHub advisory 的 {@code vulnerabilities[]} + Maven Central 真 jar HEAD 探测。
 * 生成时七组断言全过(阳性对照 / 核心主张 / 老线终版 / 哨兵 / 主打结构 / 裂模块 / 评级)。
 *
 * <p><b>判据不是「jar 里有没有某个类」</b>(见 gen_table.py 头注):
 * 主打那条 CVE-2026-2332 的修复改的是 {@code HttpParser} 方法体、没新增类。
 * 判据是「你的坐标+版本线,命中哪几条 CVE,以及官方点名的修复版在 Central 上到底存不存在」。
 */
public final class CveTable {

    /** 主打那一条(受影响面站得住、走私 high)。 */
    public static final String MAIN_CVE = "%(main)s";

    /** 修复版可得性 —— 本工具的硬核就在这个三态上。 */
    public enum FixState {
        /** advisory 点名了修复版,且它真在 Maven Central 上(公开可升)。 */
        PUBLIC,
        /** advisory 点名了修复版,但 Central 上 404 —— 官方安全页写 "see details for availability"(商业支持)。 */
        CENTRAL_404,
        /** advisory 根本没给这条线的修复版({@code first_patched_version = null})。 */
        NO_VERSION_GIVEN,
        /** 探测本身没跑成(网络/镜像)—— 读作「没查到」,不是「有」。 */
        UNKNOWN
    }

    /** 一条 CVE 的元信息。 */
    public record Cve(String id, String ghsa, String severity, Double cvssV3, Double cvssV4) {
        /** 对外展示用的分数:优先 v3,没有再退 v4。 */
        public String scoreText() {
            if (cvssV3 != null && cvssV3 > 0) return "CVSS v3 " + cvssV3;
            if (cvssV4 != null && cvssV4 > 0) return "CVSS v4 " + cvssV4;
            return "(无 CVSS)";
        }
    }

    /**
     * 判定表的一行:某条 CVE 在某个坐标的某条版本线上的情况。
     *
     * @param cve          CVE 编号
     * @param coordinate   完整坐标,如 {@code org.eclipse.jetty:jetty-http}
     *                     或 {@code org.eclipse.jetty.ee10:jetty-ee10-jaspi}(12.x 会裂开)
     * @param line         版本线,如 {@code 9.4} / {@code 12.0}
     * @param vulnUpper    该线受影响区间的上界(闭区间),如 {@code 9.4.59}
     * @param firstPatched advisory 点名的修复版;{@code null} = 官方没给
     * @param fix          修复版可得性三态
     * @param condition    这条线只在特定配置下才命中时的一句话说明;{@code null} = 默认路径就中招。
     *                     目前只有 CVE-2026-19203 的 12.1 线用(默认 RFC9110 不受影响)。
     */
    public record Row(String cve, String coordinate, String line,
                      String vulnUpper, String firstPatched, FixState fix,
                      String condition) {
    }

    private static final List<Cve> CVES = List.of(
%(cves)s
    );

    private static final List<Row> ROWS = List.of(
%(rows)s
    );

    public static List<Cve> cves() {
        return CVES;
    }

    public static List<Row> rows() {
        return ROWS;
    }

    public static Cve cveById(String id) {
        for (Cve c : CVES) {
            if (c.id().equals(id)) return c;
        }
        return null;
    }

    /** 某个坐标 + 版本线上,登记在案的所有 CVE 行。 */
    public static List<Row> rowsFor(String coordinate, String line) {
        return ROWS.stream()
                .filter(r -> r.coordinate().equals(coordinate) && r.line().equals(line))
                .toList();
    }

    /** 这个坐标(任意线)在不在判定表里 —— 用来区分「没命中」和「根本不是我们管的构件」。 */
    public static boolean knowsCoordinate(String coordinate) {
        return ROWS.stream().anyMatch(r -> r.coordinate().equals(coordinate));
    }

    private CveTable() {
    }
}
'''


if __name__ == "__main__":
    sys.exit(main())
