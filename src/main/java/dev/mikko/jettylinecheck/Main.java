package dev.mikko.jettylinecheck;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * 命令行入口。
 *
 * <p>回答一个问题:<b>你这套 Jetty(或 Spring Boot 带进来的 Jetty),中了 2026 年这六条 CVE 的哪几条,
 * 而官方叫你升的那一版,在 Maven Central 上到底存不存在?</b>
 *
 * <p>最硬的一条:9.4 / 10 / 11 这三条 EOL 老线,官方安全页对多条 CVE 写着
 * "see details for availability"(= 商业支持),而那些修复版在 Central 上实测 404 ——
 * 照公告去升,你会升到一个公开渠道根本拿不到的版本。
 */
public final class Main {

    /**
     * 有文件读不动 —— 「我没能读它」不许在自动化里等于「通过」。
     *
     * <p>留痕给人看,退出码给机器看,两者缺一不可。发现真命中时不降级成它:命中比读不动更要紧。
     */
    private static final int EXIT_UNREADABLE = 4;

    public static void main(String[] args) {
        boolean utf8 = false;
        boolean showTable = false;
        List<String> paths = new ArrayList<>();
        for (String a : args) {
            switch (a) {
                case "--utf8" -> utf8 = true;
                case "--table" -> showTable = true;
                case "-h", "--help" -> {
                    usage(System.out);
                    return;
                }
                default -> paths.add(a);
            }
        }
        PrintStream out = utf8
                ? new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8)
                : System.out;

        if (showTable) {
            printTable(out);
            return;
        }
        if (paths.isEmpty()) {
            usage(out);
            System.exit(2);
            return;
        }

        Scanner sc = new Scanner();
        for (String p : paths) {
            sc.scan(Paths.get(p));
        }
        report(out, sc);
        if (sc.unreadableCount() > 0) {
            System.exit(EXIT_UNREADABLE);
        }
    }

    private static void usage(PrintStream out) {
        out.println("jetty-line-check - which of the 2026 Jetty CVEs do you hit, and does the fixed version even exist?");
        out.println("  (Chinese text garbled? re-run with --utf8)");
        out.println();
        out.println("jetty-line-check —— 你这套 Jetty 中了哪几条 2026 CVE,官方叫你升的那版存不存在");
        out.println();
        out.println("  用法:java -jar jetty-line-check.jar [选项] <Jetty 目录 | jar | war | Spring Boot fat jar> ...");
        out.println();
        out.println("  选项:");
        out.println("    --utf8    按 UTF-8 输出(Windows 控制台中文乱码时用)");
        out.println("    --table   只打印六条 CVE × 模块 × 版本线的判定表,不扫描");
        out.println();
        out.println("  它覆盖的六条(全是 org.eclipse.jetty 的 reviewed advisory,2026 年):");
        for (CveTable.Cve c : CveTable.cves()) {
            out.printf("    %-15s %-8s %s%n", c.id(), c.severity(), c.scoreText());
        }
        out.println();
        out.println("  最硬的一条:9.4 / 10 / 11 老线的修复版,官方安全页写 \"see details for availability\",");
        out.println("  而它们在 Maven Central 上是 404。本工具逐版本探过,--table 里标了 200/404。");
    }

    private static void printTable(PrintStream out) {
        header(out);
        out.printf("%-15s %-42s %-6s %-24s %s%n", "CVE", "坐标", "线", "受影响到", "修复版可得性");
        out.println("-".repeat(110));
        String prevCoord = "";
        for (CveTable.Row r : CveTable.rows()) {
            if (!r.coordinate().equals(prevCoord)) {
                out.println();
                prevCoord = r.coordinate();
            }
            out.printf("%-15s %-42s %-6s <=%-22s %s%n",
                    r.cve(), r.coordinate(), r.line(), r.vulnUpper(), fixMark(r));
        }
        out.println();
        out.println("修复版可得性:PUBLIC=Central 上有 · 404=Central 上没有(官方页 see details for availability)"
                + " · 无=官方没给版本号");
        out.println("🔴 老线(9.4 / 10.0 / 11.0)那一片 404 / 无,就是本工具的价值所在。");
    }

    private static String fixMark(CveTable.Row r) {
        return switch (r.fix()) {
            case PUBLIC -> "PUBLIC " + r.firstPatched();
            case CENTRAL_404 -> "404  " + r.firstPatched() + "(拿不到)";
            case NO_VERSION_GIVEN -> "无(官方未给)";
            case UNKNOWN -> "?? " + r.firstPatched();
        };
    }

    private static void header(PrintStream out) {
        out.println("jetty-line-check —— 2026 年 Jetty 六条 CVE × 模块 × 版本线");
        out.println("  判据:坐标 + 版本线 → 判定表 + Maven Central 真 jar 探测(不靠「有没有某个类」)");
        out.println("  主打:" + CveTable.MAIN_CVE + "(jetty-http chunked 请求走私,受影响面 = server 装机面本身)");
        out.println();
    }

    private static void report(PrintStream out, Scanner sc) {
        header(out);

        List<Artifact> arts = sc.artifacts();
        List<Verdict> tracked = new ArrayList<>();
        List<Artifact> untracked = new ArrayList<>();
        for (Artifact a : arts) {
            Verdict v = Verdict.of(a);
            if (v.kind() == Verdict.Kind.NOT_TRACKED) {
                untracked.add(a);
            } else {
                tracked.add(v);
            }
        }

        if (tracked.isEmpty() && untracked.isEmpty()) {
            out.println("没扫到任何 Jetty 构件(找的是 org.eclipse.jetty* 的 jar)。");
            printSkipped(out, sc);
            return;
        }

        int hits = 0;
        for (Verdict v : tracked) {
            Artifact a = v.artifact();
            String head = switch (v.kind()) {
                case HIT -> "🔴 命中 " + v.findings().size() + " 条";
                case CLEAN -> "✅ 这条线未命中登记的受影响项";
                case UNKNOWN_VERSION -> "⚠️ 版本号读不出来,给不了结论";
                case NOT_TRACKED -> "";
            };
            out.println(head + "   " + a.coordinate()
                    + "  " + (a.version() == null ? "(版本未知)" : a.version()));
            out.println("   路径:" + a.source()
                    + (a.versionFrom() == null ? "" : "   版本来自 " + a.versionFrom()));
            if (v.kind() == Verdict.Kind.HIT) {
                hits++;
                for (Verdict.Finding f : v.findings()) {
                    out.println("   · " + f.cve().id() + "  [" + f.cve().severity() + " / "
                            + f.cve().scoreText() + "]  受影响到 " + f.vulnUpper());
                    if (f.conditional()) {
                        out.println("       " + f.conditionLine());
                    }
                    out.println("       " + f.fixLine());
                }
            }
            out.println();
        }

        if (!untracked.isEmpty()) {
            out.println("ℹ️ 另扫到 " + untracked.size() + " 个 Jetty 构件,不在这六条 CVE 涉及的模块里(未判定):");
            for (Artifact a : untracked) {
                out.println("   · " + a.coordinate() + "  "
                        + (a.version() == null ? "(版本未知)" : a.version()));
            }
            out.println();
        }

        out.println("-".repeat(72));
        out.println("扫到 " + tracked.size() + " 个受管构件,其中 " + hits + " 个命中受影响 CVE。");
        if (hits > 0) {
            out.println();
            out.println("说话的边界(本工具不越过,你也别):");
            out.println("  · 「命中受影响区间」是构件事实;「你会被攻击」是另一回事。");
            out.println("  · 主打的 " + CveTable.MAIN_CVE + " 是请求走私:要前面有前端代理 / LB,");
            out.println("    且两端对同一请求解读不一致,才谈得上危害。这条 CVSS 是 7.4,不是「谁装了谁完」。");
            out.println("  · 「Central 上 404」是实测事实;「官方藏补丁卖钱」是你别替官方说的话。");
        }
        printSkipped(out, sc);
    }

    private static void printSkipped(PrintStream out, Scanner sc) {
        if (sc.skipped().isEmpty()) {
            return;
        }
        out.println();
        out.println("⚠️ 下面这些没扫成 —— 读作「没查到」,不是「没问题」:");
        for (String s : sc.skipped()) {
            out.println("   · " + s);
        }
    }

    private Main() {
    }
}
