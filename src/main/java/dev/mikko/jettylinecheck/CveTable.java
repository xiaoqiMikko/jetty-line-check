package dev.mikko.jettylinecheck;

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
    public static final String MAIN_CVE = "CVE-2026-2332";

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
     */
    public record Row(String cve, String coordinate, String line,
                      String vulnUpper, String firstPatched, FixState fix) {
    }

    private static final List<Cve> CVES = List.of(
            new Cve("CVE-2026-2332", "GHSA-355h-qmc2-wpwf", "high", 7.4, 0.0),
            new Cve("CVE-2026-5795", "GHSA-r7p8-xq5m-436c", "high", 7.4, 0.0),
            new Cve("CVE-2026-6790", "GHSA-7p3p-8qv8-m2vh", "medium", 5.3, 0.0),
            new Cve("CVE-2026-10050", "GHSA-2fvj-hgj9-j2gr", "high", 0.0, 8.7),
            new Cve("CVE-2025-11143", "GHSA-wjpw-4j6x-6rwh", "low", 3.7, 0.0)
    );

    private static final List<Row> ROWS = List.of(
            new Row("CVE-2026-5795", "org.eclipse.jetty.ee10:jetty-ee10-jaspi", "12.0", "12.0.33", "12.0.34", FixState.PUBLIC),
            new Row("CVE-2026-5795", "org.eclipse.jetty.ee10:jetty-ee10-jaspi", "12.1", "12.1.7", "12.1.8", FixState.PUBLIC),
            new Row("CVE-2026-5795", "org.eclipse.jetty.ee11:jetty-ee11-jaspi", "12.0", "12.0.33", "12.0.34", FixState.CENTRAL_404),
            new Row("CVE-2026-5795", "org.eclipse.jetty.ee11:jetty-ee11-jaspi", "12.1", "12.1.7", "12.1.8", FixState.PUBLIC),
            new Row("CVE-2026-5795", "org.eclipse.jetty.ee8:jetty-ee8-jaspi", "12.0", "12.0.33", "12.0.34", FixState.PUBLIC),
            new Row("CVE-2026-5795", "org.eclipse.jetty.ee8:jetty-ee8-jaspi", "12.1", "12.1.7", "12.1.8", FixState.PUBLIC),
            new Row("CVE-2026-10050", "org.eclipse.jetty.ee8:jetty-ee8-security", "12.0", "12.0.35", "12.0.36", FixState.PUBLIC),
            new Row("CVE-2026-10050", "org.eclipse.jetty.ee8:jetty-ee8-security", "12.1", "12.1.9", "12.1.10", FixState.PUBLIC),
            new Row("CVE-2026-5795", "org.eclipse.jetty.ee9:jetty-ee9-jaspi", "12.0", "12.0.33", "12.0.34", FixState.PUBLIC),
            new Row("CVE-2026-5795", "org.eclipse.jetty.ee9:jetty-ee9-jaspi", "12.1", "12.1.7", "12.1.8", FixState.PUBLIC),
            new Row("CVE-2026-10050", "org.eclipse.jetty.ee9:jetty-ee9-security", "12.0", "12.0.35", "12.0.36", FixState.PUBLIC),
            new Row("CVE-2026-10050", "org.eclipse.jetty.ee9:jetty-ee9-security", "12.1", "12.1.9", "12.1.10", FixState.PUBLIC),
            new Row("CVE-2025-11143", "org.eclipse.jetty:jetty-http", "10.0", "10.0.26", null, FixState.NO_VERSION_GIVEN),
            new Row("CVE-2026-2332", "org.eclipse.jetty:jetty-http", "10.0", "10.0.27", "10.0.28", FixState.CENTRAL_404),
            new Row("CVE-2025-11143", "org.eclipse.jetty:jetty-http", "11.0", "11.0.26", null, FixState.NO_VERSION_GIVEN),
            new Row("CVE-2026-2332", "org.eclipse.jetty:jetty-http", "11.0", "11.0.28", "11.0.29", FixState.CENTRAL_404),
            new Row("CVE-2025-11143", "org.eclipse.jetty:jetty-http", "12.0", "12.0.30", "12.0.31", FixState.PUBLIC),
            new Row("CVE-2026-2332", "org.eclipse.jetty:jetty-http", "12.0", "12.0.32", "12.0.33", FixState.PUBLIC),
            new Row("CVE-2025-11143", "org.eclipse.jetty:jetty-http", "12.1", "12.1.4", "12.1.5", FixState.PUBLIC),
            new Row("CVE-2026-2332", "org.eclipse.jetty:jetty-http", "12.1", "12.1.6", "12.1.7", FixState.PUBLIC),
            new Row("CVE-2025-11143", "org.eclipse.jetty:jetty-http", "9.4", "9.4.58", null, FixState.NO_VERSION_GIVEN),
            new Row("CVE-2026-2332", "org.eclipse.jetty:jetty-http", "9.4", "9.4.59", "9.4.60", FixState.CENTRAL_404),
            new Row("CVE-2026-5795", "org.eclipse.jetty:jetty-jaspi", "10.0", "10.0.28", "10.0.29", FixState.CENTRAL_404),
            new Row("CVE-2026-5795", "org.eclipse.jetty:jetty-jaspi", "11.0", "11.0.28", "11.0.29", FixState.CENTRAL_404),
            new Row("CVE-2026-5795", "org.eclipse.jetty:jetty-jaspi", "9.4", "9.4.60", "9.4.61", FixState.CENTRAL_404),
            new Row("CVE-2026-10050", "org.eclipse.jetty:jetty-security", "10.0", "10.0.26", "10.0.31", FixState.CENTRAL_404),
            new Row("CVE-2026-10050", "org.eclipse.jetty:jetty-security", "11.0", "11.0.26", "11.0.31", FixState.CENTRAL_404),
            new Row("CVE-2026-10050", "org.eclipse.jetty:jetty-security", "12.0", "12.0.35", "12.0.36", FixState.PUBLIC),
            new Row("CVE-2026-10050", "org.eclipse.jetty:jetty-security", "12.1", "12.1.9", "12.1.10", FixState.PUBLIC),
            new Row("CVE-2026-10050", "org.eclipse.jetty:jetty-security", "9.4", "9.4.58.v20250814", "9.4.63", FixState.CENTRAL_404),
            new Row("CVE-2026-6790", "org.eclipse.jetty:jetty-server", "10.0", "10.0.26", null, FixState.NO_VERSION_GIVEN),
            new Row("CVE-2026-6790", "org.eclipse.jetty:jetty-server", "11.0", "11.0.26", null, FixState.NO_VERSION_GIVEN),
            new Row("CVE-2026-6790", "org.eclipse.jetty:jetty-server", "12.0", "12.0.34", "12.0.35", FixState.PUBLIC),
            new Row("CVE-2026-6790", "org.eclipse.jetty:jetty-server", "12.1", "12.1.8", "12.1.9", FixState.PUBLIC),
            new Row("CVE-2026-6790", "org.eclipse.jetty:jetty-server", "9.4", "9.4.58.v20250814", null, FixState.NO_VERSION_GIVEN)
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
