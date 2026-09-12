package dev.mikko.jettylinecheck;

/**
 * 一个被扫到的 Jetty 构件。
 *
 * <p>与 tomcat-line-check 的 Artifact 不同:那里带 {@code fixPresent}(靠类的存在判修没修),
 * 这里<b>没有那个字段</b> —— Jetty 这几条 CVE 的修复没新增类,判据只能是「坐标 + 版本线 → 判定表」。
 * 见 {@code CveTable} 与 {@code tools/gen_table.py} 的头注。
 *
 * @param source      从哪儿扫出来的(嵌套的话带 {@code !} 分隔)
 * @param coordinate  完整坐标,如 {@code org.eclipse.jetty:jetty-http}
 * @param version     读到的版本号;读不到是 {@code null}
 * @param versionFrom 版本号从哪儿读的(让人判断可不可信)
 */
public record Artifact(String source, String coordinate, String version, String versionFrom) {

    /** 大版本线;版本号读不到或认不出返回 {@code null}。 */
    public String line() {
        return VersionKey.lineOf(version);
    }

    /** 这个坐标在不在判定表里 —— 不在就是我们不覆盖的 Jetty 模块。 */
    public boolean tracked() {
        return CveTable.knowsCoordinate(coordinate);
    }
}
