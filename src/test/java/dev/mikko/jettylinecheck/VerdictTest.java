package dev.mikko.jettylinecheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 判定核心:直接构造 Artifact,打生成表里的真实场景。
 *
 * <p>🔴 这些断言的数字都来自 {@code CveTable}(由 {@code tools/gen_table.py} 从一手源生成)。
 * 若上游改了区间 / 修复版可得性,gen_table 的 A1~A7 会先拦下,这里跟着改。
 */
class VerdictTest {

    private static Artifact art(String coord, String ver) {
        return new Artifact("(test)", coord, ver, "test");
    }

    private static Optional<Verdict.Finding> finding(Verdict v, String cve) {
        return v.findings().stream().filter(f -> f.cve().id().equals(cve)).findFirst();
    }

    @Test
    @DisplayName("🔴 主打场景:jetty-http 9.4.58 老线 —— 命中 2332,且修复版 Central 404")
    void oldLineHttpHitsMainSmuggling() {
        Verdict v = Verdict.of(art("org.eclipse.jetty:jetty-http", "9.4.58.v20250814"));
        assertEquals(Verdict.Kind.HIT, v.kind());
        assertTrue(v.hitsMain(), "9.4 老线的 jetty-http 应命中主打的 CVE-2026-2332");

        Optional<Verdict.Finding> smug = finding(v, "CVE-2026-2332");
        assertTrue(smug.isPresent());
        assertEquals(CveTable.FixState.CENTRAL_404, smug.get().fix(),
                "2332 的 9.4 修复版官方点名了但 Central 404");
        assertTrue(smug.get().fixLine().contains("see details for availability"));

        // 同一构件还命中 11143(low),但那条官方连版本号都没给
        Optional<Verdict.Finding> uri = finding(v, "CVE-2025-11143");
        assertTrue(uri.isPresent());
        assertEquals(CveTable.FixState.NO_VERSION_GIVEN, uri.get().fix());
    }

    @Test
    @DisplayName("12.0.32 命中 2332,但这条有公开修复版可升(PUBLIC)")
    void line120HasPublicFix() {
        Verdict v = Verdict.of(art("org.eclipse.jetty:jetty-http", "12.0.32"));
        assertEquals(Verdict.Kind.HIT, v.kind());
        Optional<Verdict.Finding> smug = finding(v, "CVE-2026-2332");
        assertTrue(smug.isPresent());
        assertEquals(CveTable.FixState.PUBLIC, smug.get().fix());
        assertTrue(smug.get().fixLine().contains("12.0.33"));
    }

    @Test
    @DisplayName("12.0.33 已过 2332 区间,且未命中其它 → CLEAN")
    void line12033Clean() {
        Verdict v = Verdict.of(art("org.eclipse.jetty:jetty-http", "12.0.33"));
        assertEquals(Verdict.Kind.CLEAN, v.kind());
        assertFalse(v.hitsMain());
    }

    @Test
    @DisplayName("jetty-security 老线命中 10050(第 15 注判死那条,受影响面小,只当判定表一行)")
    void securityHits10050() {
        Verdict v = Verdict.of(art("org.eclipse.jetty:jetty-security", "10.0.26"));
        assertEquals(Verdict.Kind.HIT, v.kind());
        Optional<Verdict.Finding> f = finding(v, "CVE-2026-10050");
        assertTrue(f.isPresent());
        assertEquals(CveTable.FixState.CENTRAL_404, f.get().fix());
    }

    @Test
    @DisplayName("jetty-server 老线命中 6790(medium),官方没给任何修复版")
    void serverHits6790NoFix() {
        Verdict v = Verdict.of(art("org.eclipse.jetty:jetty-server", "11.0.26"));
        assertEquals(Verdict.Kind.HIT, v.kind());
        Optional<Verdict.Finding> f = finding(v, "CVE-2026-6790");
        assertTrue(f.isPresent());
        assertEquals(CveTable.FixState.NO_VERSION_GIVEN, f.get().fix());
        assertEquals("medium", f.get().cve().severity(), "6790 是 medium,别渲染成高危");
    }

    @Test
    @DisplayName("光 jetty-jaspi 只在 9.4/10/11 老线上;老线命中 5795")
    void jaspiOldLineHits5795() {
        Verdict v = Verdict.of(art("org.eclipse.jetty:jetty-jaspi", "9.4.60"));
        assertEquals(Verdict.Kind.HIT, v.kind());
        assertTrue(finding(v, "CVE-2026-5795").isPresent());
    }

    @Test
    @DisplayName("版本号读不出来时判 UNKNOWN_VERSION,不硬猜")
    void unknownVersion() {
        Verdict v = Verdict.of(art("org.eclipse.jetty:jetty-http", null));
        assertEquals(Verdict.Kind.UNKNOWN_VERSION, v.kind());
    }

    @Test
    @DisplayName("是 Jetty 但坐标不在这五条 CVE 涉及的模块里 → NOT_TRACKED")
    void untrackedJettyModule() {
        Verdict v = Verdict.of(art("org.eclipse.jetty:jetty-util", "9.4.58.v20250814"));
        assertEquals(Verdict.Kind.NOT_TRACKED, v.kind());
    }

    @Test
    @DisplayName("生成表自证:主打 CVE 覆盖 jetty-http 的三条老线,且都是 404")
    void tableSelfCheck() {
        for (String line : new String[]{"9.4", "10.0", "11.0"}) {
            Optional<CveTable.Row> row = CveTable.rowsFor("org.eclipse.jetty:jetty-http", line).stream()
                    .filter(r -> r.cve().equals(CveTable.MAIN_CVE)).findFirst();
            assertTrue(row.isPresent(), "主打 CVE 应覆盖 jetty-http " + line + " 线");
            assertEquals(CveTable.FixState.CENTRAL_404, row.get().fix(),
                    line + " 线的修复版应是 Central 404");
        }
        assertNotNull(CveTable.cveById(CveTable.MAIN_CVE));
    }
}
