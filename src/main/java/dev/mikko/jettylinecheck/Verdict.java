package dev.mikko.jettylinecheck;

import java.util.ArrayList;
import java.util.List;

/**
 * 把一个构件的坐标+版本,翻成「你中了哪几条 CVE,以及官方叫你升的那一版存不存在」。
 *
 * <p>🔴 <b>本类的措辞有红线</b>(见 {@code README.md}「说话的边界」):
 * <ul>
 *   <li>说「缺少公开修复版 / 命中受影响区间」,<b>不说「你会被打穿」</b> ——
 *       走私(CVE-2026-2332)的危害前提是前面还有一个前端代理 / LB 且两者解读不一致,
 *       裸跑 Jetty 讲不出攻击故事。这条 CVSS 是 7.4,不是「谁装了谁完」。</li>
 *   <li>只说「Central 上 404 + 官方页写 see details for availability」,
 *       <b>不说「Jetty 把补丁藏起来卖钱」</b>(那是推断,没有一手源这么写)。</li>
 * </ul>
 */
public final class Verdict {

    /** 构件级判定档位。 */
    public enum Kind {
        /** 命中一条或多条受影响 CVE。 */
        HIT,
        /** 坐标在判定表里,版本也认得,但这条线没有命中任何登记的受影响项。 */
        CLEAN,
        /** 坐标在判定表里,但版本号读不出来 —— 给不了线级结论。 */
        UNKNOWN_VERSION,
        /** 是 Jetty 构件,但坐标不在我们覆盖的 6 条 CVE 涉及的模块里。 */
        NOT_TRACKED
    }

    /** 对某一条 CVE 的判定。 */
    public record Finding(CveTable.Cve cve, boolean affected,
                          CveTable.FixState fix, String firstPatched, String vulnUpper,
                          String condition) {

        /** 这条线是否只在特定配置下才命中(如 19203 的 12.1 线,默认 RFC9110 不受影响)。 */
        public boolean conditional() {
            return condition != null && !condition.isBlank();
        }

        /** 命中前提的一句话 —— 仅当 {@link #conditional()} 时有意义。防对默认配置用户误报。 */
        public String conditionLine() {
            return "⚠️ 前提:" + condition;
        }

        /** 修复版可得性的一句话。 */
        public String fixLine() {
            return switch (fix) {
                case PUBLIC -> "✅ 有公开修复版:升到 " + firstPatched + "(实测在 Maven Central 上)";
                case CENTRAL_404 -> "🔴 官方点名的修复版是 " + firstPatched
                        + ",但它在 Maven Central 上是 404 —— 官方安全页对这条线写的是 "
                        + "\"see details for availability\"(= 商业支持,公开渠道拿不到)";
                case NO_VERSION_GIVEN -> "🔴 官方没有给这条线任何修复版(advisory 的 first_patched 为空)"
                        + " —— 这条线要修只能跨大版本升级";
                case UNKNOWN -> "⚠️ 修复版是否存在没探成 —— 读作「没查到」,自己核一遍 " + firstPatched;
            };
        }
    }

    private final Artifact artifact;
    private final Kind kind;
    private final List<Finding> findings;

    private Verdict(Artifact a, Kind k, List<Finding> f) {
        this.artifact = a;
        this.kind = k;
        this.findings = f;
    }

    public Artifact artifact() {
        return artifact;
    }

    public Kind kind() {
        return kind;
    }

    public List<Finding> findings() {
        return findings;
    }

    /** 命中里有没有主打那条(2332,受影响面站得住的走私)。 */
    public boolean hitsMain() {
        return findings.stream().anyMatch(f -> f.affected() && f.cve().id().equals(CveTable.MAIN_CVE));
    }

    public static Verdict of(Artifact a) {
        if (!a.tracked()) {
            return new Verdict(a, Kind.NOT_TRACKED, List.of());
        }
        String line = a.line();
        VersionKey vk = VersionKey.parse(a.version());
        if (line == null || vk == null) {
            return new Verdict(a, Kind.UNKNOWN_VERSION, List.of());
        }

        List<Finding> findings = new ArrayList<>();
        for (CveTable.Row r : CveTable.rowsFor(a.coordinate(), line)) {
            VersionKey upper = VersionKey.parse(r.vulnUpper());
            boolean affected = upper != null && vk.lteq(upper);
            if (affected) {
                findings.add(new Finding(CveTable.cveById(r.cve()), true,
                        r.fix(), r.firstPatched(), r.vulnUpper(), r.condition()));
            }
        }
        return new Verdict(a, findings.isEmpty() ? Kind.CLEAN : Kind.HIT, findings);
    }
}
