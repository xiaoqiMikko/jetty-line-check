package dev.mikko.jettylinecheck;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Jetty 版本号的解析与比较。
 *
 * <p>🔴 Jetty 的版本号有两种写法,同一个工具都要认:
 * <ul>
 *   <li>9.4 老线带时间戳尾巴:{@code 9.4.58.v20250814};</li>
 *   <li>10 / 11 / 12 线是纯号:{@code 11.0.26} / {@code 12.0.32}。</li>
 * </ul>
 *
 * <p>比较时<b>只看前面的数字段,{@code .vTIMESTAMP} 当构建元数据丢掉</b> ——
 * advisory 的区间上界写的是 {@code 9.4.58.v20250814},而 CVE-2025-11143 的上界写的是
 * {@code 9.4.58}(没尾巴),两者必须判成同一个补丁号 58。
 */
public final class VersionKey {

    private static final Pattern NUM = Pattern.compile("(\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?");

    private final int major;
    private final int minor;
    private final int patch;

    private VersionKey(int major, int minor, int patch) {
        this.major = major;
        this.minor = minor;
        this.patch = patch;
    }

    /** 解析一个版本号;认不出数字段时返回 {@code null}(读作「没查到」,不硬猜)。 */
    public static VersionKey parse(String v) {
        if (v == null) {
            return null;
        }
        Matcher m = NUM.matcher(v.trim());
        if (!m.lookingAt()) {
            return null;
        }
        int major = Integer.parseInt(m.group(1));
        int minor = m.group(2) == null ? 0 : Integer.parseInt(m.group(2));
        int patch = m.group(3) == null ? 0 : Integer.parseInt(m.group(3));
        return new VersionKey(major, minor, patch);
    }

    /** 大版本线,如 {@code 9.4} / {@code 12.0} —— 与 {@code CveTable.Row#line()} 同口径。 */
    public String line() {
        return major + "." + minor;
    }

    /** 从版本号直接取线;认不出返回 {@code null}。 */
    public static String lineOf(String v) {
        VersionKey k = parse(v);
        return k == null ? null : k.line();
    }

    /** {@code this <= other} 吗(只比数字段,忽略时间戳尾巴)。 */
    public boolean lteq(VersionKey other) {
        if (other == null) {
            return false;
        }
        if (major != other.major) {
            return major < other.major;
        }
        if (minor != other.minor) {
            return minor < other.minor;
        }
        return patch <= other.patch;
    }

    @Override
    public String toString() {
        return major + "." + minor + "." + patch;
    }
}
