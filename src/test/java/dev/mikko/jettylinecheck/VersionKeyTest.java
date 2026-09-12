package dev.mikko.jettylinecheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 版本号解析:两种写法都要认,比较时忽略时间戳尾巴。 */
class VersionKeyTest {

    @Test
    @DisplayName("9.4 老线的 .vTIMESTAMP 尾巴:线是 9.4,比较只看数字段")
    void timestampTail() {
        assertEquals("9.4", VersionKey.lineOf("9.4.58.v20250814"));
        VersionKey a = VersionKey.parse("9.4.58.v20250814");
        VersionKey upper = VersionKey.parse("9.4.59");
        assertTrue(a.lteq(upper), "9.4.58 应 <= 9.4.59");
        // CVE-2025-11143 的上界写的是 9.4.58(没尾巴),必须和带尾巴的判成同一个补丁号
        assertTrue(a.lteq(VersionKey.parse("9.4.58")), "9.4.58.v... 应 <= 9.4.58");
        assertTrue(VersionKey.parse("9.4.58").lteq(a), "反向也应成立(相等)");
    }

    @Test
    @DisplayName("纯号线:12.0 / 12.1 / 11.0 / 10.0")
    void plainVersions() {
        assertEquals("12.0", VersionKey.lineOf("12.0.32"));
        assertEquals("12.1", VersionKey.lineOf("12.1.6"));
        assertEquals("11.0", VersionKey.lineOf("11.0.26"));
        assertEquals("10.0", VersionKey.lineOf("10.0.27"));
    }

    @Test
    @DisplayName("比较跨补丁号:修复版 >= 上界+1 才算过区间")
    void comparison() {
        assertTrue(VersionKey.parse("12.0.32").lteq(VersionKey.parse("12.0.32")));
        assertFalse(VersionKey.parse("12.0.33").lteq(VersionKey.parse("12.0.32")),
                "12.0.33 不该 <= 12.0.32");
        assertTrue(VersionKey.parse("12.0.0").lteq(VersionKey.parse("12.0.32")));
    }

    @Test
    @DisplayName("认不出来的版本号返回 null,不硬猜")
    void garbage() {
        assertNull(VersionKey.parse(null));
        assertNull(VersionKey.parse("not-a-version"));
        assertNull(VersionKey.lineOf(""));
    }
}
