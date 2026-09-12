package dev.mikko.jettylinecheck;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 扫描器:从目录 / jar / war / Spring Boot fat jar 里找出 Jetty 构件,读它的坐标与版本。
 *
 * <p>🔴 <b>这里不判修没修</b> —— 只负责把「这是哪个坐标、哪个版本」如实读出来,
 * 判定交给 {@link Verdict} 查 {@link CveTable}。判据是坐标+版本线,不是类的存在
 * (Jetty 这几条 CVE 的修复没新增类,见 {@code tools/gen_table.py} 头注)。
 *
 * <p>zip 防线、嵌套解压、「读不动」计数三样是从 tomcat-line-check 抄过来的,
 * <b>一个字都不许省</b> —— 少了它们,「我没能读它」会在自动化里安静地等于「你没事」。
 */
public final class Scanner {

    /** 嵌套解压深度上限。war 里套 jar 常见,再深就不正常了,防 zip bomb。 */
    private static final int MAX_DEPTH = 3;

    private final List<Artifact> found = new ArrayList<>();
    private final List<String> skipped = new ArrayList<>();

    /**
     * 有多少个文件是「读不动」的(不是 zip / 截断 / IO 失败)。
     *
     * <p>🔴 它存在的理由是退出码:留痕给人看,而 CI 与脚本看的是退出码 ——
     * 少了它,「我没能读它」在自动化里等于「通过」。用计数器而不是匹配告警文案:
     * 文案改一个字,匹配式判据就安静失效了。
     */
    private int unreadable;

    /** 读不动的文件数 —— 大于 0 时退出码不许是 0。 */
    public int unreadableCount() {
        return unreadable;
    }

    public List<Artifact> artifacts() {
        return found;
    }

    /** 扫不动的东西(坏 zip、读不了的文件)—— <b>显式列出来,不静默吞掉</b>。 */
    public List<String> skipped() {
        return skipped;
    }

    public void scan(Path p) {
        if (!Files.exists(p)) {
            skipped.add(p + " —— 路径不存在");
            return;
        }
        if (Files.isDirectory(p)) {
            scanDir(p);
        } else {
            scanArchive(p.toString(), readAll(p), 0);
        }
    }

    private void scanDir(Path dir) {
        try (var s = Files.walk(dir)) {
            s.filter(Files::isRegularFile)
                    .filter(f -> {
                        String n = f.getFileName().toString().toLowerCase(Locale.ROOT);
                        return n.endsWith(".jar") || n.endsWith(".war");
                    })
                    .forEach(f -> scanArchive(f.toString(), readAll(f), 0));
        } catch (IOException e) {
            unreadable++;
            skipped.add(dir + " —— 目录遍历失败:" + e.getMessage());
        }
    }

    private byte[] readAll(Path p) {
        try {
            return Files.readAllBytes(p);
        } catch (IOException e) {
            unreadable++;
            skipped.add(p + " —— 读不了:" + e.getMessage());
            return null;
        }
    }

    /**
     * ☠️ <b>ZipInputStream 对非 zip 内容不抛异常,只是一个条目都不给</b>。
     *
     * <p>损坏 / 加密 / 根本不是 zip 的 .jar 会静默走完扫描,得出「没扫到 Jetty」——
     * 用户会读成「我不受影响」。<b>「读不动」和「你是安全的」必须是两句话。</b>
     * 空 zip({@code PK\05\06})合法,不算坏文件。
     */
    static boolean looksLikeZip(byte[] b) {
        if (b == null || b.length < 4 || b[0] != 'P' || b[1] != 'K') {
            return false;
        }
        int c = b[2], d = b[3];
        return (c == 3 && d == 4) || (c == 5 && d == 6) || (c == 7 && d == 8);
    }

    /**
     * 是不是一个<b>合法的空 zip</b> —— 整个文件就是一条 22 字节的 EOCD 记录。
     *
     * <p>判据不是「魔数像 zip」:PK 03 04 开头但截断的文件魔数也是对的。
     * 空 zip 是真的空,不该报错;截断的必须报。
     */
    static boolean isEmptyZip(byte[] b) {
        return b != null && b.length == 22
                && b[0] == 'P' && b[1] == 'K' && b[2] == 5 && b[3] == 6;
    }

    private void scanArchive(String source, byte[] bytes, int depth) {
        if (bytes == null || depth > MAX_DEPTH) {
            return;
        }
        if (!looksLikeZip(bytes)) {
            unreadable++;
            skipped.add(source + " —— 读不动,不是有效的 zip/jar(截断、加密,或其实是个 HTML 错误页)"
                    + " —— 🔴 这不等于「里面没有 Jetty」");
            return;
        }

        String coordinate = null;
        String version = null;
        String versionFrom = null;
        // MANIFEST 兜底(Jetty 有 pom.properties,一般用不上,但重打包的构件可能只剩 MANIFEST)
        String bundleName = null;
        String implVersion = null;
        List<String> nestedNames = new ArrayList<>();
        List<byte[]> nestedBytes = new ArrayList<>();

        int entries = 0;
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                entries++;
                String name = e.getName();
                if (name.startsWith("META-INF/maven/org.eclipse.jetty")
                        && name.endsWith("/pom.properties")) {
                    Properties pr = new Properties();
                    pr.load(new ByteArrayInputStream(drain(zin)));
                    String g = pr.getProperty("groupId");
                    String a = pr.getProperty("artifactId");
                    String v = pr.getProperty("version");
                    if (g != null && a != null) {
                        coordinate = g + ":" + a;
                        version = v;
                        versionFrom = "pom.properties";
                    }
                } else if ("META-INF/MANIFEST.MF".equals(name)) {
                    String mf = new String(drain(zin), StandardCharsets.UTF_8);
                    bundleName = manifestValue(mf, "Bundle-SymbolicName");
                    implVersion = manifestValue(mf, "Implementation-Version");
                } else if (depth < MAX_DEPTH
                        && (name.endsWith(".jar") || name.endsWith(".war"))
                        && !e.isDirectory()) {
                    // war 的 WEB-INF/lib、Spring Boot fat jar 的 BOOT-INF/lib
                    nestedNames.add(source + "!" + name);
                    nestedBytes.add(drain(zin));
                }
            }
        } catch (IOException ex) {
            unreadable++;
            skipped.add(source + " —— 不是可读的 zip:" + ex.getMessage());
            return;
        }

        // 🔴 第二层防线:魔数对、也没抛异常,但一个条目都没解出来(截断 / 下载不全)。
        if (entries == 0 && !isEmptyZip(bytes)) {
            unreadable++;
            skipped.add(source + " —— 魔数像 zip,但一个条目都解不出来(多半是截断或下载不全)"
                    + " —— 🔴 这不等于「里面没有 Jetty」");
            return;
        }

        // 没有 pom.properties 时,靠 MANIFEST 的 Bundle-SymbolicName 兜底认坐标 —— 并说清楚是推断的。
        if (coordinate == null && bundleName != null && bundleName.startsWith("org.eclipse.jetty")) {
            coordinate = guessCoordinate(bundleName) + "(按 MANIFEST 推断)";
            if (version == null) {
                version = implVersion;
                versionFrom = "MANIFEST.MF";
            }
        }

        if (coordinate != null && coordinate.replace("(按 MANIFEST 推断)", "").startsWith("org.eclipse.jetty")) {
            found.add(new Artifact(source, coordinate, version, versionFrom));
        }
        for (int i = 0; i < nestedNames.size(); i++) {
            scanArchive(nestedNames.get(i), nestedBytes.get(i), depth + 1);
        }
    }

    private static byte[] drain(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    private static String manifestValue(String mf, String key) {
        for (String line : mf.split("\r?\n")) {
            if (line.startsWith(key + ":")) {
                String v = line.substring(key.length() + 1).trim();
                return v.isEmpty() ? null : v;
            }
        }
        return null;
    }

    /** {@code org.eclipse.jetty.http} → {@code org.eclipse.jetty:jetty-http}(Bundle-SymbolicName 用点,坐标用冒号+连字符)。 */
    private static String guessCoordinate(String bundle) {
        // org.eclipse.jetty.http → group=org.eclipse.jetty, artifact=jetty-http
        int idx = bundle.lastIndexOf('.');
        if (idx <= 0) {
            return bundle;
        }
        String group = bundle.substring(0, idx);
        String tail = bundle.substring(idx + 1);
        return group + ":jetty-" + tail;
    }
}
