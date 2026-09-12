package dev.mikko.jettylinecheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 扫描器:合成 jar 覆盖各种形状,不依赖网络。 */
class ScannerTest {

    private static Path jar(Path dir, String name, String... entries) throws IOException {
        Path p = dir.resolve(name);
        try (OutputStream os = Files.newOutputStream(p); ZipOutputStream z = new ZipOutputStream(os)) {
            for (int i = 0; i < entries.length; i += 2) {
                z.putNextEntry(new ZipEntry(entries[i]));
                z.write(entries[i + 1].getBytes(StandardCharsets.UTF_8));
                z.closeEntry();
            }
        }
        return p;
    }

    private static Path nested(Path dir, String name, Path inner, String innerPath) throws IOException {
        Path p = dir.resolve(name);
        try (OutputStream os = Files.newOutputStream(p); ZipOutputStream z = new ZipOutputStream(os)) {
            z.putNextEntry(new ZipEntry(innerPath));
            z.write(Files.readAllBytes(inner));
            z.closeEntry();
        }
        return p;
    }

    private static String pom(String group, String artifact, String version) {
        return "groupId=" + group + "\nartifactId=" + artifact + "\nversion=" + version + "\n";
    }

    @Test
    @DisplayName("pom.properties 是首选坐标源:读出完整坐标 + 版本")
    void readsPomProperties(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "jetty-http-9.4.58.jar",
                "META-INF/maven/org.eclipse.jetty/jetty-http/pom.properties",
                pom("org.eclipse.jetty", "jetty-http", "9.4.58.v20250814"));
        Scanner sc = new Scanner();
        sc.scan(j);
        assertEquals(1, sc.artifacts().size());
        Artifact a = sc.artifacts().get(0);
        assertEquals("org.eclipse.jetty:jetty-http", a.coordinate());
        assertEquals("9.4.58.v20250814", a.version());
        assertEquals("9.4", a.line());
        assertTrue(a.tracked());
    }

    @Test
    @DisplayName("没有 pom.properties 时靠 Bundle-SymbolicName 兜底,并标明是推断")
    void manifestFallback(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "repacked.jar",
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\nBundle-SymbolicName: org.eclipse.jetty.http\n"
                        + "Implementation-Version: 11.0.26\n");
        Scanner sc = new Scanner();
        sc.scan(j);
        assertEquals(1, sc.artifacts().size());
        Artifact a = sc.artifacts().get(0);
        assertTrue(a.coordinate().startsWith("org.eclipse.jetty:jetty-http"));
        assertTrue(a.coordinate().contains("推断"), "MANIFEST 兜底出来的坐标要标明是推断");
        assertEquals("11.0.26", a.version());
    }

    @Test
    @DisplayName("非 Jetty 的 jar 一个都不报")
    void irrelevantJarIgnored(@TempDir Path dir) throws IOException {
        Path j = jar(dir, "guava.jar", "com/google/common/base/Strings.class", "x");
        Scanner sc = new Scanner();
        sc.scan(j);
        assertTrue(sc.artifacts().isEmpty());
    }

    @Test
    @DisplayName("war / fat jar 里的嵌套 Jetty 构件要扫到")
    void nestedArtifacts(@TempDir Path dir) throws IOException {
        Path inner = jar(dir, "inner.jar",
                "META-INF/maven/org.eclipse.jetty/jetty-server/pom.properties",
                pom("org.eclipse.jetty", "jetty-server", "9.4.53.v20231009"));
        Path war = nested(dir, "app.war", inner, "WEB-INF/lib/jetty-server-9.4.53.jar");
        Files.delete(inner);

        Scanner sc = new Scanner();
        sc.scan(war);
        assertEquals(1, sc.artifacts().size());
        Artifact a = sc.artifacts().get(0);
        assertEquals("org.eclipse.jetty:jetty-server", a.coordinate());
        assertEquals("9.4.53.v20231009", a.version());
        assertTrue(a.source().contains("!"), "嵌套路径应带 ! 分隔");
    }

    @Test
    @DisplayName("目录扫描:递归找 jar,只留 Jetty 构件")
    void scanDirectory(@TempDir Path dir) throws IOException {
        Path lib = Files.createDirectories(dir.resolve("jetty/lib"));
        jar(lib, "jetty-http.jar",
                "META-INF/maven/org.eclipse.jetty/jetty-http/pom.properties",
                pom("org.eclipse.jetty", "jetty-http", "11.0.26"));
        jar(lib, "unrelated.jar", "foo/Bar.class", "x");
        Scanner sc = new Scanner();
        sc.scan(dir);
        assertEquals(1, sc.artifacts().size());
        assertEquals("11.0.26", sc.artifacts().get(0).version());
    }

    @Test
    @DisplayName("☠️ 坏文件(非 zip)要显式列进 skipped 且计入 unreadable,不静默吞掉")
    void brokenFileIsReported(@TempDir Path dir) throws IOException {
        Path bad = dir.resolve("broken.jar");
        Files.write(bad, "this is not a zip".getBytes(StandardCharsets.UTF_8));
        Scanner sc = new Scanner();
        sc.scan(bad);
        assertTrue(sc.artifacts().isEmpty());
        assertEquals(1, sc.unreadableCount(), "读不动必须计数 —— 否则退出码会停在 0");
        assertFalse(sc.skipped().isEmpty());
    }

    @Test
    @DisplayName("☠️ 截断的 zip(魔数对但零条目)也要判读不动,不能假装扫过")
    void truncatedZipIsReported(@TempDir Path dir) throws IOException {
        Path bad = dir.resolve("truncated.jar");
        // PK\03\04 开头但后面截断
        Files.write(bad, new byte[]{'P', 'K', 3, 4, 0, 0, 0, 0});
        Scanner sc = new Scanner();
        sc.scan(bad);
        assertEquals(1, sc.unreadableCount());
    }

    @Test
    @DisplayName("合法空 zip 不算坏文件")
    void emptyZipNotBroken(@TempDir Path dir) throws IOException {
        Path empty = dir.resolve("empty.jar");
        Files.write(empty, new byte[]{'P', 'K', 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        Scanner sc = new Scanner();
        sc.scan(empty);
        assertEquals(0, sc.unreadableCount(), "空 zip 是合法的,不该计入读不动");
    }

    @Test
    @DisplayName("路径不存在要报出来,不能当成「没问题」")
    void missingPathIsReported() {
        Scanner sc = new Scanner();
        sc.scan(Path.of("no", "such", "path.jar"));
        List<String> sk = sc.skipped();
        assertEquals(1, sk.size());
        assertTrue(sk.get(0).contains("不存在"));
    }
}
