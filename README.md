# jetty-line-check

**你这套 Jetty(或 Spring Boot 带进来的 Jetty),中了 2026 年这六条 CVE 的哪几条 —— 而官方叫你升的那一版,在 Maven Central 上到底存不存在?**

主打 **CVE-2026-2332**(`GHSA-355h-qmc2-wpwf`,high / CVSS v3 7.4):jetty-http 的 chunked 请求走私。
**2026-09-17 官方又发了同族的 CVE-2026-19203**(LF EXT.TERM 走私,high / CVSS v4 8.3):它的 9.4 线覆盖到 **9.4.63**,
官方叫你升 **9.4.64** —— 而 9.4.64 在 Central 上同样 **404**。
最硬的一条事实:**9.4 / 10 / 11 这三条 EOL 老线的公开修复版根本不存在** —— 官方安全页对它们逐条写着
`see details for availability`(= 商业支持),而那些版本号在 Maven Central 上实测全部 404。

```
java -jar jetty-line-check.jar /path/to/jetty         # 解压部署的 Jetty(扫 lib/*.jar)
java -jar jetty-line-check.jar app.war                # war
java -jar jetty-line-check.jar app.jar                # Spring Boot fat jar
java -jar jetty-line-check.jar --table                # 只看六条 CVE × 模块 × 版本线的判定表
java -jar jetty-line-check.jar --utf8 ...             # Windows 控制台中文乱码时加
```

## 判据:坐标 + 版本线 → 判定表 + Central 真 jar 探测

姊妹项目 [tomcat-line-check](https://github.com/xiaoqiMikko/tomcat-line-check) 的判据是「jar 里有没有某个修复类」,
因为 Tomcat 那次修复**新增了一个类**。

**Jetty 这几条不行。** 主打的 CVE-2026-2332,其修复改的是 `HttpParser` 的**方法体**、没有新增任何类
(建造前用 `gh api compare` + `javap` 坐实过)。所以判据只能是:

> **你的完整坐标 + 版本线,命中哪几条 CVE;以及官方点名的修复版,在 Maven Central 上到底存不存在。**

判定表由 `tools/gen_table.py` 从**六条 GitHub advisory 的 `vulnerabilities[]` + Maven Central 真 jar HEAD 探测**生成,
七组断言(阳性对照 / 核心主张 / 老线终版 / 哨兵 / 主打结构 / 裂模块 / 评级)不过就拒绝出表。

## 修复版可得性的三态(本工具的硬核)

| 三态 | 含义 |
|---|---|
| `PUBLIC` | advisory 点名了修复版,且它**真在** Maven Central 上 —— 公开可升 |
| `404` | advisory 点名了修复版,但它在 Central 上**是 404** —— 官方安全页写 `see details for availability`(商业支持) |
| `无` | advisory **根本没给**这条线的修复版(`first_patched_version` 为空)—— 这条线要修只能跨大版本升级 |

老线(9.4 / 10.0 / 11.0)那一整片 `404` 与 `无`,就是本工具的价值所在。跑 `--table` 看全貌。

## 覆盖的六条(全是 `org.eclipse.jetty` 的 reviewed advisory,2026 年)

| CVE | 模块 | 评级 | 一句话 |
|---|---|---|---|
| **CVE-2026-2332** | jetty-http | high / v3 7.4 | ⭐ 主打:chunked quoted-string 里的 `\r\n` 被当分块头结束 → 请求走私(CWE-444) |
| **CVE-2026-19203** | jetty-http | high / v4 8.3 | ⭐ 2332 同族续作(09-17):chunk 扩展里的 `\n`(LF)被当分块头结束 → 走私(LF EXT.TERM);9.4 线覆盖到 9.4.63 |
| CVE-2026-5795 | jaspi(12.x 裂成 ee8/9/10/11-jaspi) | high / v3 7.4 | JASPI 的 ThreadLocal 未清 → 越权 |
| CVE-2026-6790 | jetty-server | medium / v3 5.3 | HTTP/2·3 的 Host / `:authority` 混淆 |
| CVE-2026-10050 | jetty-security(12.x 加 ee8/9-security) | high / v4 8.7 | Digest 认证 ISO-8859-1 处理 |
| CVE-2025-11143 | jetty-http | low / v3 3.7 | URI 解析差异 |

🔴 **两条走私(2332 与 19203)的受影响面站得住**(都落在 `ServerConnector` / `HttpParser` 这条默认解析主路径上,
不需要开任何特定功能)。其余四条只当判定表里的一行:

- ⚠️ **19203 的 12.1 线是例外**:12.1.x 默认 RFC9110 合规模式**不受影响**,只有显式配置 RFC7230 / RFC2616 才命中 ——
  本工具对 12.1.x 会标出这个前提(`--table` 与扫描输出里都有),别对默认部署误报。9.4 / 10 / 11 / 12.0 线则默认就中招。
- `CVE-2026-10050`(Digest)的受影响面很小 —— 要显式启用 Digest 认证才碰得到,别当主卖点。
- `CVE-2026-6790` 是 **medium**、`CVE-2025-11143` 是 **low** —— **不许统称「高危」**。

## 说话的边界(本工具不越过,你也别)

- **「命中受影响区间」是构件事实;「你会被攻击」是另一回事。** 本工具的措辞一律是前者。
- **主打的两条(CVE-2026-2332 / CVE-2026-19203)都是请求走私:** 要前面还有一个前端代理 / LB,且两端对同一请求解读不一致,
  才谈得上危害。裸跑的 Jetty 上讲不出攻击故事 —— 这两条 CVSS 分别是 **v3 7.4 / v4 8.3**,不是「谁装了谁完」。
- **19203「全局漏洞库拿不到区间」是实测(截至发文当天):** 它的全局 advisory `vulnerabilities` 为空,
  Dependabot 报得出「有这个洞」却给不出「升到哪」;区间只在仓库级 advisory 里。**一旦全局库补上,这句要改。**
- **「Central 上 404」是实测事实;「官方把补丁藏起来卖钱」是你别替官方说的话。**
  官方页面自己写的是 `see details for availability`,到此为止。
- **也不是「Jetty 不发版了」** —— 12.0 / 12.1 线仍在更新,那两条线的公开修复版都在 Central 上。

## 一手源

- 主打 advisory:<https://github.com/advisories/GHSA-355h-qmc2-wpwf>(2332,含可跑 PoC 与 Funky Chunks 研究链接)
- 19203(2332 同族续作,LF EXT.TERM):仓库级 <https://github.com/jetty/jetty.project/security/advisories/GHSA-xc35-c22g-239h>(区间与 PoC 在这;全局 `GHSA-p2j5-5566-vpv9` 的 vulnerabilities 为空)
- 另四条:`GHSA-r7p8-xq5m-436c` · `GHSA-7p3p-8qv8-m2vh` · `GHSA-2fvj-hgj9-j2gr` · `GHSA-wjpw-4j6x-6rwh`
- 官方安全页(`see details for availability` 出处):<https://jetty.org/security.html>
- 版本线 EOL:<https://jetty.org/download.html>

## 重新生成 / 发文前复核

```bash
python tools/gen_table.py --dry              # 只跑断言,不写文件
python tools/gen_table.py                    # 断言全过才写 CveTable.java
python tools/recheck_before_publish.py       # 发文当天重跑,主张失效就改文案别改判据
```

## 构建

```bash
mvn package      # 需要 JDK 17;运行时零依赖(JUnit 仅测试期)
```

## 退出码

| 码 | 含义 |
|---|---|
| `0` | 扫完了,**并且每个文件都真的读进去了** |
| `2` | 用法错误(没给路径) |
| `4` | **有文件读不动** —— 不是 zip、内容截断、或读取失败 |

🔴 **`4` 的理由:** 留痕是给人看的,**CI 和脚本看的是退出码**。少了它,一个损坏 / 加密 / 下载不全的 jar
会安静地变成一句「没发现问题」——「我读不动它」和「你是安全的」必须是两句话。
⚠️ 合法的空 jar(一条 22 字节的 EOCD 记录)不算读不动,不会触发 `4`。

## License

MIT
