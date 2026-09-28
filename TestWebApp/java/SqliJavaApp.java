import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

/**
 * H2/HSQLDB SQL注入靶场（嵌入式库，读写的文件=本机文件）。
 * 端点与TestWebApp对齐：/init?db=h2|hsqldb 建表种子；/num?db=h2&id=1 数字型注入点（错误回显在.err区）。
 * 用法：java -cp .;h2.jar;hsqldb.jar SqliJavaApp  （监听 127.0.0.1:5098）
 */
public class SqliJavaApp {
    static final Map<String, Connection> CONNS = new HashMap<>();

    public static void main(String[] args) throws Exception {
        Class.forName("org.h2.Driver");
        Class.forName("org.hsqldb.jdbc.JDBCDriver");
        CONNS.put("h2", DriverManager.getConnection("jdbc:h2:./h2db", "sa", ""));
        CONNS.put("hsqldb", DriverManager.getConnection("jdbc:hsqldb:file:./hsqldb;shutdown=true", "SA", ""));

        int port = args.length > 0 ? Integer.parseInt(args[0]) : 5098;
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/init", SqliJavaApp::handleInit);
        server.createContext("/num", SqliJavaApp::handleNum);
        server.setExecutor(null);
        server.start();
        System.out.println("SqliJavaApp listening on 127.0.0.1:" + port + " (h2/hsqldb)");
    }

    static void handleInit(HttpExchange ex) throws IOException {
        String db = param(ex, "db");
        StringBuilder log = new StringBuilder();
        try {
            Connection c = CONNS.get(db);
            if (c == null) throw new Exception("未知数据库:" + db);
            try { exec(c, "create table users(id int primary key,username varchar(50),password varchar(100),email varchar(100))"); log.append("OK: users\n"); }
            catch (Exception e) { log.append("SKIP: ").append(msg(e)).append("\n"); }
            try { exec(c, "create table news(id int primary key,title varchar(200),content varchar(2000),author varchar(50))"); log.append("OK: news\n"); }
            catch (Exception e) { log.append("SKIP: ").append(msg(e)).append("\n"); }
            Integer cnt = scalarInt(c, "select count(1) from users");
            if (cnt != null && cnt == 0) {
                exec(c, "insert into users values(1,'admin','e10adc3949ba59abbe56e057f20f883e','admin@test.com')");
                exec(c, "insert into users values(2,'test','123456','test@test.com')");
                exec(c, "insert into users values(3,'zhangsan','zs888888','zhangsan@test.com')");
                exec(c, "insert into news values(1,'国产数据库发展报告','达梦与人大金仓在政企市场持续增长','admin')");
                exec(c, "insert into news values(2,'SQL注入防护指南','参数化查询是最有效的防护手段','test')");
                exec(c, "insert into news values(3,'网络安全法实施条例','关键信息基础设施保护要求','admin')");
                exec(c, "insert into news values(4,'数据安全评估办法','重要数据出境需安全评估','zhangsan')");
                log.append("seed users(3) + news(4)");
            } else {
                log.append("已有数据，跳过种子");
            }
        } catch (Exception e) {
            log.append("ERROR: ").append(msg(e));
        }
        respond(ex, "<h3>init " + db + "</h3><pre>" + esc(log.toString()) + "</pre>");
    }

    static void handleNum(HttpExchange ex) throws IOException {
        String db = param(ex, "db");
        String id = param(ex, "id");
        String sql = "select id,title,content,author from news where id=" + id;
        StringBuilder rows = new StringBuilder();
        String err = "";
        try {
            Connection c = CONNS.get(db);
            if (c == null) throw new Exception("未知数据库:" + db);
            //允许堆叠语句（分号分隔多语句依次执行），最后一个select的结果集用于回显
            String[] parts = sql.split(";");
            Statement st = c.createStatement();
            for (int i = 0; i < parts.length; i++) {
                String part = parts[i].trim();
                //跳过空段与纯注释段（注入payload常以 -- 收尾）
                if (part.isEmpty() || part.startsWith("--")) continue;
                boolean hasResult = st.execute(part);
                if (i == parts.length - 1 && hasResult) {
                    ResultSet rs = st.getResultSet();
                    while (rs.next()) {
                        rows.append("<li>").append(rs.getString(1)).append(" | ")
                            .append(rs.getString(2)).append(" | ").append(rs.getString(3))
                            .append(" | ").append(rs.getString(4)).append("</li>");
                    }
                    rs.close();
                }
            }
            st.close();
        } catch (Exception e) {
            err = "<div class=err>" + esc(msg(e)) + "</div>";
        }
        String html = "<h3>数字型注入点 /num（" + db + "）</h3><div class=sql>执行SQL：" + esc(sql) + "</div>"
            + err + "<ul>" + rows + "</ul>";
        respond(ex, html);
    }

    static void exec(Connection c, String sql) throws SQLException {
        try (Statement st = c.createStatement()) { st.execute(sql); }
    }

    static Integer scalarInt(Connection c, String sql) {
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : null;
        } catch (Exception e) { return null; }
    }

    static String param(HttpExchange ex, String name) {
        String q = ex.getRequestURI().getRawQuery();
        if (q == null) return "";
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0 && kv.substring(0, i).equals(name)) {
                try { return URLDecoder.decode(kv.substring(i + 1), "UTF-8"); }
                catch (Exception e) { return kv.substring(i + 1); }
            }
        }
        return "";
    }

    static String msg(Throwable e) {
        String m = e.getMessage();
        return m == null ? e.toString() : m;
    }

    static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    static void respond(HttpExchange ex, String body) throws IOException {
        String html = "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
            + "<style>body{font-family:Consolas,monospace;margin:24px;background:#f7f7f7;color:#222}"
            + ".err{background:#ffecec;border:1px solid #f00;padding:8px;margin:8px 0;white-space:pre-wrap;color:#a00}"
            + ".sql{background:#eef;border:1px dashed #66f;padding:6px;margin:6px 0;font-size:13px}li{margin:4px 0}</style>"
            + "</head><body>" + body + "</body></html>";
        byte[] b = html.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
