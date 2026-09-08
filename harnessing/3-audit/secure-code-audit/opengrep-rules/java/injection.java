import java.sql.Connection;
import java.sql.Statement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.persistence.EntityManager;

class InjectionTests {

    void sql(Statement stmt, Connection conn, EntityManager em, String user) throws Exception {
        // ruleid: traust-java-injection-sql-concat
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
        // ruleid: traust-java-injection-sql-concat
        stmt.executeUpdate("DELETE FROM sessions WHERE owner = '" + user + "'");
        // ruleid: traust-java-injection-sql-concat
        stmt.execute("UPDATE t SET v = 1 WHERE k = '" + user);
        // ruleid: traust-java-injection-sql-concat
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = '" + user + "'");
        // ruleid: traust-java-injection-sql-concat
        em.createNativeQuery("SELECT * FROM users WHERE name = '" + user + "'");

        // ok: traust-java-injection-sql-concat
        PreparedStatement safe = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        safe.setString(1, user);
        // ok: traust-java-injection-sql-concat
        ResultSet fixed = stmt.executeQuery("SELECT COUNT(*) FROM users");
    }

    void exec(String host) throws Exception {
        // ruleid: traust-java-injection-exec-concat
        Runtime.getRuntime().exec("ping -c 1 " + host);
        Runtime rt = Runtime.getRuntime();
        // ruleid: traust-java-injection-exec-concat
        rt.exec("nslookup " + host + " 8.8.8.8");
        // ruleid: traust-java-injection-exec-concat
        new ProcessBuilder("sh", "-c", "dig " + host);

        // ok: traust-java-injection-exec-concat
        Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", host});
        // ok: traust-java-injection-exec-concat
        new ProcessBuilder("ping", "-c", "1", host);
    }
}
