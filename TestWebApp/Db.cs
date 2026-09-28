using System.Data.Common;
using Dm;
using Oracle.ManagedDataAccess.Client;
using IBM.Data.Db2;
using ClickHouse.Client.ADO;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using MySqlConnector;
using Npgsql;

namespace TestWebApp;

/// <summary>
/// 多数据库连接工厂：sqlite开箱即用（本地文件），mysql/pgsql/sqlserver/kingbase改appsettings.json里的连接串即可。
/// 人大金仓KingbaseES基于PG协议，直接用pgsql提供程序连接54321端口（PG兼容模式）。
/// </summary>
public static class Db
{
    public class DbEntry
    {
        public string Name = "";
        public string Provider = "";
        public string ConnectionString = "";
        public string Note = "";
    }

    public static readonly List<DbEntry> All = new()
    {
        new DbEntry { Name = "sqlite", Provider = "sqlite", ConnectionString = "Data Source=sqli_test.db", Note = "SQLite（内置，开箱即测）" },
        new DbEntry { Name = "mysql", Provider = "mysql", ConnectionString = "Server=127.0.0.1;Port=3307;User ID=root;Password=root;Database=sqli_test;AllowUserVariables=true", Note = "MySQL 8.0容器（sqli-mysql80@3307；本机3306无服务，与mysqlc同容器，/init?db=mysql）" },
        new DbEntry { Name = "mysqlc", Provider = "mysql", ConnectionString = "Server=127.0.0.1;Port=3307;User ID=root;Password=root;Database=sqli_test;AllowUserVariables=true", Note = "MySQL 8.0容器（sqli-mysql80，secure_file_priv为空，验证UDF命令执行/文件读写，/init?db=mysqlc）" },
        new DbEntry { Name = "pgsql", Provider = "pgsql", ConnectionString = "Host=127.0.0.1;Port=5432;Username=postgres;Password=postgres;Database=sqli_test", Note = "PostgreSQL（先手工建库sqli_test，再 /init?db=pgsql）" },
        new DbEntry { Name = "pgsql94", Provider = "pgsql", ConnectionString = "Host=127.0.0.1;Port=5433;Username=postgres;Password=postgres;Database=sqli_test", Note = "PostgreSQL 9.4（容器sqli-pgsql94，验证PG UDF lib_postgresqludf_sys通道，/init?db=pgsql94）" },
        new DbEntry { Name = "sqlserver", Provider = "sqlserver", ConnectionString = "Server=127.0.0.1,11433;User Id=sa;Password=Sa@123456;Database=sqli_test;TrustServerCertificate=true;Encrypt=false", Note = "SQLServer（/init?db=sqlserver 自动建库；1433被Windows端口保留段占用，容器映射到11433）" },
        new DbEntry { Name = "sqlserver08", Provider = "sqlserver", ConnectionString = "Server=192.168.3.70,1433;User Id=sa;Password=test@123;Database=sqli_test;TrustServerCertificate=true;Encrypt=false;Connect Timeout=10", Note = "SQLServer 2008 Windows版（192.168.3.70，/init?db=sqlserver08 自动建库；验证xp_cmdshell/OLE）" },
        new DbEntry { Name = "kingbase", Provider = "pgsql", ConnectionString = "Host=127.0.0.1;Port=54322;Username=system;Password=123456;Database=test;No Reset On Close=true", Note = "人大金仓KingbaseES V8R6（PG协议，54321被snac_agent占用改54322；容器内libfaketime冻结2021-12规避license过期）" },
        new DbEntry { Name = "dm", Provider = "dm", ConnectionString = "Server=127.0.0.1;Port=5236;User Id=SYSDBA;Password=SYSDBA001", Note = "达梦DM8（官方DmProvider，/init?db=dm 自动建表）" },
        new DbEntry { Name = "oracle", Provider = "oracle", ConnectionString = "Data Source=127.0.0.1:15210/XEPDB1;User Id=sqli;Password=Sqli12345", Note = "Oracle XE 21c（容器sqli-oracle，/init?db=oracle 自动建表）" },
        new DbEntry { Name = "opengauss", Provider = "pgsql", ConnectionString = "Host=127.0.0.1;Port=15433;Username=sqli;Password=Test@123;Database=testdb;No Reset On Close=true", Note = "openGauss 6.0（容器sqli-opengauss，PG协议；No Reset On Close规避DISCARD ALL不支持）" },
        new DbEntry { Name = "db2", Provider = "db2", ConnectionString = "Server=127.0.0.1:50010;Database=testdb;UID=db2inst1;PWD=Db2@123456", Note = "DB2 11.5.8（容器sqli-db2，/init?db=db2 校验连接，表已在容器内建好）" },
        new DbEntry { Name = "clickhouse", Provider = "clickhouse", ConnectionString = "Host=127.0.0.1;Port=18123;Username=default;Password=clickhouse;Database=sqli_test", Note = "ClickHouse 26（容器sqli-clickhouse，HTTP协议18123，/init?db=clickhouse 建表种子）" },
    };

    /// <summary>
    /// 允许用 appsettings.json 的 Databases:名称:ConnectionString 覆盖默认连接串
    /// </summary>
    public static void ApplyConfig(IConfiguration cfg)
    {
        foreach (DbEntry e in All)
        {
            string cs = cfg[$"Databases:{e.Name}:ConnectionString"];
            if (!string.IsNullOrWhiteSpace(cs))
            {
                e.ConnectionString = cs;
            }
        }
    }

    public static DbEntry Find(string name)
    {
        return All.FirstOrDefault(x => x.Name.Equals(name ?? "", StringComparison.OrdinalIgnoreCase))
            ?? throw new Exception("未知数据库：" + name + "，支持：" + string.Join(",", All.Select(x => x.Name)));
    }

    public static DbConnection Open(DbEntry e)
    {
        DbConnection conn = e.Provider switch
        {
            "sqlite" => new SqliteConnection(e.ConnectionString),
            "mysql" => new MySqlConnection(e.ConnectionString),
            "pgsql" => new NpgsqlConnection(e.ConnectionString),
            "sqlserver" => new SqlConnection(e.ConnectionString),
            "dm" => new DmConnection(e.ConnectionString),
            "oracle" => new OracleConnection(e.ConnectionString),
            "db2" => new DB2Connection(e.ConnectionString),
            "clickhouse" => new ClickHouseConnection(e.ConnectionString),
            _ => throw new Exception("未知提供程序：" + e.Provider)
        };
        conn.Open();
        return conn;
    }

    /// <summary>建表+种子数据（幂等）。返回执行日志。</summary>
    public static string Init(DbEntry e)
    {
        List<string> log = new();
        if (e.Provider == "mysql")
        {
            //先建库再重连
            DbEntry noDb = new() { Name = e.Name, Provider = e.Provider, ConnectionString = RemoveDatabase(e.ConnectionString) };
            using (DbConnection c = Open(noDb))
            {
                Exec(c, "create database if not exists sqli_test default charset utf8mb4");
                log.Add("create database sqli_test");
            }
        }
        if (e.Provider == "sqlserver")
        {
            //连接串默认带Database=sqli_test，建库阶段需先连master
            DbEntry master = new() { Name = e.Name, Provider = e.Provider, ConnectionString = RemoveDatabase(e.ConnectionString) };
            using (DbConnection c = Open(master))
            {
                Exec(c, "if not exists(select name from sys.databases where name='sqli_test') create database sqli_test");
                log.Add("create database sqli_test");
            }
        }
        using (DbConnection conn = Open(e))
        {
            foreach (string sql in SchemaSql(e.Provider))
            {
                try { Exec(conn, sql); log.Add("OK: " + sql); }
                catch (Exception ex) { log.Add("SKIP: " + ex.Message); }
            }
            //种子数据（为空才插入）
            long cnt = Convert.ToInt64(Scalar(conn, "select count(1) from users"));
            if (cnt == 0)
            {
                string[][] users = {
                    new[]{"1","admin","e10adc3949ba59abbe56e057f20f883e","admin@test.com"},
                    new[]{"2","test","123456","test@test.com"},
                    new[]{"3","zhangsan","zs888888","zhangsan@test.com"},
                };
                foreach (string[] u in users)
                {
                    Exec(conn, $"insert into users(id,username,password,email) values({u[0]},'{u[1]}','{u[2]}','{u[3]}')");
                }
                string[][] news = {
                    new[]{"1","国产数据库发展报告","达梦与人大金仓在政企市场持续增长","admin"},
                    new[]{"2","SQL注入防护指南","参数化查询是最有效的防护手段","test"},
                    new[]{"3","网络安全法实施条例","关键信息基础设施保护要求","admin"},
                    new[]{"4","数据安全评估办法","重要数据出境需安全评估","zhangsan"},
                };
                foreach (string[] n in news)
                {
                    Exec(conn, $"insert into news(id,title,content,author) values({n[0]},'{n[1]}','{n[2]}','{n[3]}')");
                }
                log.Add("seed users(3) + news(4)");
            }
            else
            {
                log.Add("已有数据，跳过种子");
            }
        }
        return string.Join("\n", log);
    }

    private static string RemoveDatabase(string cs)
    {
        return string.Join(";", cs.Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Where(p => !p.TrimStart().StartsWith("Database=", StringComparison.OrdinalIgnoreCase)));
    }

    private static IEnumerable<string> SchemaSql(string provider)
    {
        if (provider == "clickhouse")
        {
            //ClickHouse必须指定表引擎；if not exists幂等
            yield return "create table if not exists users(id Int32, username String, password String, email String) engine=MergeTree order by id";
            yield return "create table if not exists news(id Int32, title String, content String, author String) engine=MergeTree order by id";
        }
        else if (provider == "sqlserver")
        {
            yield return "if not exists(select * from sysobjects where name='users') create table users(id int primary key,username varchar(50),password varchar(100),email varchar(100))";
            yield return "if not exists(select * from sysobjects where name='news') create table news(id int primary key,title varchar(200),content varchar(2000),author varchar(50))";
        }
        else if (provider == "dm" || provider == "oracle" || provider == "db2")
        {
            //达梦/Oracle不支持if not exists；重复执行报错由Init的try/catch记为SKIP
            yield return "create table users(id int primary key,username varchar(50),password varchar(100),email varchar(100))";
            yield return "create table news(id int primary key,title varchar(200),content varchar(2000),author varchar(50))";
        }
        else
        {
            string idType = provider switch
            {
                "mysql" => "int primary key",
                "pgsql" => "int primary key",
                _ => "integer primary key"
            };
            yield return $"create table if not exists users(id {idType},username varchar(50),password varchar(100),email varchar(100))";
            yield return $"create table if not exists news(id {idType},title varchar(200),content varchar(2000),author varchar(50))";
        }
    }

    public static void Exec(DbConnection c, string sql)
    {
        using DbCommand cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    public static object Scalar(DbConnection c, string sql)
    {
        using DbCommand cmd = c.CreateCommand();
        cmd.CommandText = sql;
        return cmd.ExecuteScalar();
    }
}
