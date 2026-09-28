本目录中的二进制文件为 MySQL/PostgreSQL UDF 扩展库（lib_mysqludf_sys / lib_postgresqludf_sys），
通过注入写入目标数据库的 plugin 目录并创建 sys_eval/sys_exec 等函数后，在目标数据库所在系统上执行，
不在运行本软件的系统上执行。
这些二进制遵循 GNU Lesser General Public License (LGPL) 许可，
源代码可从 udfhack 项目获取: https://github.com/sqlmapproject/udfhack
