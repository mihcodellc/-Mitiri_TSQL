create or alter proc sp_MIHCode_Permission
@loginuser sysname = NULL,
@Permission sysname = NULL,
@userDB sysname = NULL
as
begin

/***
   Changes - for the full list of improvements and fixes in this version, see:
   https://github.com/users/mihcodellc/projects/2  

MIT Licence

Project: Mitiri_TSQL

Copyright (c) 2022 MIH Code LLC

     Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

***/

-- consider sp_help_permissions instead if don't have impersonate permission
/*
Last update 10/19/2022 : Monktar Bello - fixed not return objects' permission on @userDB 
 4/5/2022 : Monktar Bello - put in @UserDB and filtered with @LoginUser  
*/
/*============================================================================
  File:     UserPermission_DB_Server.sql
  Summary:  
	   Run without a specific permission, it returns 
		  -all single database principals with their permissions 4238
	   
	   it loop through all databases & current server

  	   Mainly, I'm using "fn_my_permissions" & "execute as" for each principal.
	   I need to work on implicit(inherit) permissions. one solution should be to customize "fn_my_permissions"

	   SET @permission IF you need to exclude an EXPLICIT permission DEFAULTED TO '%SELECT%'.
	   @permission prevails over @LoginUser
	   Get permissions on server need "execute as login" 
	   Get permissions on db need "execute as user".
	   
	   name like '##%' 
	   name like 'NT%'  
	   name of type IN ('G','R', 'C') are excluded -- group, role, certificate
		  details about the above 3 names come from : 
			 sys.server_principals, 
			 server_permissions,  
			 database_principals, 
			 database_permissions

	   name in 'public', 'INFORMATION_SCHEMA','sys' are excluded

				
  Date:     March 2021
  Version:	SQL Server 2017
------------------------------------------------------------------------------
  Written by Monktar Bello
============================================================================*/


set nocount on;
set transaction isolation level read uncommitted


declare @canImpersonate int, @type char(1), @db sysname 
declare @query nvarchar(2000)
declare @clause nvarchar(2000)

set @query = ''


SELECT @canImpersonate = HAS_PERMS_BY_NAME(null, null, 'IMPERSONATE ANY LOGIN');

IF @canImpersonate = 0
    print 'the caller doesn''t the permission IMPERSONATE ANY LOGIN';


IF @canImpersonate = 1
BEGIN

    DECLARE @name sysname;
    if object_id('tempdb..#UserPermissions') is not null
	   drop table #UserPermissions
    if object_id('tempdb..#Principals') is not null
	   drop table #Principals
    if object_id('tempdb..#uROLES') is not null
	   drop table #uROLES
    CREATE TABLE #UserPermissions ([User/Login] sysname
							 ,Entity_Name sysname
							 , SubEntity_Name sysname
							 , Permission_Name sysname
							 , db sysname
							 , state_desc nvarchar(50)
						    )
    CREATE TABLE #Principals(name sysname, isLoginUser nvarchar(15), type char(1), db sysname);
    CREATE TABLE #uROLES (
	RoleON VARCHAR(15)
	,rolename SYSNAME
	,PrincipalName SYSNAME
	)


    INSERT INTO #Principals
    SELECT name, 'LOGIN',  type, '' 
    FROM sys.server_principals
    WHERE NAME NOT IN ('public') --
		and name not like '##%' -- not sure some are SQL login and others are certificate
		and name not like 'NT %'
		and type not in ('G','R', 'C')
		and (name=@LoginUser or @LoginUser is null )

    IF LEN(@UserDB) > 0
    BEGIN
	   set @clause = '
	   INSERT INTO #Principals
	   SELECT name, ''USER'', type, db_name() as db 
		  FROM sys.database_principals
		  WHERE NAME NOT IN (''public'', ''INFORMATION_SCHEMA'',''sys'') --
			   and name not like ''##%'' -- not sure some are SQL login and others are certificate 
			   and name not like ''NT %'' -- network principal
			   and type not in (''G'',''R'')
		  ORDER BY NAME;
	   '
	   EXEC sp_ineachdb @command = @clause
    END
    ELSE
    BEGIN
	   set @clause = '
	   INSERT INTO #Principals
	   SELECT name, ''USER'', type, db_name() as db 
		  FROM sys.database_principals
		  WHERE NAME NOT IN (''public'', ''INFORMATION_SCHEMA'',''sys'') --
			   and name not like ''##%'' -- not sure some are SQL login and others are certificate 
			   and name not like ''NT %'' -- network principal
			   and type not in (''G'',''R'')
		  ORDER BY NAME;
	   '
	   EXEC sp_ineachdb @command = @clause
     END
   
    --***CURSOR ON USER
    DECLARE UserCursor CURSOR FOR
	   SELECT distinct name, db  
	   FROM #Principals
	   WHERE isLoginUser = 'USER'  AND (db = @UserDB OR  @UserDB IS NULL)

    OPEN UserCursor 
    FETCH NEXT FROM UserCursor INTO @name,  @db
    --what about db user without login on the server OR Group
    --CREATE DATABASE 

    WHILE @@FETCH_STATUS = 0
    BEGIN
	   IF DB_ID(@db) IS NOT NULL
	   begin
		  set @query = '
		  use [' + @db + '];
	  
		  IF EXISTS(SELECT 1 FROM sys.server_principals WHERE name = @name) 
		  BEGIN
			 -- Set the execution context on user
			 EXECUTE AS user = @name;
			 -- permission on db
			 INSERT INTO #UserPermissions
			 SELECT @name, entity_name, subentity_name, permission_name,  db_name(), '''' 
			 FROM fn_my_permissions(null, ''database'');
			 REVERT;
		  END
		  
		  INSERT INTO #UserPermissions
		  select  principals.name principalName,permissionst.class_desc, 
				coalesce(tp.table_schema +''.''+tp.table_name, 
						  cp.table_schema +''.''+cp.table_name, case when object_name( permissionst.major_id) is not null then object_name( permissionst.major_id) else '''' end) as subentity_name, --may need improvement also reliable schema is in sys.objects 
				coalesce(tp.PRIVILEGE_TYPE, cp.PRIVILEGE_TYPE
				, permissionst.permission_name)  COLLATE DATABASE_DEFAULT as permission_name
				,  db_name(), permissionst.state_desc
		  from sys.database_principals principals
		  join sys.database_permissions permissionst
			 on permissionst.grantee_principal_id = principals.principal_id
		  left join INFORMATION_SCHEMA.TABLE_PRIVILEGES tp
			 on tp.GRANTEE = principals.name 
		  left join INFORMATION_SCHEMA.COLUMN_PRIVILEGES cp
			 on cp.GRANTEE = principals.name	
			 WHERE principals.name = @name
		  
		  '
	   
		  exec sp_executesql @query, N'@name sysname, @db sysname', @name = @name, @db = @db
	   end

	   FETCH NEXT FROM UserCursor INTO  @name, @db
    END
    CLOSE UserCursor
    DEALLOCATE UserCursor




    --***CURSOR ON LOGIN
    DECLARE UserCursor CURSOR FOR
	   SELECT name 
	   FROM #Principals
	   WHERE isLoginUser = 'LOGIN' 
	   		and (name=@LoginUser or @LoginUser is null )


    OPEN UserCursor 
    FETCH NEXT FROM UserCursor INTO @name

    WHILE @@FETCH_STATUS = 0
    BEGIN
	  
		  INSERT INTO #UserPermissions
		  select principals.name principalName
			    ,permissionst.class_desc
			    , ''''
			    , permissionst.permission_name
			    , db_name()
			    , permissionst.state_desc
		  from sys.server_principals principals
		  join sys.server_permissions permissionst
			 on permissionst.grantee_principal_id = principals.principal_id
			 WHERE principals.name =  @name  
	   FETCH NEXT FROM UserCursor INTO  @name
    END
    CLOSE UserCursor
    DEALLOCATE UserCursor



    -- get other details on those I can''t run with "execute as"  
    IF @UserDB IS NOT NULL
    BEGIN
	    set @clause = ' use [' + @UserDB + '];
    	    INSERT INTO #UserPermissions
	   select distinct principals.name principalName,permissionst.class_desc, 
			 coalesce(tp.table_schema +''.''+tp.table_name, 
					   cp.table_schema +''.''+cp.table_name, case when object_name( permissionst.major_id) is not null then object_name( permissionst.major_id) else '''' end) as subentity_name, --may need improvement also reliable schema is in sys.objects 
			 coalesce(tp.PRIVILEGE_TYPE, cp.PRIVILEGE_TYPE
			 , permissionst.permission_name)  COLLATE DATABASE_DEFAULT as permission_name
			 , db_name(), permissionst.state_desc
	   from sys.database_principals principals
	   join sys.database_permissions permissionst
		  on permissionst.grantee_principal_id = principals.principal_id
	   left join INFORMATION_SCHEMA.TABLE_PRIVILEGES tp
		  on tp.GRANTEE = principals.name 
	   left join INFORMATION_SCHEMA.COLUMN_PRIVILEGES cp
		  on cp.GRANTEE = principals.name	
	   WHERE principals.name NOT IN (''public'') and --
		  ( principals.name  like ''##%'' -- not sure some are SQL login and others are certificate
		  or principals.name  like ''NT %''
		  or principals.type  in (''G'', ''C'',''R'')
		  )
		  and (name=''' + @LoginUser + ''' or 1=1 )
	   ';

	    exec (@clause)
	END


    INSERT INTO #UserPermissions
    select principals.name principalName,permissionst.class_desc, '''', permissionst.permission_name COLLATE DATABASE_DEFAULT
		  , db_name(), permissionst.state_desc
    from sys.server_principals principals
    join sys.server_permissions permissionst
	   on permissionst.grantee_principal_id = principals.principal_id
    WHERE principals.NAME NOT IN ('public') and --
		  ( principals.name  like '##%' -- not sure some are SQL login and others are certificate
		  or principals.name  like 'NT %'
		  or principals.type  in ('G', 'C','R')
		  )
    

    IF LEN(@permission) > 0
	   begin
		  declare @title sysname;

		  SELECT 'Principals without an explicit permission: ' + @permission

		  SELECT DISTINCT [User/Login] --,Entity_Name, SubEntity_Name, Permission_Name
		  FROM #UserPermissions
		  WHERE Permission_Name LIKE @permission
		  ORDER BY [User/Login]	   
	   end
    ELSE 
    begin
	   SELECT DISTINCT [User/Login],Entity_Name, SubEntity_Name, Permission_Name, case when Entity_Name='SERVER' THEN '' ELSE  db END as dbName, state_desc
	   FROM #UserPermissions u
	   WHERE ([User/Login] = @LoginUser OR  @LoginUser IS NULL) and (db = @UserDB OR  @UserDB IS NULL)
	   ORDER BY Entity_Name, dbName, [User/Login],  Permission_Name
    end

    --MEMBERS OF ROLES
    set @clause = '
	   INSERT INTO #uROLES
	   exec sp_helpMemberOfRole 
    '
    EXEC sp_ineachdb @command = @clause


    SELECT DISTINCT PrincipalName,  rolename, RoleON 
    FROM #uROLES
    WHERE (PrincipalName = @LoginUser OR  @LoginUser IS NULL) 
    ORDER BY PrincipalName

    
    SELECT rol.name AS DatabaseRoleName,   
       isnull (us.name, '') AS UserMemberName, us.principal_id MemberID   
     FROM sys.database_principals AS rol    
     LEFT JOIN  sys.database_role_members AS mb
    	   ON mb.role_principal_id = rol.principal_id  
     LEFT JOIN sys.database_principals AS us  
    	   ON mb.member_principal_id = us.principal_id  
    WHERE rol.type = 'R' and 
		exists( select 1/0 from #uROLES r where r.rolename = rol.name and (r.PrincipalName = @LoginUser OR  @LoginUser IS NULL) )
    order by 1


    if @LoginUser is not null
	   delete from #uROLES where PrincipalName <> @LoginUser


    create table #objectPermission (
    principalName sysname,	PrincipalID int,	permission_name sysname,	state_desc varchar(128),	
    class_desc varchar(128),	SchemaName sysname,	ObjName sysname,	IsTable bit,	IsTrigger bit,	IsView bit,	IsProcedure bit,	CurrentDatabase sysname
    )

    	   set @clause = '
        insert into #objectPermission
	   select principals.name principalName, principal_id PrincipalID
	   , permissionst.permission_name 
	   , permissionst.state_desc 
	   , permissionst.class_desc 
	   , OBJECT_SCHEMA_NAME(permissionst.major_id) SchemaName 
	   ,  object_name( permissionst.major_id) ObjName ,
	   OBJECTPROPERTY(permissionst.major_id, ''IsTable'') AS [IsTable],
	   OBJECTPROPERTY(permissionst.major_id, ''IsTrigger'') AS [IsTrigger],
	   OBJECTPROPERTY(permissionst.major_id, ''IsView'') AS [IsView],
	   OBJECTPROPERTY(permissionst.major_id, ''IsProcedure'') AS [IsProcedure]
	   , DB_NAME() CurrentDatabase 
	   from sys.database_principals principals
	   join sys.database_permissions permissionst
	   on permissionst.grantee_principal_id = principals.principal_id
	   WHERE principal_id > 0 AND EXISTS(SELECT 1 FROM #uROLES r where r.rolename = principals.name COLLATE DATABASE_DEFAULT )
	   and OBJECT_SCHEMA_NAME(permissionst.major_id) is not null
	   order by principalName, permission_name
	   '
	   EXEC sp_ineachdb @command = @clause



    select * from  #objectPermission
    where CurrentDatabase = @UserDB OR  @UserDB IS NULL


    --all logins
    if @LoginUser is null
    begin
        --all logins
	   select name as [SQL_Logins] from sys.server_principals order by name

	   --sysadmins : sp_helpsrvrolemember 'sysadmin' isnot ordered
	   SELECT DISTINCT PrincipalName as isSysAdmin 
	   FROM #uROLES
	   WHERE (PrincipalName = @LoginUser OR  @LoginUser IS NULL) and rolename = 'sysadmin'
	   ORDER BY PrincipalName
    end

    IF OBJECT_ID('tempDB..#UserPermissions') IS NOT NULL
	   DROP TABLE #UserPermissions

    IF OBJECT_ID('tempDB..#Principals') IS NOT NULL
	   DROP TABLE #Principals

    IF OBJECT_ID('tempDB..#uROLES') IS NOT NULL
	   DROP TABLE #uROLES

    IF OBJECT_ID('tempDB..#objectPermission') IS NOT NULL
	   DROP TABLE #objectPermission

  
END


end
