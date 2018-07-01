-- -----------------------------------------------------------------------------
--                 WWW.PETEFINNIGAN.COM LIMITED
-- -----------------------------------------------------------------------------
-- Script Name : cracker-v2.0.sql
-- Author      : Pete Finnigan
-- Date        : March 2008
-- -----------------------------------------------------------------------------
-- Description : This script can be used to test users passwords in databases 
--               of versions 7 - 10gR2 and 11gR1 (TBD)
-- -----------------------------------------------------------------------------
-- Maintainer  : Pete Finnigan (http://www.petefinnigan.com)
-- Copyright   : Copyright (C) 2008, 2009 PeteFinnigan.com Limited. All rights
--               reserved. All registered trademarks are the property of their
--               respective owners and are hereby acknowledged.
-- -----------------------------------------------------------------------------
-- Package     : This software forms part of the "Oscan-v2.0" Oracle database
--               security scanner software package.
-- -----------------------------------------------------------------------------
-- License     : This software is free software BUT it is not in the public
--               domain. This means that you can use it for personal or 
--               commercial work but you cannot remove this notice or copyright
--               notices or the banner output by the program or edit them in any
--               way at all. You also cannot host/distribute/copy or in anyway 
--               make this script available through any means. The script is 
--               only available from its own webpage 
--               http://www.petefinnigan.com/oracle_password_cracker.htm
--               This script cannot be incorporated into any other free or 
--               commercial tools without permission from PeteFinnigan.com 
--               Limited.
--
--               In simple terms use it for free but dont make it available in
--               any way or build it into any other tools. 
-- -----------------------------------------------------------------------------
-- TODO        : 1) Add 11g password algorithm and test for case sensitivity and 
--               crack 11gR1 passwords.
-- -----------------------------------------------------------------------------
-- Notes       : Note that debug / trace is turned off and commented out. If 
--               there is an issue or potential bug then uncomment the debugw 
--               lines in the code and set the debug and debug_level define vars
--               This will help me locate any issues.
-- -----------------------------------------------------------------------------
-- Version History
-- ===============
--
-- Who         version     Date      Description
-- ===         =======     ======    ======================
-- P.Finnigan  1.0         Mar 2008  First Issue.
-- P.Finnigan  1.1         Jul 2008  Release version
-- P.Finnigan  1.2         Sep 2008  Release on website
-- P.Finnigan  1.3         Sep 2008  Fixed impossible passwords longer than 30
--                                   Also encased usernames to cater for blanks
-- P.Finnigan  1.4         Oct 2008  Added a flag to enable just WEAK to be output
-- P.Finnigan  1.5         May 2009  Fixed a bug in the debug buffer
-- -----------------------------------------------------------------------------


-- -------------------------------------------------------------------------------
-- hide 11g features from earlier versions of SQL*Plus
-- -------------------------------------------------------------------------------

set verify off
set termout off
set feed off

set serveroutput on format wrapped size 1000000 

-- idea from Tanel Poder SQl*Plus trick to comment out PL/SQL code
define _if_11g="/* NOT 11g" /* dummy */

col cracker_version noprint new_value _if_11g

select decode(substr(banner,instr(banner, 'Release ')+8,2),11,'','/* NOT 11g') cracker_version
from v$version
where rownum=1
/
-- -------------------------------------------------------------------------------
-- debug initialisation section
-- -------------------------------------------------------------------------------

define debug = 'OFF'
define debug_level = '1'

var debugv varchar2(3)
var debugl varchar2(1)

execute :debugv := '&debug';
execute :debugl := '&debug_level';

-- -------------------------------------------------------------------------------
-- set up weak passwords
-- -------------------------------------------------------------------------------

define weak = 'OFF'

var weakv varchar2(3);

execute :weakv := '&weak';

set termout on 
set feed on

declare
	--
	-- -------------------------------------------
	-- Main block global variables.
	-- -------------------------------------------
	--
	lg_debug	varchar2(1):='N';
	lg_fptr		utl_file.file_type;
	lg_mode		varchar2(1):='L';
	--
	-- A level of 9 means print 1 - 9. A level of 1 
	-- means print only level 1.
	--
	lg_level	varchar2(1):='0';
	--
	raw_ip raw(128);
	prod_date varchar2(100);
	--
	type defpwd is table of varchar2(30) index by binary_integer;
	defs defpwd;
	--
	type dictword is table of varchar2(30) index by binary_integer;
	dicts dictword;
	--
	type user_node is record (
		entry_type varchar2(1),   --* 'U'ser or 'R'ole
		username varchar2(30),    --* database username
		accnt_status varchar2(3), --* account status
		hash10g varchar2(30),     --* 10g hash
		hash11g varchar2(40),     --* 11g hash
		salt11g varchar2(20),     --* 11g salt
		password varchar2(38),    --* cracked password or EXT, GLOB, IMP
		prof varchar2(30),        -- profile name
		fla number(10),           -- failed login attempts
		sespu number(10),         -- sessions per user
		prt number(10),           -- pass reuse time
		prm number(10),           -- pass reuse max
		plt number(10),           -- pass lock time
		pgt number(10),           -- pass grace time
		plft number(10),          -- pass life time
		pvf varchar2(30),         -- pass verify function
		crt varchar2(2),          --* crack typ, PU, DE, DI, BF, HS
						-- PU - Pass=User
						-- DE - Default pwd
						-- DI - Dictionary word
						-- BF - brute forced
						-- HS - set to a known hash but pwd not known
						-- GE - Global or external
						-- IM - impossible password
		flg boolean               --* cracked
	);
	type usert is table of user_node index by binary_integer;
	userts usert;
	res_cracked varchar2(2);
	res_username varchar2(30);
	res_password varchar2(30);
	--
	type hash_rec is record (
		user varchar2(30),          -- username for none cracked default
		hash varchar2(30)           -- hash for known default non-cracked
	);
	type hash_t is table of hash_rec index by binary_integer;
	hashes hash_t;
	--
	max_users binary_integer;
	--
	start_time number:=0;
	end_time number:=0;
	elapsed_time_sec number(10,2):=0.0;
	seconds_per_password number(10,2):=0.0;
	num_cracks number(10):=0;
	--
	raw_key raw(128):= hextoraw('0123456789ABCDEF');
	--
	type mask_t is table of number(2) index by binary_integer;
	mask mask_t;
	charset varchar2(70):='ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_#$';
	charset_len number:=26;
	passlen number;
	bfpass varchar2(15);
	--
	-- -------------------------------------------------------------
	-- debug functions
	-- -------------------------------------------------------------
	--
	procedure traceon(pv_mode in varchar2,pv_level in varchar2) is
	begin
		--
		lg_debug:='Y';
		--
		lg_level:=pv_level;
		--
		-- mode should be 'L'ocal or 'F'ile
		--
		lg_mode:=pv_mode;
		if lg_mode='L' then
			dbms_output.disable;
			dbms_output.enable(1000000);
		end if;
		--
	end traceon;
	--
	procedure traceoff is
	begin
		--
		lg_debug:='N';
		--
	end traceoff;
	--
	function timestamp return varchar2 is
		--
		cursor	c_time is
		select	to_char(sysdate,'DD Mon YYYY HH24:MI:SS') timestamp
		from	sys.dual;
		--
		lf_time	c_time%rowtype;
		lf_ret_val	varchar2(20):=' ';
		--
	begin
		--
		open c_time;
		fetch c_time into lf_time;
		lf_ret_val:=lf_time.timestamp;
		close c_time;	
		return lf_ret_val;
		--
	end timestamp;
	--
	procedure open_log (pv_path_name in varchar2,
				pv_file_name in varchar2) is
	begin
		--
		lg_fptr:=utl_file.fopen(pv_path_name,
				pv_file_name,'A');
		--
	exception
		when utl_file.invalid_path  then
			dbms_output.put_line('invalid path');
			raise_application_error(-20100,'file error');	
		when utl_file.invalid_mode  then
			dbms_output.put_line('invalid_mode');
			raise_application_error(-20100,'file error');	
		when utl_file.invalid_filehandle  then
			dbms_output.put_line('invalid_filehandle');
			raise_application_error(-20100,'file error');	
		when utl_file.invalid_operation  then
			dbms_output.put_line('invalid_operation');
			raise_application_error(-20100,'file error');	
		when utl_file.read_error  then
			dbms_output.put_line('read_error');
			raise_application_error(-20100,'file error');	
		when utl_file.write_error  then
			dbms_output.put_line('write_error');
			raise_application_error(-20100,'file error');	
		when utl_file.internal_error  then
			dbms_output.put_line('internal_error');
			raise_application_error(-20100,'file error');	
		when others then
			dbms_output.put_line(sqlerrm);
			dbms_output.put_line('un-handled');
			raise_application_error(-20100,'file error');	
	end open_log;
	--
	procedure close_log is
	begin
		--
		utl_file.fclose(lg_fptr);
		--
	exception
		when utl_file.invalid_path  then
			dbms_output.put_line('invalid path');
			raise_application_error(-20100,'file error');	
		when utl_file.invalid_mode  then
			dbms_output.put_line('invalid_mode');
			raise_application_error(-20100,'file error');	
		when utl_file.invalid_filehandle  then
			dbms_output.put_line('invalid_filehandle');
			raise_application_error(-20100,'file error');	
		when utl_file.invalid_operation  then
			dbms_output.put_line('invalid_operation');
			raise_application_error(-20100,'file error');	
		when utl_file.read_error  then
			dbms_output.put_line('read_error');
			raise_application_error(-20100,'file error');	
		when utl_file.write_error  then
			dbms_output.put_line('write_error');
			raise_application_error(-20100,'file error');	
		when utl_file.internal_error  then
			dbms_output.put_line('internal_error');
			raise_application_error(-20100,'file error');	
		when others then
			dbms_output.put_line(sqlerrm);
			dbms_output.put_line('un-handled');
			raise_application_error(-20100,'file error');	
	end close_log;
	--
	procedure debugw (pv_level in varchar2,pv_str in varchar2) is
	begin
		--
		if lg_debug='Y' then 
			--
			-- A level of 9 means print 1-9 and a level of
			-- 1 means print just 1.
			--
			if pv_level<=lg_level then
				if lg_mode='F' then
					utl_file.put_line(lg_fptr,'['||timestamp
						||']: '||pv_str);
				else
					dbms_output.put_line('['||timestamp
						||']: '||pv_str);
				end if;
			end if;
		end if;
		--
	exception
		when utl_file.invalid_path  then
			dbms_output.put_line('invalid path');
			raise_application_error(-20100,'file error');	
		when utl_file.invalid_mode  then
			dbms_output.put_line('invalid_mode');
			raise_application_error(-20100,'file error');	
		when utl_file.invalid_filehandle  then
			dbms_output.put_line('invalid_filehandle');
			raise_application_error(-20100,'file error');	
		when utl_file.invalid_operation  then
			dbms_output.put_line('invalid_operation');
			raise_application_error(-20100,'file error');	
		when utl_file.read_error  then
			dbms_output.put_line('read_error');
			raise_application_error(-20100,'file error');	
		when utl_file.write_error  then
			dbms_output.put_line('write_error');
			raise_application_error(-20100,'file error');	
		when utl_file.internal_error  then
			dbms_output.put_line('internal_error');
			raise_application_error(-20100,'file error');	
		when others then
			dbms_output.put_line(sqlerrm);
			dbms_output.put_line('un-handled');
			raise_application_error(-20100,'file error');	
	end debugw;
	--
	-- -------------------------------------------------------------
	-- cracker functions
	-- -------------------------------------------------------------
	--
	function updatemask(char_posn in number) return boolean
	is
		retn boolean;
	begin
		mask(char_posn):=mask(char_posn)+1;
		if mask(char_posn) = (charset_len+1) then
			if (char_posn = passlen) then
				return(FALSE);
			else
				mask(char_posn):=1;
				return(updatemask(char_posn+1));
	
			end if;
		else
			return(TRUE);
		end if;
	end; 
	--
	function checkhex (passwd in varchar2) return boolean
	is
		len number;
		curr_char char(1);
		flg boolean:=FALSE;
	begin
		len:=length(passwd);
		--debugw(pv_level => '3',pv_str => 'len = '||len);
		for i in 1..len loop
			curr_char:=substr(passwd,i,1);
			--debugw(pv_level => '3', pv_str => 'curr_char ='||curr_char);
			if curr_char not in ('0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F') then
				flg:=TRUE;
				return (flg);
			end if;
		end loop;
		return(flg);
	end checkhex;
	--
	procedure pre_load
	is
		--
		cursor c_user is
		select 	name,
			password,
			type#,
			substr(spare4,3,40) hash11g,
			substr(spare4,43,20) salt11g,
			decode(astatus,1,'EXP',2,'EG ',4,'LT ',8,'LO ',5,'ELT',6,'EGT',9,'EL',10,'EGL',0,'OP ') astatus
		from sys.user$
		where password is not null;
		--and password <> 'GLOBAL';
		--
		--cursor c_prof is
		--
	begin
		max_users:=0;
		for lv_user in c_user loop
			max_users:=max_users+1;
			if lv_user.type# = 0 then
				userts(max_users).entry_type:='R';
			else
				userts(max_users).entry_type:='U';
			end if;
			if lv_user.password in ('EXTERNAL','GLOBAL') then
				userts(max_users).flg:=TRUE;
				userts(max_users).crt:='GE';
				userts(max_users).password:='GL-EX {'||lv_user.password||'}';
			elsif length(lv_user.password) != 16 then
				-- impossible password ( be careful as we also need to check for HEX)
				userts(max_users).flg:=TRUE;
				userts(max_users).crt:='IM';
				userts(max_users).password:='IMP {'||lv_user.password||'}';				
			elsif checkhex(lv_user.password) = TRUE then
				--debugw(pv_level => '3',pv_str => 'impossible password');
				-- impossible password that is 16 chars
				userts(max_users).flg:=TRUE;
				userts(max_users).crt:='IM';
				userts(max_users).password:='IMP {'||lv_user.password||'}';								
			else
				userts(max_users).hash10g:=lv_user.password;
				userts(max_users).flg:=FALSE;
				userts(max_users).crt:='--';
			end if;
			if (lv_user.hash11g is not null) then
				userts(max_users).hash11g:=lv_user.hash11g;
				userts(max_users).salt11g:=lv_user.salt11g;
			end if;
			userts(max_users).username:=lv_user.name;
			userts(max_users).accnt_status:=lv_user.astatus;
		end loop;
	end;
	--
	procedure unicode_str(userpwd in varchar2, unistr out raw)
	is
		enc_str varchar2(124):='';
		tot_len number;
		curr_char char(1);
		padd_len number;
		ch char(1);
		mod_len number;
		debugp varchar2(256);
	begin
		tot_len:=length(userpwd);
		--debugw(pv_level => '5',
		--	pv_str => 'tot_len:='||tot_len);
		for i in 1..tot_len loop
			curr_char:=substr(userpwd,i,1);
			--debugw(pv_level => '5',
			--	pv_str => 'curr_char:='||curr_char);
			enc_str:=enc_str||chr(0)||curr_char;
		end loop;
		-- padd to 8 byte boundaries
		mod_len:= mod((tot_len*2),8);
		if (mod_len = 0) then
			padd_len:= 0;
		else
			padd_len:=8 - mod_len;
		end if;
		--debugw(pv_level => '5',
		--	pv_str => 'padd_len:='||padd_len);
		for i in 1..padd_len loop
			enc_str:=enc_str||chr(0);
		end loop;
		-- /* debug code
		for i in 1..tot_len*2+padd_len loop
			ch:=substr(enc_str,i,1);
			if (ch = chr(0)) then
				debugp:=debugp||'|*';
			else
				debugp:=debugp||'|'||ch;
			end if;
		end loop;
		-- end debug code */
		unistr:=utl_raw.cast_to_raw(enc_str);
	end;
	--
	function crack (userpwd in raw, num_cracks in out number) return varchar2 
	is
		enc_raw raw(2048);
		--
		raw_key2 raw(128);
		pwd_hash raw(2048);
		--
		hexstr varchar2(2048);
		len number;
		password_hash varchar2(16);	
	begin
		num_cracks:=num_cracks+1;
		dbms_obfuscation_toolkit.DESEncrypt(input => userpwd, 
		       key => raw_key, encrypted_data => enc_raw );
		hexstr:=rawtohex(enc_raw);
		--debugw(pv_level => '5',
		--	pv_str => '> encrypted hex value: ' ||hexstr);
		len:=length(hexstr);
		--debugw(pv_level => '5',
		--	pv_str => 'Length of Hex = '||len);
		-- need + 1 as the strings in PL/SQL are "1" based not "0" based as in C
		--debugw(pv_level => '5',
		--	pv_str => 'Last 16 digits : '||substr(hexstr,(len-16+1),16));
		raw_key2:=hextoraw(substr(hexstr,(len-16+1),16));
		dbms_obfuscation_toolkit.DESEncrypt(input => userpwd, 
		       key => raw_key2, encrypted_data => pwd_hash );
		--debugw(pv_level => '5',
		--	pv_str => '> encrypted hex value: ' ||pwd_hash);
		hexstr:=hextoraw(pwd_hash);
		len:=length(hexstr);
		password_hash:=substr(hexstr,(len-16+1),16);
		--debugw(pv_level => '5',
		--	pv_str => 'Password hash:= '||password_hash);
		return(password_hash);
	end;
	--
	-- ------------------------------------------------------------------
	-- This function is yet to be completed.
	-- ------------------------------------------------------------------
	--
	-- sqlplus trick to comment out code
	&_if_11g
	function crack11g (userpwd in varchar2, num_cracks in out number) return varchar2 
	is
		enc_raw raw(2048);
		--
		raw_key2 raw(128);
		pwd_hash raw(2048);
		--
		hexstr varchar2(2048);
		len number;
		password_hash varchar2(16);	
	begin
		num_cracks:=num_cracks+1;
		-- pass in the cracked password and then loop through and upper case it
		--debugw(pv_level => '5',
		--	pv_str => 'Password hash:= '||password_hash);
		return(password_hash);
	end;
	-- */
	--
	procedure init_default
	is
	begin
		--
		defs(1):='OCSG40';
		defs(2):='PARSER';
		defs(3):='MEDIA';
		defs(4):='SURFACE';
		defs(5):='MEDIASURFACE';
		defs(6):='MGMT';
		defs(7):='MGMT_VIEW';
		defs(8):='06071992';
		defs(9):='0RACL3';
		defs(10):='0RACL38';
		defs(11):='0RACL38I';
		defs(12):='0RACL39';
		defs(13):='0RACL39I';
		defs(14):='0RACLE';
		defs(15):='0RACLE8';
		defs(16):='0RACLE8I';
		defs(17):='0RACLE9';
		defs(18):='0RACLE9I';
		defs(19):='199220706';
		defs(20):='ABM';
		defs(21):='ADGANGSKODE';
		defs(22):='ADLDEMO';
		defs(23):='ADMIN';
		defs(24):='ADMINISTRATOR';
		defs(25):='AHL';
		defs(26):='AHM';
		defs(27):='AIROPLANE';
		defs(28):='AK';
		defs(29):='AKF7D98S2';
		defs(30):='ALR';
		defs(31):='AMS';
		defs(31):='AMV';
		defs(32):='ANONYMOUS';
		defs(33):='AP';
		defs(34):='APPLMGR';
		defs(35):='APPLSYS';
		defs(36):='APPLSYSPUB';
		defs(37):='APPPASSWORD';
		defs(38):='APPS';
		defs(39):='AQ';
		defs(40):='AQDEMO';
		defs(41):='AQJAVA';
		defs(42):='AQUSER';
		defs(43):='AR';
		defs(44):='ASF';
		defs(45):='ASG';
		defs(46):='ASL';
		defs(47):='ASO';
		defs(48):='ASP';
		defs(49):='AST';
		defs(50):='AUDIOUSER';
		defs(51):='AX';
		defs(52):='AZ';
		defs(53):='BAR';
		defs(54):='BC4J';
		defs(55):='BEN';
		defs(56):='BIC';
		defs(57):='BIL';
		defs(58):='BIM';
		defs(59):='BIS';
		defs(60):='BIV';
		defs(61):='BIX';
		defs(62):='BLEWIS';
		defs(63):='BOM';
		defs(64):='BRIO_ADMIN';
		defs(65):='BSC';
		defs(66):='BUG_REPORTS';
		defs(67):='CATALOG';
		defs(68):='CCT';
		defs(69):='CDEMO82';
		defs(70):='CDEMO83';
		defs(71):='CDEMOCOR';
		defs(72):='CDEMORID';
		defs(73):='CDEMOUCB';
		defs(74):='CDOUGLAS';
		defs(75):='CE';
		defs(76):='CENTRA';
		defs(77):='CENTRAL';
		defs(78):='CHANGE_ON_INSTALL';
		defs(79):='CIDS';
		defs(80):='CIS';
		defs(81):='CISINFO';
		defs(82):='CLAVE';
		defs(83):='CLERK';
		defs(84):='CLOTH';
		defs(85):='CN';
		defs(86):='COMPANY';
		defs(87):='COMPIERE';
		defs(88):='CRP';
		defs(89):='CS';
		defs(90):='CSC';
		defs(91):='CSD';
		defs(92):='CSE';
		defs(93):='CSF';
		defs(94):='CSI';
		defs(95):='CSL';
		defs(96):='CSMIG';
		defs(97):='CSP';
		defs(98):='CSR';
		defs(99):='CSS';
		defs(100):='CTXDEMO';
		defs(101):='CTXSYS';
		defs(102):='CUA';
		defs(103):='CUE';
		defs(104):='CUF';
		defs(105):='CUG';
		defs(106):='CUI';
		defs(107):='CUN';
		defs(108):='CUP';
		defs(109):='CUS';
		defs(110):='CZ';
		defs(111):='DBSNMP';
		defs(112):='DBVISION';
		defs(113):='DEMO';
		defs(114):='DEMO8';
		defs(115):='DEMO9';
		defs(116):='DES';
		defs(117):='DES2K';
		defs(118):='DEV2000_DEMOS';
		defs(119):='DIP';
		defs(120):='DISCOVERER_ADMIN';
		defs(121):='DMSYS';
		defs(122):='DPFPASS';
		defs(123):='DSGATEWAY';
		defs(124):='DSSYS';
		defs(125):='DTSP';
		defs(126):='D_SYSPW';
		defs(127):='D_SYSTPW';
		defs(128):='EAA';
		defs(129):='EAM';
		defs(130):='EAST';
		defs(131):='EC';
		defs(132):='ECX';
		defs(133):='EJB';
		defs(134):='EJSADMIN';
		defs(135):='EJSADMIN_PASSWORD';
		defs(136):='EMP';
		defs(137):='ENG';
		defs(138):='ENI';
		defs(139):='ESTORE';
		defs(140):='EVENT';
		defs(141):='EVM';
		defs(142):='EXAMPLE';
		defs(143):='EXFSYS';
		defs(144):='EXTDEMO';
		defs(145):='EXTDEMO2';
		defs(146):='FA';
		defs(147):='FEM';
		defs(148):='FII';
		defs(149):='FINANCE';
		defs(150):='FINPROD';
		defs(151):='FLM';
		defs(152):='FND';
		defs(153):='FNDPUB';
		defs(154):='FPT';
		defs(155):='FRM';
		defs(156):='FTE';
		defs(157):='FV';
		defs(158):='GL';
		defs(159):='GMA';
		defs(160):='GMD';
		defs(161):='GME';
		defs(162):='GMF';
		defs(163):='GMI';
		defs(164):='GML';
		defs(165):='GMP';
		defs(166):='GMS';
		defs(167):='GPFD';
		defs(168):='GPLD';
		defs(169):='GR';
		defs(170):='HADES';
		defs(171):='HCPARK';
		defs(172):='HLW';
		defs(173):='HOBBES';
		defs(174):='HR';
		defs(175):='HRI';
		defs(176):='HVST';
		defs(177):='HXC';
		defs(178):='HXT';
		defs(179):='IBA';
		defs(180):='IBE';
		defs(181):='IBP';
		defs(182):='IBU';
		defs(183):='IBY';
		defs(184):='ICDBOWN';
		defs(185):='ICX';
		defs(186):='IDEMO_USER';
		defs(187):='IEB';
		defs(188):='IEC';
		defs(189):='IEM';
		defs(190):='IEO';
		defs(191):='IES';
		defs(192):='IEU';
		defs(193):='IEX';
		defs(194):='IFSSYS';
		defs(195):='IGC';
		defs(196):='IGF';
		defs(197):='IGI';
		defs(198):='IGS';
		defs(199):='IGW';
		defs(200):='IMAGEUSER';
		defs(201):='IMC';
		defs(202):='IMEDIA';
		defs(203):='IMT';
		defs(204):='INSTANCE';
		defs(205):='INV';
		defs(206):='INVALID';
		defs(207):='IPA';
		defs(208):='IPD';
		defs(209):='IPLANET';
		defs(210):='ISC';
		defs(211):='ITG';
		defs(212):='JA';
		defs(213):='JE';
		defs(214):='JETSPEED';
		defs(215):='JG';
		defs(216):='JL';
		defs(217):='JMUSER';
		defs(218):='JOHN';
		defs(219):='JTF';
		defs(220):='JTM';
		defs(221):='JTS';
		defs(222):='KWALKER';
		defs(223):='L2LDEMO';
		defs(224):='LASKJDF098KSDAF09';
		defs(225):='LBACSYS';
		defs(226):='MANAG3R';
		defs(227):='MANAGER';
		defs(228):='MANPROD';
		defs(229):='MDDATA';
		defs(230):='MDDEMO';
		defs(231):='MDDEMO_MGR';
		defs(232):='MDSYS';
		defs(233):='ME';
		defs(234):='MFG';
		defs(235):='MGR';
		defs(236):='MGWUSER';
		defs(237):='MIGRATE';
		defs(238):='MILLER';
		defs(239):='MMO2';
		defs(240):='MMO3';
		defs(241):='MOREAU';
		defs(242):='MOT_DE_PASSE';
		defs(243):='MRP';
		defs(244):='MSC';
		defs(245):='MSD';
		defs(246):='MSO';
		defs(247):='MSR';
		defs(248):='MT6CH5';
		defs(249):='MTRPW';
		defs(250):='MTSSYS';
		defs(251):='MTS_PASSWORD';
		defs(252):='MUMBLEFRATZ';
		defs(253):='MWA';
		defs(254):='MXAGENT';
		defs(255):='NAMES';
		defs(256):='NEOTIX_SYS';
		defs(257):='NNEULPASS';
		defs(258):='OAS_PUBLIC';
		defs(259):='OCITEST';
		defs(260):='OCM_DB_ADMIN';
		defs(261):='ODM';
		defs(262):='ODS';
		defs(263):='ODSCOMMON';
		defs(264):='ODS_SERVER';
		defs(265):='OE';
		defs(266):='OEMADM';
		defs(267):='OEMREP';
		defs(268):='OEM_TEMP';
		defs(269):='OKB';
		defs(270):='OKC';
		defs(271):='OKE';
		defs(272):='OKI';
		defs(273):='OKO';
		defs(274):='OKR';
		defs(275):='OKS';
		defs(276):='OKX';
		defs(277):='OLAPDBA';
		defs(278):='OLAPSVR';
		defs(279):='OLAPSYS';
		defs(280):='ONT';
		defs(281):='OO';
		defs(282):='OPENSPIRIT';
		defs(283):='OPI';
		defs(284):='ORACACHE';
		defs(285):='ORACL3';
		defs(286):='ORACLE';
		defs(287):='ORACLE8';
		defs(288):='ORACLE8I';
		defs(289):='ORACLE9';
		defs(290):='ORACLE9I';
		defs(291):='ORADBAPASS';
		defs(292):='ORAPROBE';
		defs(293):='ORAREGSYS';
		defs(294):='ORASSO';
		defs(295):='ORASSO_DS';
		defs(296):='ORASSO_PA';
		defs(297):='ORASSO_PS';
		defs(298):='ORASSO_PUBLIC';
		defs(299):='ORASTAT';
		defs(300):='ORDCOMMON';
		defs(301):='ORDPLUGINS';
		defs(302):='ORDSYS';
		defs(303):='OSM';
		defs(304):='OSP22';
		defs(305):='OTA';
		defs(306):='OUTLN';
		defs(307):='OWA';
		defs(308):='OWA_PUBLIC';
		defs(309):='OWF_MGR';
		defs(310):='OWNER';
		defs(311):='OZF';
		defs(312):='OZP';
		defs(313):='OZS';
		defs(314):='PA';
		defs(315):='PANAMA';
		defs(316):='PAPER';
		defs(317):='PAROL';
		defs(318):='PASSWD';
		defs(319):='PASSWO1';
		defs(320):='PASSWO2';
		defs(321):='PASSWO3';
		defs(322):='PASSWO4';
		defs(323):='PASSWORD';
		defs(324):='PATROL';
		defs(325):='PAUL';
		defs(326):='PERFSTAT';
		defs(327):='PERSTAT';
		defs(328):='PJM';
		defs(329):='PLANNING';
		defs(330):='PLEX';
		defs(331):='PM';
		defs(332):='PMI';
		defs(333):='PN';
		defs(334):='PO';
		defs(335):='PO7';
		defs(336):='PO8';
		defs(337):='POA';
		defs(338):='POM';
		defs(339):='PORTAL30';
		defs(340):='PORTAL30_ADMIN';
		defs(341):='PORTAL30_DEMO';
		defs(342):='PORTAL30_PS';
		defs(343):='PORTAL30_PUBLIC';
		defs(344):='PORTAL30_SSO';
		defs(345):='PORTAL30_SSO_ADMIN';
		defs(346):='PORTAL30_SSO_PS';
		defs(347):='PORTAL30_SSO_PUBLIC';
		defs(348):='PORTAL31';
		defs(349):='PORTAL_DEMO';
		defs(350):='PORTAL_SSO_PS';
		defs(351):='POS';
		defs(352):='POWERCARTUSER';
		defs(353):='PRIMARY';
		defs(354):='PSA';
		defs(355):='PSB';
		defs(356):='PSP';
		defs(357):='PUB';
		defs(358):='PUBSUB';
		defs(359):='PUBSUB1';
		defs(360):='PV';
		defs(361):='QA';
		defs(362):='QDBA';
		defs(363):='QP';
		defs(364):='QS';
		defs(365):='QS_ADM';
		defs(366):='QS_CB';
		defs(367):='QS_CBADM';
		defs(368):='QS_CS';
		defs(369):='QS_ES';
		defs(370):='QS_OS';
		defs(371):='QS_WS';
		defs(372):='RE';
		defs(373):='REPADMIN';
		defs(374):='REPORTS';
		defs(375):='REP_OWNER';
		defs(376):='RG';
		defs(377):='RHX';
		defs(378):='RLA';
		defs(379):='RLM';
		defs(380):='RMAIL';
		defs(381):='RMAN';
		defs(382):='RRS';
		defs(383):='SAMPLE';
		defs(384):='SAMPLEATM';
		defs(385):='SAP';
		defs(386):='SAPR3';
		defs(387):='SDOS_ICSAP';
		defs(388):='SECDEMO';
		defs(389):='SENHA';
		defs(390):='SERVICECONSUMER1';
		defs(391):='SH';
		defs(392):='SHELVES';
		defs(393):='SITEMINDER';
		defs(394):='SI_INFORMTN_SCHEMA';
		defs(395):='SLIDEPW';
		defs(396):='SNOWMAN';
		defs(397):='SPIERSON';
		defs(398):='SSP';
		defs(399):='STARTER';
		defs(400):='STEEL';
		defs(401):='STRAT_PASSWD';
		defs(402):='SUPERSECRET';
		defs(403):='SUPPORT';
		defs(404):='SWORDFISH';
		defs(405):='SWPRO';
		defs(406):='SWUSER';
		defs(407):='SYMPA';
		defs(408):='SYS';
		defs(409):='SYSADM';
		defs(410):='SYSADMIN';
		defs(411):='SYSMAN';
		defs(412):='SYSPASS';
		defs(413):='SYSTEM';
		defs(414):='SYSTEMPASS';
		defs(415):='SYS_STNT';
		defs(416):='TAHITI';
		defs(417):='TDOS_ICSAP';
		defs(418):='TECTEC';
		defs(419):='TEST';
		defs(420):='TESTPILOT';
		defs(421):='TEST_USER';
		defs(422):='THINSAMPLEPW';
		defs(423):='TIBCO';
		defs(424):='TIGER';
		defs(425):='TIGGER';
		defs(426):='TIP37';
		defs(427):='TRACE';
		defs(428):='TRAVEL';
		defs(429):='TSDEV';
		defs(430):='TSUSER';
		defs(431):='TURBINE';
		defs(432):='ULTIMATE';
		defs(433):='UM_ADMIN';
		defs(434):='UM_CLIENT';
		defs(435):='UNKNOWN';
		defs(436):='USER';
		defs(437):='USER0';
		defs(438):='USER1';
		defs(439):='USER2';
		defs(440):='USER3';
		defs(441):='USER4';
		defs(442):='USER5';
		defs(443):='USER6';
		defs(444):='USER7';
		defs(445):='USER8';
		defs(446):='USER9';
		defs(447):='UTILITY';
		defs(448):='UTLESTAT';
		defs(449):='VEA';
		defs(450):='VEH';
		defs(451):='VERTEX_LOGIN';
		defs(452):='VIDEOUSER';
		defs(453):='VIF_DEV_PWD';
		defs(454):='VIRUSER';
		defs(455):='VRR1';
		defs(456):='VRR2';
		defs(457):='WEBCAL01';
		defs(458):='WEBDB';
		defs(459):='WEBREAD';
		defs(460):='WELCOME';
		defs(461):='WEST';
		defs(462):='WFADMIN';
		defs(463):='WH';
		defs(464):='WIP';
		defs(465):='WKADMIN';
		defs(466):='WKPROXY';
		defs(467):='WKSYS';
		defs(468):='WKUSER';
		defs(469):='WK_TEST';
		defs(470):='WMS';
		defs(471):='WMSYS';
		defs(472):='WOB';
		defs(473):='WOOD';
		defs(474):='WPS';
		defs(475):='WSH';
		defs(476):='WSM';
		defs(477):='WWW';
		defs(478):='WWWUSER';
		defs(479):='XADEMO';
		defs(480):='XDP';
		defs(481):='XLA';
		defs(482):='XNC';
		defs(483):='XNI';
		defs(484):='XNM';
		defs(485):='XNP';
		defs(486):='XNS';
		defs(487):='XPRT';
		defs(488):='XTR';
		defs(489):='XXX';
		defs(490):='YES';
		defs(491):='YOUR_PASS';
		defs(492):='ZWERG';
		defs(493):='FOOBAR';
		defs(494):='LIZARD';
		defs(495):='PASS';
		defs(496):='PEOP1E';
		defs(497):='AASH';                                                              
		defs(498):='ABA1';                                                              
		defs(499):='ADS';                                                               
		defs(500):='AL';                                                                
		defs(501):='ALA1';                                                              
		defs(502):='ALLUSERS';                                                          
		defs(503):='AMA1';                                                              
		defs(504):='AMA2';                                                              
		defs(505):='AMA3';                                                              
		defs(506):='AMA4';                                                              
		defs(507):='AMF';                                                               
		defs(508):='AMS';                                                               
		defs(509):='AMS1';                                                              
		defs(510):='AMS2';                                                              
		defs(511):='AMS3';                                                              
		defs(512):='AMS4';                                                              
		defs(513):='AMSYS';                                                             
		defs(514):='AMW';                                                               
		defs(515):='ANNE';                                                              
		defs(516):='AOLDEMO';                                                           
		defs(517):='APA1';                                                              
		defs(518):='APA2';                                                              
		defs(519):='APA3';                                                              
		defs(520):='APA4';                                                              
		defs(521):='APPLEAD';                                                           
		defs(522):='APS1';                                                              
		defs(523):='APS2';                                                              
		defs(524):='APS3';                                                              
		defs(525):='APS4';                                                              
		defs(526):='ARA1';                                                              
		defs(527):='ARA2';                                                              
		defs(528):='ARA3';                                                              
		defs(529):='ARA4';                                                              
		defs(530):='ARS1';                                                              
		defs(531):='ARS2';                                                              
		defs(532):='ARS3';                                                              
		defs(533):='ARS4';                                                              
		defs(534):='ART';                                                               
		defs(535):='ASN';                                                               
		defs(536):='AUC_GUEST';                                                         
		defs(537):='AUTHORIA';                                                          
		defs(538):='B2B';                                                               
		defs(539):='BAM';                                                               
		defs(540):='BCA1';                                                              
		defs(541):='BCA2';                                                              
		defs(542):='BMEADOWS';                                                          
		defs(543):='BNE';                                                               
		defs(544):='BP01';                                                              
		defs(545):='BP02';                                                              
		defs(546):='BP03';                                                              
		defs(547):='BP04';                                                              
		defs(548):='BP05';                                                              
		defs(549):='BP06';                                                              
		defs(550):='BUYACCT';                                                           
		defs(551):='BUYAPPR1';                                                          
		defs(552):='BUYAPPR2';                                                          
		defs(553):='BUYAPPR3';                                                          
		defs(554):='BUYER';                                                             
		defs(555):='BUYMTCH';                                                           
		defs(556):='CAMRON';                                                            
		defs(557):='CANDICE';                                                           
		defs(558):='CARL';                                                              
		defs(559):='CARLY';                                                             
		defs(560):='CARMEN';                                                            
		defs(561):='CARRIECONYERS';                                                     
		defs(562):='CATADMIN';                                                          
		defs(563):='CEASAR';                                                            
		defs(564):='CFD';                                                               
		defs(565):='CHANDRA';                                                           
		defs(566):='CHARLEY';                                                           
		defs(567):='CHRISBAKER';                                                        
		defs(568):='CHRISTIE';                                                          
		defs(569):='CINDY';                                                             
		defs(570):='CLARK';                                                             
		defs(571):='CLAUDE';                                                            
		defs(572):='CLINT';                                                             
		defs(573):='CLN';                                                               
		defs(574):='CNCADMIN';                                                          
		defs(575):='CONNIE';                                                            
		defs(576):='CONNOR';                                                            
		defs(577):='CORY';                                                              
		defs(578):='CRM1';                                                              
		defs(579):='CRM2';                                                              
		defs(580):='CRPB733';                                                           
		defs(581):='CRPCTL';                                                            
		defs(582):='CRPDTA';                                                            
		defs(583):='CSADMIN';                                                           
		defs(584):='CSAPPR1';                                                           
		defs(585):='CSDUMMY';                                                           
		defs(586):='CSM';                                                               
		defs(587):='CTXTEST';                                                           
		defs(588):='DAVIDMORGAN';                                                       
		defs(589):='DCM';                                                               
		defs(590):='DD7333';                                                            
		defs(591):='DD7334';                                                            
		defs(592):='DD810';                                                             
		defs(593):='DD811';                                                             
		defs(594):='DD812';                                                             
		defs(595):='DD9';                                                               
		defs(596):='DDB733';                                                            
		defs(597):='DDD';                                                               
		defs(598):='DEVB733';                                                           
		defs(599):='DEVUSER';                                                           
		defs(600):='DISCOVERER5';                                                       
		defs(601):='DKING';                                                             
		defs(602):='DLD';                                                               
		defs(603):='DMATS';                                                             
		defs(604):='DMS';                                                               
		defs(605):='DOM';                                                               
		defs(606):='DPOND';                                                             
		defs(607):='DV7333';                                                            
		defs(608):='DV7334';                                                            
		defs(609):='DV810';                                                             
		defs(610):='DV811';                                                             
		defs(611):='DV812';                                                             
		defs(612):='DV9';                                                               
		defs(613):='DVP1';                                                              
		defs(614):='EDR';                                                               
		defs(615):='EDWEUL_US';                                                         
		defs(616):='EDWREP';                                                            
		defs(617):='EGC1';                                                              
		defs(618):='EGD1';                                                              
		defs(619):='EGM1';                                                              
		defs(620):='EGO';                                                               
		defs(621):='EGR1';                                                              
		defs(622):='END1';                                                              
		defs(623):='ENM1';                                                              
		defs(624):='ENS1';                                                              
		defs(625):='ENTMGR_CUST';                                                       
		defs(626):='ENTMGR_PRO';                                                        
		defs(627):='ENTMGR_TRAIN';                                                      
		defs(628):='EOPP_PORTALADM';                                                    
		defs(629):='EOPP_PORTALMGR';                                                    
		defs(630):='EOPP_USER';                                                         
		defs(631):='EUL_US';                                                            
		defs(632):='EXA1';                                                              
		defs(633):='EXA2';                                                              
		defs(634):='EXA3';                                                              
		defs(635):='EXA4';                                                              
		defs(636):='EXS1';                                                              
		defs(637):='EXS2';                                                              
		defs(638):='EXS3';                                                              
		defs(639):='EXS4';                                                              
		defs(640):='FIA1';                                                              
		defs(641):='FNI1';                                                              
		defs(642):='FNI2';                                                              
		defs(643):='FPA';                                                               
		defs(644):='FTA1';                                                              
		defs(645):='FUN';                                                               
		defs(646):='FVP1';                                                              
		defs(647):='GALLEN';                                                            
		defs(648):='GCA1';                                                              
		defs(649):='GCA2';                                                              
		defs(650):='GCA3';                                                              
		defs(651):='GCA9';                                                              
		defs(652):='GCMGR1';                                                            
		defs(653):='GCMGR2';                                                            
		defs(654):='GCMGR3';                                                            
		defs(655):='GCS';                                                               
		defs(656):='GCS1';                                                              
		defs(657):='GCS2';                                                              
		defs(658):='GCS3';                                                              
		defs(659):='GEORGIAWINE';                                                       
		defs(660):='GLA1';                                                              
		defs(661):='GLA2';                                                              
		defs(662):='GLA3';                                                              
		defs(663):='GLA4';                                                              
		defs(664):='GLS1';                                                              
		defs(665):='GLS2';                                                              
		defs(666):='GLS3';                                                              
		defs(667):='GLS4';                                                              
		defs(668):='GM_AWDA';                                                           
		defs(669):='GM_COPI';                                                           
		defs(670):='GM_DPHD';                                                           
		defs(671):='GM_MLCT';                                                           
		defs(672):='GM_PLADMA';                                                         
		defs(673):='GM_PLADMH';                                                         
		defs(674):='GM_PLCCA';                                                          
		defs(675):='GM_PLCCH';                                                          
		defs(676):='GM_PLCOMA';                                                         
		defs(677):='GM_PLCOMH';                                                         
		defs(678):='GM_PLCONA';                                                         
		defs(679):='GM_PLCONH';                                                         
		defs(680):='GM_PLNSCA';                                                         
		defs(681):='GM_PLNSCH';                                                         
		defs(682):='GM_PLSCTA';                                                         
		defs(683):='GM_PLSCTH';                                                         
		defs(684):='GM_PLVET';                                                          
		defs(685):='GM_SPO';                                                            
		defs(686):='GM_STKH';                                                           
		defs(687):='GUEST';                                                             
		defs(688):='HCC';                                                               
		defs(689):='HHCFO';                                                             
		defs(690):='IA';                                                                
		defs(691):='IBC';                                                               
		defs(692):='INTERNET_APPSERVER_REGISTRY';                                       
		defs(693):='IP';                                                                
		defs(694):='ISTEWARD';                                                          
		defs(695):='JD7333';                                                            
		defs(696):='JD7334';                                                            
		defs(697):='JD9';                                                               
		defs(698):='JDE';                                                               
		defs(699):='JDEDBA';                                                            
		defs(700):='JOHNINARI';                                                         
		defs(701):='JTI';                                                               
		defs(702):='JTR';                                                               
		defs(703):='JUNK_PS';                                                           
		defs(704):='JUSTOSHUM';                                                         
		defs(705):='KELLYJONES';                                                        
		defs(706):='KEVINDONS';                                                         
		defs(707):='KPN';                                                               
		defs(708):='LADAMS';                                                            
		defs(709):='LBA';                                                               
		defs(710):='LDQUAL';                                                            
		defs(711):='LHILL';                                                             
		defs(712):='LNS';                                                               
		defs(713):='LQUINCY';                                                           
		defs(714):='LSA';                                                               
		defs(715):='MGR2';                                                              
		defs(716):='MGR3';                                                              
		defs(717):='MGR4';                                                              
		defs(718):='MIKEIKEGAMI';                                                       
		defs(719):='MJONES';                                                            
		defs(720):='MLAKE';                                                             
		defs(721):='MM1';                                                               
		defs(722):='MM2';                                                               
		defs(723):='MM3';                                                               
		defs(724):='MM4';                                                               
		defs(725):='MM5';                                                               
		defs(726):='MMARTIN';                                                           
		defs(727):='MST';                                                               
		defs(728):='NEILKATSU';                                                         
		defs(729):='OBJ7333';                                                           
		defs(730):='OBJ7334';                                                           
		defs(731):='OBJB733';                                                           
		defs(732):='OCA';                                                               
		defs(733):='OKL';                                                               
		defs(734):='OL810';                                                             
		defs(735):='OL811';                                                             
		defs(736):='OL812';                                                             
		defs(737):='OL9';                                                               
		defs(738):='ORABAM';                                                            
		defs(739):='ORABAMSAMPLES';                                                     
		defs(740):='ORABPEL';                                                           
		defs(741):='ORAESB';                                                            
		defs(742):='ORAOCA_PUBLIC';                                                     
		defs(743):='ORASAGENT';                                                         
		defs(744):='OWAPUB';                                                            
		defs(745):='PABLO';                                                             
		defs(746):='PAIGE';                                                             
		defs(747):='PAM';                                                               
		defs(748):='PARRISH';                                                           
		defs(749):='PARSON';                                                            
		defs(750):='PAT';                                                               
		defs(751):='PATORILY';                                                          
		defs(752):='PATRICKSANCHEZ';                                                    
		defs(753):='PATSY';                                                             
		defs(754):='PAULA';                                                             
		defs(755):='PAXTON';                                                            
		defs(756):='PCA1';                                                              
		defs(757):='PCA2';                                                              
		defs(758):='PCA3';                                                              
		defs(759):='PCA4';                                                              
		defs(760):='PCS1';                                                              
		defs(761):='PCS2';                                                              
		defs(762):='PCS3';                                                              
		defs(763):='PCS4';                                                              
		defs(764):='PD7333';                                                            
		defs(765):='PD7334';                                                            
		defs(766):='PD810';                                                             
		defs(767):='PD811';                                                             
		defs(768):='PD812';                                                             
		defs(769):='PD9';                                                               
		defs(770):='PDA1';                                                              
		defs(771):='PEARL';                                                             
		defs(772):='PEG';                                                               
		defs(773):='PENNY';                                                             
		defs(774):='PERCY';                                                             
		defs(775):='PERRY';                                                             
		defs(776):='PETE';                                                              
		defs(777):='PEYTON';                                                            
		defs(778):='PHIL';                                                              
		defs(779):='PJI';                                                               
		defs(780):='POLLY';                                                             
		defs(781):='PON';                                                               
		defs(782):='PORTAL';                                                            
		defs(783):='PORTAL_APP';                                                        
		defs(784):='PORTAL_PUBLIC';                                                     
		defs(785):='PPM1';                                                              
		defs(786):='PPM2';                                                              
		defs(787):='PPM3';                                                              
		defs(788):='PPM4';                                                              
		defs(789):='PPM5';                                                              
		defs(790):='PRISTB733';                                                         
		defs(791):='PRISTCTL';                                                          
		defs(792):='PRISTDTA';                                                          
		defs(793):='PRODB733';                                                          
		defs(794):='PRODCTL';                                                           
		defs(795):='PRODDTA';                                                           
		defs(796):='PRODUSER';                                                          
		defs(797):='PRP';                                                               
		defs(798):='PS';                                                                
		defs(799):='PS810';                                                             
		defs(800):='PS810CTL';                                                          
		defs(801):='PS810DTA';                                                          
		defs(802):='PS811';                                                             
		defs(803):='PS811CTL';                                                          
		defs(804):='PS811DTA';                                                          
		defs(805):='PS812';                                                             
		defs(806):='PS812CTL';                                                          
		defs(807):='PS812DTA';                                                          
		defs(808):='PSBASS';                                                            
		defs(809):='PSEM';                                                              
		defs(810):='PSFT';                                                              
		defs(811):='PSFTDBA';                                                           
		defs(812):='PTE';                                                               
		defs(813):='PTG';                                                               
		defs(814):='PTJPN';                                                             
		defs(815):='PTWEBSERVER';                                                       
		defs(816):='PY7333';                                                            
		defs(817):='PY7334';                                                            
		defs(818):='PY810';                                                             
		defs(819):='PY811';                                                             
		defs(820):='PY812';                                                             
		defs(821):='PY9';                                                               
		defs(822):='QOT';                                                               
		defs(823):='QRM';                                                               
		defs(824):='RENE';                                                              
		defs(825):='RESTRICTED_US';                                                     
		defs(826):='RM1';                                                               
		defs(827):='RM2';                                                               
		defs(828):='RM3';                                                               
		defs(829):='RM4';                                                               
		defs(830):='RM5';                                                               
		defs(831):='ROB';                                                               
		defs(832):='RPARKER';                                                           
		defs(833):='RWA1';                                                              
		defs(834):='SALLYH';                                                            
		defs(835):='SAM';                                                               
		defs(836):='SARAHMANDY';                                                        
		defs(837):='SCM1';                                                              
		defs(838):='SCM2';                                                              
		defs(839):='SCM3';                                                              
		defs(840):='SCM4';                                                              
		defs(841):='SDAVIS';                                                            
		defs(842):='SEDWARDS';                                                          
		defs(843):='SELLCM';                                                            
		defs(844):='SELLER';                                                            
		defs(845):='SELLTREAS';                                                         
		defs(846):='SETUP';                                                             
		defs(847):='SID';                                                               
		defs(848):='SKAYE';                                                             
		defs(849):='SKYTETSUKA';                                                        
		defs(850):='SLSAA';                                                             
		defs(851):='SLSMGR';                                                            
		defs(852):='SLSREP';                                                            
		defs(853):='SRABBITT';                                                          
		defs(854):='SRALPHS';                                                           
		defs(855):='SRAY';                                                              
		defs(856):='SRIVERS';                                                           
		defs(857):='SSA1';                                                              
		defs(858):='SSA2';                                                              
		defs(859):='SSA3';                                                              
		defs(860):='SSC1';                                                              
		defs(861):='SSC2';                                                              
		defs(862):='SSC3';                                                              
		defs(863):='SSOSDK';                                                            
		defs(864):='SSS1';                                                              
		defs(865):='SUPPLIER';                                                          
		defs(866):='SVM7333';                                                           
		defs(867):='SVM7334';                                                           
		defs(868):='SVM810';                                                            
		defs(869):='SVM811';                                                            
		defs(870):='SVM812';                                                            
		defs(871):='SVM9';                                                              
		defs(872):='SVMB733';                                                           
		defs(873):='SVP1';                                                              
		defs(874):='SY810';                                                             
		defs(875):='SY811';                                                             
		defs(876):='SY812';                                                             
		defs(877):='SY9';                                                               
		defs(878):='SYS7333';                                                           
		defs(879):='SYS7334';                                                           
		defs(880):='SYSB733';                                                           
		defs(881):='TDEMARCO';                                                          
		defs(882):='TESTCTL';                                                           
		defs(883):='TESTDTA';                                                           
		defs(884):='TRA1';                                                              
		defs(885):='TRBM1';                                                             
		defs(886):='TRCM1';                                                             
		defs(887):='TRDM1';                                                             
		defs(888):='TRRM1';                                                             
		defs(889):='TWILLIAMS';                                                         
		defs(890):='UDDISYS';                                                           
		defs(891):='VIDEO31';                                                           
		defs(892):='VIDEO4';                                                            
		defs(893):='VIDEO5';                                                            
		defs(894):='VP1';                                                               
		defs(895):='VP2';                                                               
		defs(896):='VP3';                                                               
		defs(897):='VP4';                                                               
		defs(898):='VP5';                                                               
		defs(899):='VP6';                                                               
		defs(900):='WAA1';                                                              
		defs(901):='WAA2';                                                              
		defs(902):='WCRSYS';                                                            
		defs(903):='WENDYCHO';                                                          
		defs(904):='WIRELESS';                                                          
		defs(905):='XDO';                                                               
		defs(906):='XLE';                                                               
		defs(907):='XNB';                                                               
		defs(908):='YCAMPOS';                                                           
		defs(909):='YSANCHEZ';                                                          
		defs(910):='ZFA';                                                               
		defs(911):='ZPB';                                                               
		defs(912):='ZSA';                                                               
		defs(913):='ZX'; 
		--
	end;
	--
	procedure init_dicts
	is
	begin
		--
		dicts(1):='THOMAS';
		dicts(2):='ARSENAL';
		dicts(3):='MONKEY';
		dicts(4):='CHARLIE';
		dicts(5):='QWERTY';
		dicts(6):='123456';
		dicts(7):='LETMEIN';
		dicts(8):='NCC1701';
		dicts(9):='TRUSTNO1';
		dicts(10):='LIVERPOOL';
		dicts(11):='PASSWORD';
		dicts(12):='ABC123';
		dicts(13):='MYSPACE1';
		dicts(14):='PASSWORD1';
		dicts(15):='ORACLE';
		dicts(16):='ELCARO';
		dicts(17):='BLINK182';
		dicts(18):='THX1138';
		dicts(19):='12345';
		dicts(20):='ABC123';
		dicts(21):='PASSWORD';
		dicts(22):='PASSWD';
		dicts(23):='123456';
		dicts(24):='NEWPASS';
		dicts(25):='NOTUSED';
		dicts(26):='ORACLE10G';
		dicts(27):='ORA10G';
		dicts(28):='CHANGEME';
		dicts(29):='ORACLE11GR1';
		dicts(30):='ORACLE1';
		dicts(31):='ORACLE2';
		dicts(32):='ORACLE3';
		dicts(33):='ORACLE4';
		dicts(34):='ORACLE5';
		dicts(35):='ORACLE6';
		dicts(36):='ORACLE7';
		dicts(37):='ORACLE8';
		dicts(38):='ORACLE9';
		dicts(39):='ORACLE0';
		dicts(40):='ORACLE9IR1';
		dicts(41):='ORACLE9IR2';
		dicts(42):='ORACLE8IR1';
		dicts(43):='ORACLE8IR2';
		dicts(44):='ORACLE8IR3';
		dicts(45):='ORACLE10GR1';
		dicts(46):='ORACLE10GR2';
		dicts(47):='ORACLE11G';
		--
	end;
	--
	procedure init_hashes
	is
	begin
		--
		hashes(1).hash:='94C33111FD9C66F3';                                             
		hashes(1).user:='ANONYMOUS';                                                    
		hashes(2).hash:='2ADC32A0B154F897';                                             
		hashes(2).user:='INS1 ';                                                        
		hashes(3).hash:='EA372A684B790E2A';                                             
		hashes(3).user:='INS2 ';                                                        
		hashes(4).hash:='E013305AB0185A97';                                             
		hashes(4).user:='MGR1 ';                                                        
		hashes(5).hash:='4C35813E45705EBA';                                             
		hashes(5).user:='PTADMIN ';                                                     
		hashes(6).hash:='463AEFECBA55BEE8';                                             
		hashes(6).user:='PTCNE ';                                                       
		hashes(7).hash:='251D71390034576A';                                             
		hashes(7).user:='PTDMO ';                                                       
		hashes(8).hash:='5553404C13601916';                                             
		hashes(8).user:='PTESP ';                                                       
		hashes(9).hash:='A360DAD317F583E3';                                             
		hashes(9).user:='PTFRA ';                                                       
		hashes(10).hash:='C8D1296B4DF96518';                                            
		hashes(10).user:='PTGER ';                                                      
		hashes(11).hash:='D0EF510BCB2992A3';                                            
		hashes(11).user:='PTUKE ';                                                      
		hashes(12).hash:='2C27080C7CC57D06';                                            
		hashes(12).user:='PTUPG ';                                                      
		hashes(13).hash:='8F7F509D4DC01DF6';                                            
		hashes(13).user:='PTWEB ';                                                      
		hashes(14).hash:='43CA255A7916ECFE';                                            
		hashes(14).user:='SYS';                                                         
		hashes(15).hash:='EB258E708132DD2D';                                            
		hashes(15).user:='SYSMAN';                                                      
		hashes(16).hash:='4D27CA6E3E3066E6';                                            
		hashes(16).user:='SYSTEM'; 
		--
	end;
	--	
begin
	--
	-- ---------------------------------------------------
	-- initialise debug
	-- ---------------------------------------------------
	--
	if :debugv = 'ON' then
		traceon(pv_mode => 'L',pv_level => :debugl);	
	end if;
	select to_char(sysdate,'Dy Mon dd hh24:mi:ss yyyy') system_date 
	into prod_date
	from sys.dual;
	dbms_output.put_line('cracker: Release 1.0.5.0.0 - Beta on '||prod_date);
	dbms_output.put_line('Copyright (c) 2008, 2009 PeteFinnigan.com Limited. All rights reserved.');
	dbms_output.new_line;
	--
	-- ----------------------------------------------------------------
	-- initialise the default user strings and dictionary words
	-- ----------------------------------------------------------------
	--
	init_default;
	init_dicts;
	init_hashes;
	--
	-- pre load the users details
	--
	pre_load;
	--
	start_time:=dbms_utility.get_time;
	--
	-- ----------------------------------------------------------------
	-- crack default passwords
	-- ----------------------------------------------------------------
	--
	--debugw(pv_level => '5',
	--	pv_str => 'defs array len = ['||defs.count||']');
	for i in 1..max_users loop
		for j in 1..defs.count loop
			--debugw(pv_level => '5',
			--	pv_str => 'j = '||j||': defs(j)='||defs(j));
			unicode_str(userts(i).username||defs(j),raw_ip);
			if (userts(i).hash10g = crack(raw_ip,num_cracks)) then
				userts(i).flg:=TRUE;
				userts(i).crt:='DE';
				if (:weakv = 'ON') then
					userts(i).password:='WEAK';
				else
					userts(i).password:=defs(j);				
				end if;
			end if;
		end loop;
	end loop;	
	-- 
	-- -----------------------------------------------------------------
	-- crack username=password
	-- -----------------------------------------------------------------
	--
	for i in 1..max_users loop
		if(userts(i).flg = FALSE) then
			unicode_str(userts(i).username||userts(i).username,raw_ip);
			if (userts(i).hash10g = crack(raw_ip,num_cracks)) then
				userts(i).flg:=TRUE;
				userts(i).crt:='PU';
				if (:weakv = 'ON') then
					userts(i).password:='WEAK';
				else
					userts(i).password:=userts(i).username;				
				end if;
			end if;
		end if;
	end loop;
	--
	-- ------------------------------------------------------------------
	-- crack dictionary words
	-- ------------------------------------------------------------------
	--
	--debugw(pv_level => '5',
	--	pv_str => 'dictss array len = ['||dicts.count||']');	
	for i in 1..max_users loop
		if(userts(i).flg = FALSE) then
			for j in 1..dicts.count loop
				--debugw(pv_level => '5',
				--	pv_str => 'j = '||j||': dicts(j)='||dicts(j));
				unicode_str(userts(i).username||dicts(j),raw_ip);
				if (userts(i).hash10g = crack(raw_ip,num_cracks)) then
					userts(i).flg:=TRUE;
					userts(i).crt:='DI';
					if (:weakv = 'ON') then
						userts(i).password:='WEAK';
					else
						userts(i).password:=dicts(j);				
					end if;
				end if;
			end loop;
		end if;
	end loop;	
	-- 
	-- --------------------------------------------------------------------
	-- do the brute force cracks
	-- --------------------------------------------------------------------
	--	
	passlen:=4;   -- need to restrict to 4 so that it takes around 35 secs 
	--		
	for j in 1..max_users loop
		if(userts(j).flg = FALSE) then			
			for i in 1..passlen loop
				mask(i):=0;
			end loop;
			while updatemask(1) loop
				-- create the password
				bfpass:='';
				for i in 1..passlen loop
					if mask(i) != 0 then
						bfpass:=substr(charset,mask(i),1)||bfpass;	
					end if;
				end loop;
				--debugw(pv_level => '7',pv_str => 'passwd='||bfpass);
				unicode_str(userts(j).username||bfpass,raw_ip);
				if (userts(j).hash10g = crack(raw_ip,num_cracks)) then
					userts(j).flg:=TRUE;
					userts(j).crt:='BF';
					if (:weakv = 'ON') then
						userts(j).password:='WEAK';
					else
						userts(j).password:=bfpass;				
					end if;
				end if;
			end loop;
		end if;	
	end loop;		
	--
	-- -------------------------------------------------------------------------------
	-- do the hash check
	-- -------------------------------------------------------------------------------
	--debugw(pv_level => '5',
	--	pv_str => 'hashes array len = ['||hashes.count||']');	
	for i in 1..max_users loop
		if(userts(i).flg = FALSE) then
			for j in 1..hashes.count loop
				--debugw(pv_level => '5',
				--	pv_str => 'j = '||j||': hashes(j)='||hashes(j).user||':'||hashes(j).hash);
				if ((userts(i).hash10g = hashes(j).hash) and (userts(i).username = hashes(j).user)) then
					userts(i).flg:=TRUE;
					userts(i).crt:='HS';
					userts(i).password:='HASH {'||hashes(j).hash||'}';
				end if;
			end loop;
		end if;
	end loop;	
	--
	-- -------------------------------------------------------------------------------
	-- print col header for the output
	-- -------------------------------------------------------------------------------
	--
	dbms_output.put_line('T '||rpad('Username',20)||' '||rpad('Password',20)||'   CR FL STA');
	dbms_output.put_line('=======================================================');
	dbms_output.new_line;
	--
	-- print out the results
	--
	for i in 1..max_users loop
		if (userts(i).flg = TRUE) then
			res_cracked:='CR';
		else
			res_cracked:='--';
		end if;
		if userts(i).password is null then
			res_password:='                    ';
		else
			res_password:=rpad(userts(i).password,20);		
		end if;
		res_username:=rpad('"'||userts(i).username||'"',20);
		dbms_output.put_line(userts(i).entry_type||' '
			||res_username||' ['||res_password
			||'] '||userts(i).crt||' '||res_cracked
			||' '||userts(i).accnt_status);
	end loop;

	end_time:=dbms_utility.get_time;
	elapsed_time_sec:=(end_time-start_time)/100;
	dbms_output.new_line;
	dbms_output.new_line;
	dbms_output.put_line('INFO: Number of crack attempts = ['||num_cracks||']');
	dbms_output.put_line('INFO: Elapsed time = ['||to_char(elapsed_time_sec)||' Seconds]');	
	dbms_output.put_line('INFO: Cracks per second = ['||to_char(trunc(num_cracks/elapsed_time_sec,-1))||']');
	traceoff;
end;
/


undefine debug
undefine _if_11g
undefine debug_level