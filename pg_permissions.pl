#!/usr/bin/perl
#------------------------------------------------------------------------------------
#
# pg_permission
#
#
#
#
#
#------------------------------------------------------------------------------------
use vars qw($VERSION);

use strict;
use warnings;
use DBI;
use Getopt::Long qw(:config no_ignore_case bundling);
#use IO::File;

$VERSION = '0.3';

# Command line options
my $dbname			= '';
my $host			= '';
my $user			= '';
my $port			= '';
my $outfile			= '';
my $role			= '';
my $maintenancedb		= 'postgres';

# Others
my $connected			= 0;
my $db				= undef;
my @dblist			= undef;
my @tab				= undef;
my $req				= undef;
my $conninfo			= '';
my $pgversion			= undef;
my $ver				= '';
my $help			= '';
my $escape_char			= '';
my $role_table			= 'pg_roles';
my $role_table_pk		= 'oid';
my $role_table_name		= 'rolname';

my $result = GetOptions(
	"h|host=s"		=> \$host,
	"H|help!"		=> \$help,
	"m|maintenance=s"	=> \$maintenancedb,
	"p|port=i"		=> \$port,
	"U|user=s"		=> \$user,
	"o|outfiles=s"		=> \$outfile,
	"r|role=s"		=> \$role,
	"d|dbname=s"		=> \$dbname,
	"V|version!"		=> \$ver
);

if ($ver){
	print "pg_permissions version $VERSION\n";
	exit 0;
}
&usage() if ($help);
# Connect to database and initialize version specific parameters
connect_db();

$pgversion = get_pgversion();
$escape_char='E' if (hasmajor(8.1));
$role_table='pg_user' if (!hasmajor(8.1));
$role_table_pk='usesysid' if (!hasmajor(8.1));
$role_table_name='usename' if (!hasmajor(8.1));

if ($dbname eq ''){
	@dblist = get_db_list();
}else{
	@dblist = ($dbname);
}

#Global ACLs
get_acl_roles();

my $sql;

if (hasmajor(8.0)){
	$sql = "SELECT '\"' || spcname || '\"', pg_get_userbyid(spcowner),COALESCE(array_to_string(spcacl,$escape_char'\\n'),'')"
		." FROM pg_tablespace";
	get_acl_prm($sql,"Tablespace");
}

$sql = "SELECT '\"' || lanname || '\"', ".(hasmajor(8.3)?'pg_get_userbyid(lanowner)':"''").",COALESCE(array_to_string(lanacl,$escape_char'\\n'),'')"
		." FROM pg_language";
get_acl_prm($sql,"Language");

#Database specific ACLs
foreach my $current_db (@dblist){
	get_db_permissions($current_db);
}

print "\n";
disconnect_db();

#------------------------------------------------------------------------------

# Build the connection string with specified arguments
sub build_conninfo{
	my ($current_db) = @_;
	$conninfo = 'dbi:Pg:';
	$conninfo .= " user=$user" if ($user ne '');
	$conninfo .= " port=$port" if ($port ne '');
	$conninfo .= " host=$host" if ($host ne '');
	if ((! defined $current_db) || ( $current_db eq '')){
		$conninfo .= " dbname=$maintenancedb";
	}else{
		$conninfo .= " dbname=$current_db";
	}
}

#------------------------------------------------------------------------------

# Connect to a database
# args:
#    $force	: force to disconnect if already connected
sub connect_db{
	my ($force) = @_;
	if (($force) && ($connected)){
		disconnect_db();
	}
	return if ($connected);
	build_conninfo('') if ($conninfo eq '');
	$db = DBI->connect($conninfo) or die('Could not connect to the database');
	$connected = 1;
}

#------------------------------------------------------------------------------

# Disconnect from database
sub disconnect_db{
	if ($connected){
		$db->disconnect();
		$connected = 0;
	}
}

#------------------------------------------------------------------------------

# Return PostgreSQL's major version
sub get_pgversion{
	$req = $db->prepare("SELECT version();");
	$req->execute();
	@tab = $req->fetchrow_array();
	$req->finish();
	return substr($tab[0],11,3);
}

#------------------------------------------------------------------------------

# Check if PostgreSQL cluster major version is recent enough
# returns boolean
sub hasmajor{
	my ($wanted_version) = @_;
	return ($pgversion >= $wanted_version);
}

#------------------------------------------------------------------------------

# Retrieve all databases except templates one
sub get_db_list{
	$req = $db->prepare("SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY datname;");
	$req->execute();
	my @list;
	while (@tab = $req->fetchrow_array()){
		push(@list,$tab[0]);
	}
	$req->finish();
	return @list;
}

#------------------------------------------------------------------------------

#  Connect to a specific database and retrieve ACLs
# args:
#    $current_db	: database to connect on
sub get_db_permissions{
	my ($current_db) = @_;
	build_conninfo($current_db);
	connect_db(1);
	get_acl_class($current_db);
}

#------------------------------------------------------------------------------

# Get role ACLs (database wild)
sub get_acl_roles{
	print "Global\n";
	my $sql;
	if (hasmajor(8.1)){
		$sql = "SELECT r.rolname,r.rolsuper,r.rolinherit,r.rolcreaterole,r.rolcreatedb,r.rolcatupdate,"
			."r.rolcanlogin,"
			."ARRAY(SELECT b.rolname"
			."	FROM pg_catalog.pg_auth_members m"
			."	JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)"
			."	WHERE m.member = r.oid) as memberof"
			.(hasmajor(9.0)?",r.rolreplication":"")
			." FROM pg_roles r".($role ne ''?" WHERE r.rolname = '$role'":"");
	}else{
		$sql = "SELECT r.usename,r.usesuper,false,false,r.usecreatedb,r.usecatupd,true,"
			."null"
			."  FROM pg_user r".($role ne ''?" WHERE r.usename = '$role'":"");
	}

	$req = $db->prepare($sql);
	$req->execute();
	while(@tab = $req->fetchrow_array()){
		print "  Role \"$tab[0]\":".($tab[1]?" Super":"").($tab[2]?" Inherit":"").($tab[3]?" Create_role":"").($tab[4]?" Create_db":"")
		.($tab[5]?" Catalog_update":"").($tab[6]?" Login":"").((hasmajor(9.0) && ($tab[8]))?" Replication":"")."\n";
		if ( (defined(@{$tab[7]}))){
			print "    Member of : ";
			foreach my $cur (@{$tab[7]}){
				print "\"$cur\" ";
			}
			print "\n";
		}
	}
	$req->finish();
}

#------------------------------------------------------------------------------

# Get all database specific ACLs on a database
# args:
#    $current_db	: chosen database
sub get_acl_class{
	my ($current_db) = @_;
	my $_sql;
	print 'database "'.$current_db.'"'."\n";

	$_sql = "SELECT '\"' || n.nspname || '\"',pg_get_userbyid(n.nspowner),COALESCE(array_to_string(n.nspacl,$escape_char'\\n'),'')"
		." FROM pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';";
	get_acl_prm($_sql,'Schema');

	$_sql  = "SELECT '\"' || n.nspname || '\".\"' || p.proname || '\"(' || pg_get_function_arguments(p.oid) || ')',r.$role_table_name,"
		." COALESCE(array_to_string(p.proacl,$escape_char'\\n'),'')"
		." FROM pg_proc p"
		." JOIN pg_namespace n ON p.pronamespace = n.oid"
		." JOIN $role_table r ON p.proowner = r.$role_table_pk"
		." WHERE n.nspname !~ 'pg_'"
		." AND n.nspname != 'information_schema'"
		." ORDER BY proname;";
	get_acl_prm($_sql,'Function');

	if (hasmajor(8.4)){
		$_sql = "SELECT '\"' || fdwname || '\"', pg_get_userbyid(fdwowner), COALESCE(array_to_string(fdwacl,$escape_char'\\n'),'')"
			." FROM pg_foreign_data_wrapper";
		get_acl_prm($_sql,"Foreign Data Wrapper");
	}

	$_sql  = "SELECT c.relkind,'\"' || n.nspname || '\".\"' || c.relname || '\"',r.$role_table_name ,"
		." COALESCE(array_to_string(c.relacl,$escape_char'\\n'),''),c.oid"
		." FROM pg_class c"
		." JOIN pg_namespace n ON c.relnamespace = n.oid"
		." JOIN $role_table r ON c.relowner = r.$role_table_pk"
		." WHERE n.nspname !~ 'pg_'"
		." AND n.nspname != 'information_schema'"
		." AND relkind NOT IN ('i')"
		." ORDER BY relkind,relname;";
	$req = $db->prepare($_sql);
	$req->execute();
	my $current_obj = '';
	while (@tab = $req->fetchrow_array()){
		if ($tab[1] ne $current_obj){
			print "  ".get_type_obj($tab[0])." $tab[1]\n";
			$current_obj = $tab [1];
		}
		my @tabacl = split('\n',$tab[3]);
		print "    Default ACL\n    Owner: $tab[2]\n" if($tab[3] eq '');
		foreach my $acl (@tabacl){
			my $first_delim = index($acl,'=');
			my $current_role = substr($acl,0,$first_delim);
			if (!(($role ne '') && ($role ne $current_role))){
				print "    Role \"".$current_role."\": ".acl2char(substr($acl,$first_delim+1,index($acl,'/')-$first_delim-1));
				print " (owner)" if ($current_role eq $tab[2]);
				print("\n");
			}
		}
		if(hasmajor(8.4)){
			my $sql = "SELECT '\"' || attname || '\"',COALESCE(array_to_string(attacl,$escape_char'\\n'),'')"
				." FROM pg_attribute WHERE attrelid = $tab[4] AND attacl IS NOT NULL;";
			my $req2 = $db->prepare($sql);
			$req2->execute();
			while(my @tab2 = $req2->fetchrow_array()){
				my @tabacl2 = split('\n',$tab2[1]);
				foreach my $acl2 (@tabacl2){
					my $first_delim2 = index($acl2,'=');
					my $current_role2 = substr($acl2,0,$first_delim2);
					if (!(($role ne '') && ($role ne $current_role2))){
						print "    Column $tab2[0], Role \"$current_role2\" : ".acl2char(substr($acl2,$first_delim2+1,index($acl2,'/')-$first_delim2-1))."\n";
					}
				}
			}
		}
	}
	$req->finish();
}

#------------------------------------------------------------------------------

# Generic function to display ACL on an object kind
# args:
#    $sql	: query that return object name,owner,ACLs
#    $kind	: Kind of object
sub get_acl_prm{
	my($sql,$kind) = @_;

	$req = $db->prepare($sql);
	$req->execute();
	while (@tab = $req->fetchrow_array()){
		print "  $kind $tab[0]\n";
		my @tabacl = split('\n',$tab[2]);
		print "    Default ACL\n    Owner: $tab[1]\n" if($tab[2] eq '');
		foreach my $acl (@tabacl){
			my $first_delim = index($acl,"=");
			my $current_role = substr($acl,0,$first_delim);
			if (!(($role ne '') && ($role ne $current_role))){
				print "    Role \"".($current_role eq ''?"public":$current_role)."\": ".acl2char(substr($acl,$first_delim+1,index($acl,'/')-$first_delim-1));
				print " (owner)" if ($current_role eq $tab[1]);
				print("\n");
			}
		}
	}
	$req->finish();

}

#------------------------------------------------------------------------------

# Transform PostgreSQL's relkind into human readable
sub get_type_obj{
	my ($relkind) = @_;
	return 'Table' if ($relkind eq 'r');
	return 'Index' if ($relkind eq 'i');
	return 'Sequence' if ($relkind eq 'S');
	return 'View' if ($relkind eq 'v');
	return 'Composite type' if ($relkind eq 'c');
	return 'TOAST Table' if ($relkind eq 't');
	return 'Foreign Table' if ($relkind eq 'f');
}

#------------------------------------------------------------------------------

# Transform PostgreSQL's ACL into human readable
sub acl2char{
	my ($acl) = @_;
	return "ALL" if ($acl eq "arwdDxt");
	return "Default" if ($acl eq '');
	my $result = '';
	foreach my $c (split(//,$acl)){
		$result.=',' if ($result ne '');
		$result.="INSERT"	if ($c eq 'a');
		$result.="SELECT"	if ($c eq 'r');
		$result.="UPDATE"	if ($c eq 'w');
		$result.="DELETE"	if ($c eq 'd');
		$result.="TRUNCATE"	if ($c eq 'D');
		$result.="REFERENCES"	if ($c eq 'x');
		$result.="TRIGGER"	if ($c eq 't');

		$result.="USAGE"	if ($c eq 'U');
		$result.="CREATE"	if ($c eq 'C');

		$result.="EXECUTE"	if ($c eq 'X');
	}
	return $result;
}

#------------------------------------------------------------------------------

# Show pg_permissions command line usage
sub usage{
	print qq{
Usage: pg_permissions [options]

	A simple tool to summarize all ACL on a PostgreSQL cluster.

Otions:

	-d | --dbname			: limit result to a single database.
	-h | --host hostname		: host to connect on.
	-H | --help			: show this message and exit.
	-m | --maintenance		: specify maintenance database to use (<= 8.1).
					  Only used without -d.
					  If none specified, postgres will be used.
	-p | --port port_number		: port to connect on.
	-r | --role rolename		: limit result to a single role name.
	-U | --user username		: username to use to connect.
	-V | --version			: show pg_permissions version and exit.

};
	exit 0;
}
