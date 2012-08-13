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
use Getopt::Long;
use IO::File;

$VERSION = '0.1';

# Command line options
my $dbname			= '';
my $host			= '';
my $user			= '';
my $port			= '';
my $outfile			= '';
my $role			= '';

# Others
my $connected			= 0;
my $db				= undef;
my @dblist			= undef;
my @tab				= undef;
my $req				= undef;
my $conninfo			= '';
my $pgversion			= undef;

my $result = GetOptions(
	"h|host=s"		=> \$host,
	"p|port=i"		=> \$port,
	"U|user=s"		=> \$user,
	"o|outfiles=s"		=> \$outfile,
	"r|role=s"		=> \$role,
	"d|dbname=s"		=> \$dbname
);

connect_db();

$pgversion = get_pgversion();

if ($dbname eq ''){
	@dblist = get_db_list();
}else{
	@dblist = ($dbname);
}

get_acl_roles();

my $sql2 = "SELECT '\"' || spcname || '\"', pg_get_userbyid(spcowner),COALESCE(array_to_string(spcacl,E'\\n'),'')"
		." FROM pg_tablespace";
get_acl_prm($sql2,"Tablespace");

$sql2 = "SELECT '\"' || lanname || '\"', pg_get_userbyid(lanowner),COALESCE(array_to_string(lanacl,E'\\n'),'')"
		." FROM pg_language";
get_acl_prm($sql2,"Language");

foreach my $current_db (@dblist){
	get_db_permissions($current_db);
}

print "\n";
disconnect_db();

sub build_conninfo{
	my ($current_db) = @_;
	$conninfo = 'dbi:Pg:';
	$conninfo .= " user=$user" if ($user ne '');
	$conninfo .= " port=$port" if ($port ne '');
	$conninfo .= " host=$host" if ($host ne '');
	if ((! defined $current_db) || ( $current_db eq '')){
		$conninfo .= " dbname=postgres";
	}else{
		$conninfo .= " dbname=$current_db";
	}
}

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

sub disconnect_db{
	if ($connected){
		$db->disconnect();
		$connected = 0;
	}
}

sub get_pgversion{
	$req = $db->prepare("SELECT version();");
	$req->execute();
	@tab = $req->fetchrow_array();
	$req->finish();
	return substr($tab[0],11,3);
}

sub hasmajor{
	my ($wanted_version) = @_;
	return ($pgversion >= $wanted_version);
}
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

sub get_db_permissions{
	my ($current_db) = @_;
	build_conninfo($current_db);
	connect_db(1);
	get_acl_class($current_db);
}

sub get_acl_roles{
	print "Global\n";
	my $sql = "SELECT r.rolname,r.rolsuper,r.rolinherit,r.rolcreaterole,r.rolcreatedb,r.rolcatupdate,"
		."r.rolcanlogin,"
		."ARRAY(SELECT b.rolname"
		."	FROM pg_catalog.pg_auth_members m"
		."	JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)"
		."	WHERE m.member = r.oid) as memberof"
		.(hasmajor(9.0)?",r.rolreplication":"")
		." FROM pg_roles r".($role ne ''?" WHERE r.rolname = '$role'":"");

	$req = $db->prepare($sql);
	$req->execute();
	while(@tab = $req->fetchrow_array()){
		print "  Role $tab[0]:".($tab[1]?" Super":"").($tab[2]?" Inherit":"").($tab[3]?" Create_role":"").($tab[4]?" Create_db":"")
		.($tab[5]?" Catalog_update":"").($tab[6]?" Login":"").((hasmajor(9.0) && ($tab[8]))?" Replication":"")."\n";
		if (@{$tab[7]} > 0){
			print "    Member of : ";
			foreach my $cur (@{$tab[7]}){
				print $cur." ";
			}
			print "\n";
		}
	}
	$req->finish();
}

sub get_acl_class{
	my ($current_db) = @_;
	my $sql;
	print 'database "'.$current_db.'"'."\n";

	$sql = "SELECT '\"' || n.nspname || '\"n',pg_get_userbyid(n.nspowner),COALESCE(array_to_string(n.nspacl,E'\\n'),'')"
		." FROM pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema';";
	get_acl_prm($sql,'Schema');

	$sql  = "SELECT '\"' || n.nspname || '\".\"' || p.proname || '\"',r.rolname,"
		." COALESCE(array_to_string(p.proacl,E'\\n'),'')"
		." FROM pg_proc p"
		." JOIN pg_namespace n ON p.pronamespace = n.oid"
		." JOIN pg_roles r ON p.proowner = r.oid"
		." WHERE n.nspname !~ 'pg_'"
		." AND n.nspname != 'information_schema'"
		." ORDER BY proname;";
	get_acl_prm($sql,'Function');

	$sql  = "SELECT c.relkind,'\"' || n.nspname || '\".\"' || c.relname || '\"',r.rolname ,"
		." COALESCE(array_to_string(c.relacl,E'\\n'),''),c.oid"
		." FROM pg_class c"
		." JOIN pg_namespace n ON c.relnamespace = n.oid"
		." JOIN pg_roles r ON c.relowner = r.oid"
		." WHERE n.nspname !~ 'pg_'"
		." AND n.nspname != 'information_schema'"
		." AND relkind NOT IN ('i')"
		." ORDER BY relkind,relname;";
	$req = $db->prepare($sql);
	$req->execute();
	my $current_obj = '';
	while (@tab = $req->fetchrow_array()){
		if ($tab[1] ne $current_obj){
			print "  ".get_type_obj($tab[0])." $tab[1]\n";
			$current_obj = $tab [1];
		}
		my @tabacl = split('\n',$tab[3]);
		print "    Default\n" if($tab[3] eq '');
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
			my $sql2 = "SELECT '\"' || attname || '\"',COALESCE(array_to_string(attacl,E'\\n'),'')"
				." FROM pg_attribute WHERE attrelid = $tab[4] AND attacl IS NOT NULL;";
			my $req2 = $db->prepare($sql2);
			$req2->execute();
			while(my @tab2 = $req2->fetchrow_array()){
				my @tabacl2 = split('\n',$tab2[1]);
				foreach my $acl2 (@tabacl2){
					my $first_delim2 = index($acl2,'=');
					my $current_role2 = substr($acl2,0,$first_delim2);
					print "    Column $tab2[0], Role \"$current_role2\" : ".acl2char(substr($acl2,$first_delim2+1,index($acl2,'/')-$first_delim2-1))."\n";
				}
			}
		}
	}
	$req->finish();
}

sub get_acl_prm{
	my($sql,$kind) = @_;

	$req = $db->prepare($sql);
	$req->execute();
	while (@tab = $req->fetchrow_array()){
		print "  $kind $tab[0]\n";
		my @tabacl = split('\n',$tab[2]);
		print "    Default\n" if($tab[2] eq '');
		foreach my $acl (@tabacl){
			my $first_delim = index($acl,"=");
			my $current_role = substr($acl,0,$first_delim);
			if (!(($role ne '') && ($role ne $current_role))){
				print "    Role ".($current_role eq ''?"public":$current_role).": ".acl2char(substr($acl,$first_delim+1,index($acl,'/')-$first_delim-1));
				print " (owner)" if ($current_role eq $tab[1]);
				print("\n");
			}
		}
	}
	$req->finish();

}

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


exit;

$db = DBI->connect('dbi:Pg:user=postgres dbname=test') or die('Could not connect to the database');

$req = $db->prepare("SELECT oid,relname,relkind FROM pg_class;");
$req->execute();

while ( @tab = $req->fetchrow_array() ){
	print @tab, "\n";
}

