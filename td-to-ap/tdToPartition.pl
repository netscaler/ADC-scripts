# Copyright 2021 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any, 
# which accompany or are included with this software.
#!/usr/bin/perl -w
use strict;
use warnings;

use List::Util qw(first);
use Text::ParseWords;
use Text::Balanced qw(extract_bracketed);
use Cwd 'abs_path';
use Data::Dumper;
use File::Basename;
our $PERL_SINGLE_QUOTE;

# Expect at least three argument from CLI.
if (($#ARGV+1) < 3)
{
	print "Usage: perl tdToPartition.pl <TD-PartName_mapping_file> <input_config_file> <output_config_file>\n";
	exit;
}

# this will validate the string and decides whether to add it to out hash table.

#no tokenizing. only command will be copied.
my $cmds_blind_copy = qr/enable ns feature|enable ns mode/;
#these commands are ignored from copying. add audit messageaction is not supported in partition.
my $cmds_blind_ignore = qr/add audit messageaction|bind system global/;
# copies the command and also will capture its dependents later.
my $cmds_copy_dependents = qr/bind \S+ global|add policy patset/;


sub is_string_valid
{
  my $str = shift(@_);
  
  if ($str eq "")
  {
	#print "$str invalid-1\n";
	return 0;
  }

  if ($str =~ m/[^a-zA-Z0-9\_\#\.\:\-\=\@]/){
	#print "$str invalid-2\n";
	return 0;
  }
  if ( $str =~ /[^0-9]/) 
  {
	;
  }
  else
  {
	#print "$str invalid-3\n";
	return 0;
  }
  if ($str =~m/ENABLED|DISABLED|ON|OFF|^-\S+|UP|DOWN|END|REQUEST|YES/)	
  {
	#print "$str invalid-4\n";
	return 0;
  }
  if( $str=~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)/ && 
	          ( $1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255 ))
			{
			  #print "$str invalid-5\n";
			  return 0;
			}
  return 1;
}


my %token_hash;
my %td_info;
my %partition_info;

open(my $MAPPING, '<', $ARGV[0]) or die "Error: $!";	# Open input mapping file.

while (<$MAPPING>)
{
 my $line = chomp($_);
 if ($line =~m/^#/){
	;#comment only. ignore
  }
  else {
	my ($td, $part, $netprofile) = parse_line('\|', 1, $_);
	$td_info{$td}{"pname"} = $part;
	if (defined $netprofile){
		$td_info{$td}{"partition_netprofile_for_appflow"} = $netprofile;
	}
  }
}
close($MAPPING);

open(my $FOUT, '>', $ARGV[2]) or die "Error: Cannot create file. $!";	# Open output config file.

open(my $FIN, '<', $ARGV[1]) or die "Error: $!";	# Open input config file.
my @lines = <$FIN>;
close($FIN);
foreach my $line (@lines)
{
  chomp($line);
}


my %Cmds_3args=("aaa","","cmp","","subscriber","","ica","","rdp","","responder","","rewrite","","system","","appflow","","cr","","appfw","","appqoe","","cs","","tm","","db","","ipsec","","transform","","audit","","ns","","authentication","","sc","","dns","","tunnel","","authorization","","dos","","autoscale","","lb","","ntp","","ca","","cache","","feo","","vpn","","filter","","smpp","","snmp","","policy","","gslb","","spillover","","wf","","HA","","wi","","pq","","ssl","","lsn","","cluster","","stream","");



my @config_in_partition;

foreach my $td (keys %td_info)
{
  my $pName = $td_info{$td}{"pname"};

  open(my $LOG, '>', "$ARGV[2].$pName.log") or die "Error: Cannot create log file.";	# Open output config file.

  open(my $PartFile, '>', "$ARGV[2].$pName.conf") or die "Error: Cannot create file. $!";	# Create temporary config file for each partition. 

  @config_in_partition = ();
  undef %token_hash;

  my $lines_added = 1;
  my $lookup = "";
  my $token = "";
  my $line_number = 0;
  my $log_str = "";
# Parse input config file.
  while ($lines_added)
  {
	$line_number = 0;
	$lines_added = 0;
	foreach my $line (@lines)
	{
	  if (exists $config_in_partition[$line_number] && ($config_in_partition[$line_number] > 0)){
		;
	  }
	  elsif($line =~ $cmds_blind_ignore) {
		  $config_in_partition[$line_number] = 2; # not related command.
		}
	  elsif ($line =~m/-td\s(\d+)/){
		if ($td != $1) {
		  $config_in_partition[$line_number] = 2; # not related command.
		}else {
		  # we need to add this line to our config.
		  $config_in_partition[$line_number] = 1;
		  $lines_added++;
		  my @words = split(/ /, $line);
			if (scalar(@words) < 4){
		  		$lookup = "";
			}
		  elsif (exists $Cmds_3args{$words[1]}) {
			$lookup = $words[3];
			$log_str = join(" ", @words[0..3]);
			splice(@words, 0, 3);
		  }else {
			$lookup = $words[2];
			$log_str = join(" ", @words[0..2]);
			splice(@words, 0, 2);
		  }
		  if (is_string_valid($lookup)) {
			print $LOG "$log_str <-- Marked for TD $td\n";
			foreach $token (@words){
			  if (is_string_valid($token))
			  {
				$token_hash{$token} = $log_str;
			  }
			}
		  }
		  else {
			print $LOG "$line <-- Marked for TD $td\n";
		  }
		}
	  }
	  elsif ($line =~ $cmds_blind_copy){
		  $config_in_partition[$line_number] = 1;
		  print $LOG "$log_str <-- RE is true  $cmds_blind_copy\n";
	  }
	  elsif ($line =~/bind lb group/)
	  {
		my @words = split(/ /, $line);
		my $group_name = $words[3];
		if (exists($token_hash{$words[4]})){
		  $config_in_partition[$line_number] = 1;
		  $lines_added++;
		  print $LOG "$line <-- Referred by $token_hash{$words[4]}\n";
		  $token_hash{$words[3]} = $line;
		}
	  }
	  else
	  {
		my @words = split(/ /, $line);

		if (scalar(@words) < 4){
		  $lookup = "";
		}
		elsif (exists $Cmds_3args{$words[1]}) {
		  $log_str = join(" ", @words[0..3]);
		  $lookup = $words[3];
		}else {
		  $log_str = join(" ", @words[0..2]);
		  $lookup = $words[2];
		}
		if (is_string_valid($lookup)) {
		  if ((exists $token_hash{$lookup}) or ($line =~ $cmds_copy_dependents))
		  {
			$config_in_partition[$line_number] = 1;
			$lines_added++;
			if (exists $token_hash{$lookup})
			{
			  print $LOG "$log_str <-- $token_hash{$lookup}\n";
			}
			else
			{
			  print $LOG "$log_str <-- RE is true:$cmds_copy_dependents\n";
			}

			if ($line =~ /add ssl certKey .* -cert (\S+).* -key (\S+)/)
			{
			  $partition_info{$pName}{"filesto_copy"}.="$1 $2 ";
			}
			#tokenize and add them to hash bucket for next round of lookup.
			if(exists $Cmds_3args{$words[1]}){
			  splice(@words, 0, 3);
			}
			else {
			  splice(@words, 0, 2);
			}
			foreach $token (@words){
			  if (is_string_valid($token) && (not exists $token_hash{$token}))
			  {
				$token_hash{$token} = $log_str;
			  }
			}
		  }
		}
		else {
		  $config_in_partition[$line_number] = 2; # not related command.
		}
	  }
	  $line_number++;
	}
  }
  # write the config to a file now.
  	$line_number=0;
	foreach my $line (@lines)
	{
	  if (exists $config_in_partition[$line_number]  && $config_in_partition[$line_number]==1)
	  {
		my $cpline = $line;
		$cpline =~s/(-td \d+)//;
		$cpline =~s/-logAction \S+//;
		if ($cpline =~m/add appflow collector/)
		{
		  if (exists $td_info{$td}{"partition_netprofile_for_appflow"}){
			$cpline.=" -netprofile $td_info{$td}{\"partition_netprofile_for_appflow\"}";
		  }
		}
		print $PartFile "$cpline\n";
	  }
	  $line_number++;
	}
	close($PartFile);
	close ($LOG);
}

# finally last config file. we do a clear config create partitions and bind vlans apply config from each partition.
foreach my $key (keys %td_info)
{
  print $FOUT "rm trafficDomain $key\n";
}
foreach my $key (keys %td_info)
{
  print $FOUT "add ns partition $td_info{$key}{\"pname\"}\n";
}
#copy vlan partition bindings.
foreach my $line (@lines)
{
  if ($line =~m/bind ns trafficDomain (\d+) -vlan (\d+)/)
  {
	print $FOUT "bind ns partition $td_info{$1}{\"pname\"} -vlan $2\n";
  }
}

foreach my $part_name (keys %partition_info)
{
  my @files_to_copy= split(" ", $partition_info{$part_name}{"filesto_copy"});
  foreach my $file (@files_to_copy)
  {
	print $FOUT "shell cp /nsconfig/ssl/$file /nsconfig/partitions/$part_name/ssl/\n";
  }
}
#print $FOUT "sync ha files\n";
#print $FOUT "shell sleep 10\n";

foreach my $key (keys %td_info)
{
  print $FOUT "switch partition $td_info{$key}{\"pname\"}\n";
  print $FOUT "batch -filename /var/$ARGV[2].$td_info{$key}{\"pname\"}.conf -outfile /var/$ARGV[2].$td_info{$key}{\"pname\"}.out\n";
  print $FOUT "save config\n";
}

print $FOUT "switch partition DEFAULT\n";
print $FOUT "save config\n";
close($FOUT);
