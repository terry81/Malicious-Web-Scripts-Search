#!/usr/bin/perl
# Version 2.1 Beta Sept 29 2010

# Copyright (C) 2010 Anatoliy Dimitrov, website-security.info

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

use warnings;
use strict;

use Cwd;
use File::Find;
use File::stat;

my $path = cwd;

my $count;

my %bad_files;

my @bad_dirs;

my %suspicious_files_pattern = (
'(Copyright)+?' => -1, #usually exploits don't have copyrights
'(shellbot|c99shell|bot_list|______)' => 100, #the easiest
'(fread\(fopen\(\$file|eval\(gzinflate\(base64_decode|file_get_contents\(base64_decode\(|eval\(gzinflate\(base64|eval\(base64)'     => 100,
'<\?php.*(urldecode|\$[a-z]{1}=@)' => 100, #one-line hacks
'if \(\$_SERVER\[\'REMOTE_ADDR' => 90, #why would someone wonder what is the remote server IP
'\$_(POST|GET)\[\'(cwd|port|exe|cmd)'                       => 50,
'(/etc/passwd|rand\(1,65000\)|netstat)'                        => 50, #why would anyone use that in regular script
);

my $suspicious_dirname_patterns = 'webscrcmd|\.\.\.|__|\s\s'; #paypal scam and others suspicious

my $suspicious_htaccess_patterns = 'HTTP_REFERER.*google'; # why would someone redirect google traffic

#$/ = ''; #bugs the re sometimes but is much faster

sub matchPattern {
    my $file = $File::Find::name;

    my $dir = $File::Find::dir;

    if ( $dir =~ /$suspicious_dirname_patterns|\s\s/i ) {
        push(@bad_dirs, $dir) unless grep( /$dir/, @bad_dirs );
    }

    if ( $file =~ m"\.htaccess$" ) {

        open INPUT, '<', $file or warn "Unable to open file: $file!\n";

        while (my $row = <INPUT>) {

            if ( $row =~ /$suspicious_htaccess_patterns/ ) {
                $bad_files{ $file } = 100;
                last;
            }
        }
        close(INPUT);
    }


    if ( $file =~ m"\.php$" ) {

        #protection against too big files

        my $filesize = stat($file)->size;

        if ($filesize > 200000) {
            return;
        }

        #it is important that each time it begins from 0
        my $probability = 0;

        open INPUT, '<', $file or warn "Unable to open file: $file!\n";

        while (my $row = <INPUT>) {

            while ( ( my $key, my $value ) = each(%suspicious_files_pattern) ) {
                if ( $row =~ m/$key/ ) {
                    $probability += $value;

                    if ($probability < 0 ) {
                        #this means we have caught something that is usually not found in exploits
                        return;
                    } elsif ( $probability > 99 ) {
                        $bad_files{ $file } = $probability;
                        #print  $file." ".$key."\n"; #debug
                        return;
                    }
                }
            }

        }

        close(INPUT);

    }

    print "! Status update: $count files processed\n" if (!( ++$count % 5000 ));    #show some progress for each 1000 files processed

}

find( \&matchPattern, $path );


if ((keys %bad_files) || @bad_dirs) {

    my $key;
    print "\n Results in descending order:\n";

    foreach $key (sort { $bad_files {$b} <=> $bad_files {$a}} keys %bad_files) {
        print "- $key\t$bad_files{$key}\n";
    }
    foreach (@bad_dirs) {
        print "- $_ - suspicious dir name \n";
    }
} else {
print "Nothing suspicious found.\n";
}

my $run_time = time() - $^T;

print "\n\nIt took $run_time seconds.\n";

# Remove the file so that we don't forget it somewhere :)
unlink $0 or warn "Please, remove file manually.";


