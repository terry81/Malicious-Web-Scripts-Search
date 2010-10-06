#!/usr/bin/perl
# A simple recursive find and replace tool
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

#If used escape these characters . * ? + [ ] ( ) { } ^ $ | \ ;
#The 's' RE modifier makes it work on more than one line by default.

use strict;
use warnings;
use File::Find;
use Cwd;

my $changefrom = 'code to be replaced\n'; #always leave \n at the end to avoid blank lines being left
my $changeto = ''; #usually empty unless you want to place something
my $extensions = '.php';
my $path = cwd; #usually the current working directory

#do not change anything below this line

sub matchPattern {

    my $file = $File::Find::name;

    if ($file =~ /$extensions/) {
        open INPUT, '<', $file or warn;
        my @input_array=<INPUT>;
        close(INPUT);
        my $file_code=join("",@input_array);
        $file_code =~ s#$changefrom#$changeto#sg;
        open OUTPUT, '>', $file or warn;
        print(OUTPUT $file_code);
        close(OUTPUT);
    }

}

find (\&matchPattern, $path);