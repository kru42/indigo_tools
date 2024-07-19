#!/usr/bin/perl
use strict;
use warnings;

# Check if the input file is provided
if (@ARGV != 1) {
    die "Usage: $0 <input_file>\n";
}

my $input_file = $ARGV[0];

# Open the input file for reading
open(my $fh, '<', $input_file) or die
    "Could not open file '$input_file': $!";

# Process each line in the file
while (my $line = readline $fh) {
    chomp $line;

    # Use the c++filt tool to demangle the symbol name
    my $demangled = `echo $line | c++filt`;
    chomp $demangled;

    # Print the original and demangled names
    print "Original: $line\n";
    print "Demangled: $demangled\n";
    print "\n";
}

# Close the file handle
close($fh);
