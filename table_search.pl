#!/usr/bin/perl
use strict;
use warnings;
use File::Find;
use Compress::Zlib;

# Directory to search
my $directory = shift || '.';

my $zlib_gzip_signature_regex = qr/(?:\x{78}\x{01}|\x{78}\x{9C}|\x{78}\x{DA}|\x{1F}\x{8B})/;

# Subroutine to process each file
sub process_file {
    return unless -f; # Only process files
    open my $fh, '<:raw', $_ or warn "Cannot open '$_': $!" and return;
    binmode $fh;
    local $/;
    my $content = <$fh>;
    close $fh;

    my $offset = 0;
    if ($content =~ /TBOFFSET/g) {
        if (defined pos($content)) {
            $offset = pos($content) - length('TBOFFSET');
            print "Found TBOFFSET in file: $File::Find::name at offset: $offset\n";

            if ($content =~ /$zlib_gzip_signature_regex/g) {
                if (defined pos($content)) {
                    $offset = pos($content) - length($zlib_gzip_signature_regex);
                    print "and also matched for zlib regex at offset $offset\n";

                    my $decompressed_data = Compress::Zlib::memGunzip(substr($content, $offset));

                    my $output_file = "$File::Find::name.decompressed";
                    print $output_file . "\n";
                    open my $out_fh, '>:raw', $output_file or die "$!";
                    print $out_fh $decompressed_data;
                    close $out_fh;

                    print "decompressed data written to: $output_file\n";
                }
            }
        }
        else {
            print "Warning: pos(\$content) is undefined for file: $File::Find::name\n";
        }
        #$offset = pos($content) - length('TBOFFSET');
        #print "Found 'TBOFFSET' in file: $File::Find::name at offset: $offset\n";
    }
}

# Search directory
find(\&process_file, $directory);