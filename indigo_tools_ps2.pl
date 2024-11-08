#!/usr/bin/perl
#
#   indigo_tools - a perl script to work with Fahrenheit Remastered
#   PC game files
#
#   TODO
#   -
#   - check console and original versions at some point
#
use strict;
use warnings;
use File::Basename;
use File::Spec;
use Getopt::Long;
use Pod::Usage;

# add current directory to @INC
use FindBin qw($RealBin);
use lib $RealBin;

use Log;

use constant {
    # QUANTICDREAMTABIDMEM
    IDM_SIGNATURE => "\x51\x55\x41\x4E\x54\x49\x43\x44\x52\x45\x41\x4D\x54\x41\x42\x49\x44\x4D\x45\x4D",
};

my $DATA_FILENAME = "BigFile_PC.dat";

sub display_help {
    pod2usage({ -verbose => 2, -exitval => 0 });
}

sub peek {
    my ($file_path, $offset, $n_bytes) = @_;
    open my $fh, '<:raw', $file_path or die "could not open '$file_path': $!";

    seek $fh, $offset // 0, 0 or die "seek failed: $!";

    my $buffer;
    if (defined $n_bytes) {
        read $fh, $buffer, $n_bytes or die "read failed";
    }
    else {
        local $/;
        $buffer = <$fh>;
    }

    close $fh or die "could not close file handle: $!";
    return $buffer;
}

#
# script start
#
print "===========================================================\n"
    . "--- $0 --- Fahrenheit PS2 data tool ----------\n"
    . "===========================================================\n\n";

my $log_level = 1;
GetOptions(
    'log=s' => \$log_level,
    'help'  => \&display_help
) or pod2usage(2);

Log::set_level($log_level);
Log::enable_colors();

# main arg (.idm file)
my ($idm_file) = shift @ARGV;
unless ($idm_file && -f $idm_file) {
    pod2usage(2);
}

if (basename($idm_file) !~ /\.idm|.IDM$/) {
    die "file has unknown extension: '.idm' expected.";
}

# check if dat file exists
my $game_path = dirname $idm_file;
unless (-e File::Spec->catfile($game_path, $_)) {
    die "dat file not found";
}

print "valid dat path\n";

# check index file signature
my $bytes = peek($idm_file, 0, length(IDM_SIGNATURE));
my $signature = unpack('a' . length(IDM_SIGNATURE), $bytes);

unless ($signature eq IDM_SIGNATURE) {
    Log->error("invalid IDM file signature: %s\n", unpack('H*', $bytes));
    die "invalid .idm file.";
}

print "index (IDM) file is valid.\nextracting data... (this may take a while)\n";


#
# !!!: test code
# https://github.com/wattostudios/GameExtractor/blob/master/src/org/watto/ge/plugin/archive/Plugin_DAT_QUANTIC.java
#
my $buffer;
open my $fh, '<:raw', $idm_file or die "could not open IDM file: $!";

# skip IDM signature and read header blocks num
seek $fh, 24, 0;
read $fh, $buffer, 4;

my $header_blocks_num = unpack('V', $buffer);

Log::debug("header blocks: $header_blocks_num");

# figure out the file count
my $current_position = tell $fh;
seek $fh, 0, 2;
my $file_size = tell $fh;

seek $fh, $current_position, 0;

my $files_num = int(($file_size - $current_position - 20) / 16);
Log::debug("number of files: $files_num");

seek $fh, 16 + $header_blocks_num * 12, 1;

read $fh, $buffer, 16 * $files_num;

mkdir "out";

# open data files
my $dat_file = "BigFile.dat";
open my $dat, '<:raw', "$game_path/$dat_file" or die "$!";

# we're at directory now, let's loop through it a bit and read some records
for (my $i = 0; $i < 16 * $files_num; $i += 16) {
    my ($file_id, $data_offset, $data_len, $data_file_id, $unk)
        = unpack("VVVCa3", substr($buffer, $i));

    Log::debug("extracting file with unk %08x\tID %04x at offset %08x...", $unk, $file_id, $data_offset);

    $file_id = sprintf "%X", $file_id;

    seek $dat, $data_offset, 0;
    read $dat, my $extracted_data, $data_len;

    my $out_filepath = "out/$file_id.unk";
    my ($file_sig) = unpack('V', $extracted_data);

    if ($file_sig == 1095909956) {
        $out_filepath = "out/$file_id.dbraw";
    }
    elsif ($file_sig == 1096040772) {
        $out_filepath = "out/$file_id.databank";
    }
    elsif ($file_sig == 1312899652) {
        $out_filepath = "out/$file_id.dbankidx";
    }
    elsif ($file_sig == 1414676816) {
        $out_filepath = "out/$file_id.partition";
    }
    elsif ($file_sig == 1598902083) {
        $out_filepath = "out/$file_id.com_cont";
    }

    open my $fh_out, '>:raw', $out_filepath or die "could not open file for writing: $!";
    print $fh_out $extracted_data;
    close $fh_out;
}


=pod

=head1 NAME

indigo_tools.pl - Fahrenheit Remaster game files tool

=head1 SYNOPSIS

indigo_tools.pl [options] <idm_file>

Options:

    --log=<log_level>   Set log level (default: 1)
    --help              Display this help message

=head1 DESCRIPTION

Lorem ipsum dolor sit amet, consectetur adipiscing elit.
Vivamus at arcu dictum, gravida sapien vel, imperdiet arcu.
Suspendisse sapien odio, accumsan ac ornare ut, aliquet quis augue.
Mauris nisi urna, ultrices vel tellus vitae, vehicula lacinia augue.
Nam sed est non enim suscipit dignissim. Donec eget sem vel risus
euismod luctus vitae nec purus.

=cut
