package Log;
use strict;
use warnings;
use Term::ANSIColor;

use constant {
    INFO  => 1,
    WARN  => 2,
    ERROR => 3,
    DEBUG => 4,
};

# Default log level
my $log_level = INFO;

my $colors_on = 0;

sub set_level {
    my ($level) = @_;
    $log_level = $level if $level >= INFO && $level <= DEBUG;
}

sub enable_colors {
    $colors_on = 1;
}

sub disable_colors {
    $colors_on = 0;
}

sub log_message {
    my ($level, $format, @args) = @_;
    my $prefix = '';

    # Get current time
    my ($sec, $min, $hour) = localtime();
    my $timestamp = sprintf("[%02d:%02d:%02d]", $hour, $min, $sec);

    if ($level == INFO) {
        $prefix = "[" . $colors_on ? colored([ 'cyan' ], 'info') : 'info' . "]";
    }
    elsif ($level == WARN) {
        $prefix = "[" . $colors_on ? colored([ 'yellow' ], 'warn') : 'warn' . "]";
    }
    elsif ($level == ERROR) {
        $prefix = "[" . $colors_on ? colored([ 'red' ], 'error') : 'error' . "]";
    }
    elsif ($level == DEBUG) {
        $prefix = "[" . ($colors_on ? colored([ 'cyan' ], 'debug') : 'debug') . "]";
    }

    printf STDERR "$prefix$timestamp $format\n", @args;
}

sub info {
    my ($format, @args) = @_;
    log_message(INFO, $format, @args) if $log_level >= INFO;
}

sub warn {
    my ($format, @args) = @_;
    log_message(WARN, $format, @args) if $log_level >= WARN;
}

sub error {
    my ($format, @args) = @_;
    log_message(ERROR, $format, @args) if $log_level >= ERROR;
}

sub debug {
    my ($format, @args) = @_;
    log_message(DEBUG, $format, @args) if $log_level >= DEBUG;
}

1;