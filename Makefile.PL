use 5.012002;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME          => 'Net::SSH::LibSSH',
    VERSION_FROM  => 'lib/Net/SSH/LibSSH.pm',
    ABSTRACT_FROM => 'lib/Net/SSH/LibSSH.pm',
    AUTHOR        => 'Matthias Pitzl <pitzl@genua.de>',
    LIBS          => [
	'-L../libopenssh/ssh/lib/ -lssh -lcrypto -lz -lgssapi -lkrb5'
    ],
    INC           => '-I../libopenssh/ssh/ -I.',
    CCFLAGS      => '-Wall',
);
