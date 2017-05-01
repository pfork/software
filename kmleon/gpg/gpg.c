#include <unistd.h>
#include <stdlib.h>

// externally invoke the outdated crypto framework
void gpg(char **argv)
{
	char gpg[] = "gpg", gpg2[] = "gpg2";

	argv[0] = gpg2;
	execvp(gpg2, argv);
	argv[0] = gpg;
	execvp(gpg, argv);

	exit(1);
}
