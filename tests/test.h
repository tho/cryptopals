#ifndef CRYPTOPALS_TEST_H
#define CRYPTOPALS_TEST_H

#include <stdio.h>
#include <stdlib.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Same as assert() but use exit() instead of abort() to terminate. */
#define ASSERT(e) ((void)((e) ? ((void)0) : ASSERT_(#e, __FILE__, __LINE__)))
#define ASSERT_(e, file, line)                                          \
	((void)printf("%s:%d: failed assertion `%s'\n", file, line, e), \
	 exit(EXIT_FAILURE))

#endif /* CRYPTOPALS_TEST_H */
