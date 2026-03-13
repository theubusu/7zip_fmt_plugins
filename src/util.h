#include <cstdio>

#ifdef DEBUG

extern FILE* g_logF;

#  define DBG_LOG(...) \
      do { \
          g_logF = fopen("C:\\Users\\tomek\\dev\\Projects\\fmt7z\\bin\\run.log", "a"); \
          fprintf(g_logF, __VA_ARGS__); \
          fclose(g_logF); \
      } while (false)

#else

#  define DBG_LOG(...)

#endif