#include <stdint.h>
#include <time.h>

typedef struct
{
  uint64_t bytes_count;
  uint64_t request_count;
  time_t start_time;
  time_t stop_time;
  time_t time_limit; // Time in seconds
  time_t time_passed;
  time_t print_info_interval;
  uint64_t request_limit;
} TestInfo;
