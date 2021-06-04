#include "util.h"

void create_message(char *message, int length)
{
  int i = 0;
  while (i < length)
  {
    message[i] = '0' + (i % 10);
    i++;
  }

  message[length - 1] = '\n';
}