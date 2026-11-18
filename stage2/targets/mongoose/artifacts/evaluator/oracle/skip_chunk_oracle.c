/* Evaluator-only exact-buffer ASan oracle for skip_chunk CRLF off-by-one.
 * Usage: skip_chunk_oracle <721|722> <body-file>
 * Body file is the HTTP body only (chunk framing), sized exactly.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int is_hex_digit(int c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

/* Simplified numeric decode sufficient for the oracle (hex length field). */
static int decode_hex_len(const char *buf, int i) {
  int n = 0;
  int k;
  for (k = 0; k < i; k++) {
    int v;
    char c = buf[k];
    if (c >= '0' && c <= '9')
      v = c - '0';
    else if (c >= 'a' && c <= 'f')
      v = 10 + c - 'a';
    else if (c >= 'A' && c <= 'F')
      v = 10 + c - 'A';
    else
      return -1;
    n = (n << 4) + v;
  }
  return n;
}

static int skip_chunk_721(const char *buf, int len, int *pl, int *dl) {
  int i = 0, n = 0;
  if (len < 3) return 0;
  while (i < len && is_hex_digit((unsigned char)buf[i])) i++;
  if (i == 0) return -1;
  if (i > (int)sizeof(int) * 2) return -1;
  /* Vulnerable guard (7.21): allows len == i+1 then reads buf[i+1]. */
  if (len < i + 1 || buf[i] != '\r' || buf[i + 1] != '\n') return -1;
  n = decode_hex_len(buf, i);
  if (n < 0) return -1;
  if (n > len - i - 4) return 0;
  if (buf[i + n + 2] != '\r' || buf[i + n + 3] != '\n') return -1;
  *pl = i + 2;
  *dl = n;
  return i + 2 + n + 2;
}

static int skip_chunk_722(const char *buf, int len, int *pl, int *dl) {
  int i = 0, n = 0;
  if (len < 3) return 0;
  while (i < len && is_hex_digit((unsigned char)buf[i])) i++;
  if (i == 0) return -1;
  if (i > (int)sizeof(int) * 2) return -1;
  /* Fixed guard (7.22). */
  if (len < i + 2 || buf[i] != '\r' || buf[i + 1] != '\n') return -1;
  n = decode_hex_len(buf, i);
  if (n < 0) return -1;
  if (n > len - i - 4) return 0;
  if (buf[i + n + 2] != '\r' || buf[i + n + 3] != '\n') return -1;
  *pl = i + 2;
  *dl = n;
  return i + 2 + n + 2;
}

int main(int argc, char **argv) {
  FILE *fp;
  long sz;
  char *buf;
  int which;
  int pl = 0, dl = 0, rc;

  if (argc != 3) {
    fprintf(stderr, "usage: %s <721|722> <body-file>\n", argv[0]);
    return 2;
  }
  which = atoi(argv[1]);
  fp = fopen(argv[2], "rb");
  if (!fp) {
    perror("fopen");
    return 2;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    perror("fseek");
    fclose(fp);
    return 2;
  }
  sz = ftell(fp);
  if (sz < 0) {
    perror("ftell");
    fclose(fp);
    return 2;
  }
  rewind(fp);
  buf = (char *)malloc((size_t)sz);
  if (!buf) {
    fclose(fp);
    return 2;
  }
  if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
    perror("fread");
    free(buf);
    fclose(fp);
    return 2;
  }
  fclose(fp);

  if (which == 721)
    rc = skip_chunk_721(buf, (int)sz, &pl, &dl);
  else
    rc = skip_chunk_722(buf, (int)sz, &pl, &dl);

  printf("rc=%d pl=%d dl=%d len=%ld\n", rc, pl, dl, sz);
  free(buf);
  return 0;
}
