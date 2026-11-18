static bool is_hex_digit(int c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

static int skip_chunk(const char *buf, int len, int *pl, int *dl) {
  int i = 0, n = 0;
  if (len < 3) return 0;
  while (i < len && is_hex_digit(buf[i])) i++;
  if (i == 0) return -1;                     // Error, no length specified
  if (i > (int) sizeof(int) * 2) return -1;  // Chunk length is too big
  if (len < i + 1 || buf[i] != '\r' || buf[i + 1] != '\n') return -1;  // Error
  if (mg_str_to_num(mg_str_n(buf, (size_t) i), 16, &n, sizeof(int)) == false)
    return -1;                    // Decode chunk length, overflow
  if (n < 0) return -1;           // Error. TODO(): some checks now redundant
  if (n > len - i - 4) return 0;  // Chunk not yet fully buffered
  if (buf[i + n + 2] != '\r' || buf[i + n + 3] != '\n') return -1;  // Error
  *pl = i + 2, *dl = n;
  return i + 2 + n + 2;
}

// Caller (inside http_cb, after detecting Transfer-Encoding: chunked):
//   char *s = (char *) c->recv.buf + ofs + n;
//   int o = 0, pl, dl, cl, len = (int) (c->recv.len - ofs - (size_t) n);
//   while ((cl = skip_chunk(s + o, len - o, &pl, &dl)) > 0 && dl) o += cl;
