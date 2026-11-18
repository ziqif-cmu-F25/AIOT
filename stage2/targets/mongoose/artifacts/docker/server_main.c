/* Minimal HTTP file server for the personal Stage 2 lab.
 * Built against a pinned Mongoose revision; no TLS.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mongoose.h"

static int s_signo;
static int s_debug_level = MG_LL_INFO;
static const char *s_root_dir = "/var/www";
static const char *s_listening_addr = "http://0.0.0.0:8000";

static void signal_handler(int signo) { s_signo = signo; }

static void cb(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *)ev_data;
    struct mg_http_serve_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.root_dir = s_root_dir;
    mg_http_serve_dir(c, hm, &opts);
  }
  (void)c;
}

int main(int argc, char *argv[]) {
  struct mg_mgr mgr;
  struct mg_connection *c;
  int i;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
      s_root_dir = argv[++i];
    } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
      s_listening_addr = argv[++i];
    } else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
      s_debug_level = atoi(argv[++i]);
    }
  }

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  mg_log_set(s_debug_level);
  mg_mgr_init(&mgr);
  c = mg_http_listen(&mgr, s_listening_addr, cb, NULL);
  if (c == NULL) {
    fprintf(stderr, "Cannot listen on %s\n", s_listening_addr);
    return 1;
  }
  fprintf(stderr, "Listening on %s root=%s\n", s_listening_addr, s_root_dir);
  while (s_signo == 0) mg_mgr_poll(&mgr, 500);
  mg_mgr_free(&mgr);
  return 0;
}
