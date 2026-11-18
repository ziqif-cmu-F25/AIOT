
int mg_http_status(const struct mg_http_message *hm) {
  return atoi(hm->uri.buf);
}

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

static void http_cb(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_READ || ev == MG_EV_CLOSE ||
      (ev == MG_EV_POLL && c->is_accepted && !c->is_draining &&
       c->recv.len > 0)) {  // see #2796
    struct mg_http_message hm;
    size_t ofs = 0;  // Parsing offset
    while (c->is_resp == 0 && ofs < c->recv.len) {
      const char *buf = (char *) c->recv.buf + ofs;
      int n = mg_http_parse(buf, c->recv.len - ofs, &hm);
      struct mg_str *te;  // Transfer - encoding header
      bool is_chunked = false, is_http_1_0 = false;
      size_t old_len = c->recv.len;
      if (n < 0) {
        // We don't use mg_error() here, to avoid closing pipelined requests
        // prematurely, see #2592
        MG_ERROR(("HTTP parse, %lu bytes", c->recv.len));
        c->is_draining = 1;
        mg_hexdump(buf, c->recv.len - ofs > 16 ? 16 : c->recv.len - ofs);
        c->recv.len = 0;
        return;
      }
      if (n == 0) break;                 // Request is not buffered yet
      mg_call(c, MG_EV_HTTP_HDRS, &hm);  // Got all HTTP headers
      if (c->recv.len != old_len) {
        // User manipulated received data. Wash our hands
        MG_DEBUG(("%lu detaching HTTP handler", c->id));
        c->pfn = NULL;
        return;
      }
      if (ev == MG_EV_CLOSE) {  // If client did not set Content-Length
        hm.message.len = c->recv.len - ofs;  // and closes now, deliver MSG
        hm.body.len = hm.message.len - (size_t) (hm.body.buf - hm.message.buf);
      }
      is_http_1_0 =
          hm.proto.len > 8 && mg_ncasecmp(hm.proto.buf, "HTTP/1.0", 8) == 0;
      // HTTP/1.0 does not use "Transfer-Encoding: chunked"
      if (!is_http_1_0 &&
          (te = mg_http_get_header(&hm, "Transfer-Encoding")) != NULL) {
        if (mg_strcasecmp(*te, mg_str("chunked")) == 0) {
          is_chunked = true;
        } else {
          mg_error(c, "Invalid Transfer-Encoding");  // See #2460
          return;
        }
      } else if (mg_http_get_header(&hm, "Content-length") == NULL) {
        // #2593: HTTP packets must contain either Transfer-Encoding or
        // Content-length
        bool is_response = mg_ncasecmp(hm.method.buf, "HTTP/", 5) == 0;
        bool require_content_len = false;
        if (!is_response && (mg_strcasecmp(hm.method, mg_str("POST")) == 0 ||
                             mg_strcasecmp(hm.method, mg_str("PUT")) == 0)) {
          // POST and PUT should include an entity body. Therefore, they should
          // contain a Content-length header (unless the body length is 0, in
          // which case it can be omitted). Other requests can also contain a
          // body, but their content has no defined semantics (RFC 7231)
          if (hm.body.len != 0) require_content_len = true;
          ofs += (size_t) n;  // this request has been processed
        } else if (is_response) {
          // HTTP spec 7.2 Entity body: All other responses must include a body
          // or Content-Length header field defined with a value of 0.
          int status = mg_http_status(&hm);
          require_content_len = status >= 200 && status != 204 && status != 304;
        }
        if (require_content_len) {
          if (!c->is_client) mg_http_reply(c, 411, "", "");
          MG_ERROR(("Content length missing from %s",
                    is_response ? "response" : "request"));
        }
      }

      if (is_chunked) {
        // For chunked data, strip off prefixes and suffixes from chunks
        // and relocate them right after the headers, then report a message
        char *s = (char *) c->recv.buf + ofs + n;
        int o = 0, pl, dl, cl, len = (int) (c->recv.len - ofs - (size_t) n);

        // Find zero-length chunk (the end of the body)
        while ((cl = skip_chunk(s + o, len - o, &pl, &dl)) > 0 && dl) o += cl;
        if (cl == 0) break;  // No zero-len chunk, buffer more data
        if (cl < 0) {
          mg_error(c, "Invalid chunk");
          break;
        }

        // Zero chunk found. Second pass: strip + relocate
        o = 0, hm.body.len = 0, hm.message.len = (size_t) n;
        while ((cl = skip_chunk(s + o, len - o, &pl, &dl)) > 0) {
          memmove(s + hm.body.len, s + o + pl, (size_t) dl);
          o += cl, hm.body.len += (size_t) dl, hm.message.len += (size_t) dl;
          if (dl == 0) break;
        }
        ofs += (size_t) (n + o);
      } else {  // Normal, non-chunked data
        size_t len = c->recv.len - ofs - (size_t) n;
        if (hm.body.len > len) break;  // Buffer more data
        ofs += (size_t) n + hm.body.len;
      }

      if (c->is_accepted) c->is_resp = 1;  // Start generating response
      mg_call(c, MG_EV_HTTP_MSG, &hm);     // User handler can clear is_resp
      if (c->is_accepted && !c->is_resp) {
        struct mg_str *cc = mg_http_get_header(&hm, "Connection");
        if (cc != NULL && mg_strcasecmp(*cc, mg_str("close")) == 0) {
          c->is_draining = 1;  // honor "Connection: close"
          break;
        }
      }
    }
    if (ofs > 0) mg_iobuf_del(&c->recv, 0, ofs);  // Delete processed data
  }
