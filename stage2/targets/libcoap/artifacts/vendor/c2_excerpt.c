/* src/coap_address.c — coap_resolve_address_info() (lines 528-595 approx) */

coap_addr_info_t *
coap_resolve_address_info(const coap_str_const_t *address,
                          uint16_t port,
                          uint16_t secure_port,
                          uint16_t ws_port,
                          uint16_t ws_secure_port,
                          int ai_hints_flags,
                          int scheme_hint_bits,
                          coap_resolve_type_t type) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error;
  coap_addr_info_t *info = NULL;
  coap_addr_info_t *info_prev = NULL;
  coap_addr_info_t *info_list = NULL;
  coap_addr_info_t *info_tmp;
  coap_uri_scheme_t scheme;

  /* ... AF_UNIX handling omitted for brevity ... */

  memset(addrstr, 0, sizeof(addrstr));
  if (address && address->length)
    memcpy(addrstr, address->s, address->length);
  else
    memcpy(addrstr, "localhost", 9);

  memset((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = 0;
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = ai_hints_flags;

  error = getaddrinfo(addrstr, NULL, &hints, &res);
  /* ... remainder uses res to build info_list ... */
}

/* Caller (in coap_proxy.c, inside the proxy forwarding path):
 *
 *   info_list = coap_resolve_address_info(&server_use->uri.host,
 *                                          server_use->uri.port,
 *                                          server_use->uri.port,
 *                                          server_use->uri.port,
 *                                          server_use->uri.port,
 *                                          0,
 *                                          1 << server_use->uri.scheme,
 *                                          COAP_RESOLVE_TYPE_REMOTE);
 *
 * server_use->uri.host comes from coap_split_proxy_uri() which parses
 * the Proxy-Uri option from an incoming CoAP request.  The hostname
 * length is not bounded before reaching coap_resolve_address_info().
 */
