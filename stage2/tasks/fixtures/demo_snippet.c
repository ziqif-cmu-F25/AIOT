void handle_header(const char *field, size_t field_len) {
    char buf[64];
    memcpy(buf, field, field_len); /* no bound check against sizeof(buf) */
    process(buf);
}
