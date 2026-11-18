# HTTP notes for analysts (public)

Approved references for this lab:

- RFC 9112 — HTTP/1.1 messaging (request line, headers, chunked transfer coding)
- Chunked body shape: `chunk-size CRLF chunk-data CRLF` … ending with `0 CRLF CRLF`
- `chunk-size` is one or more HEXDIG characters
- Incomplete or malformed framing may produce connection close, error replies, or no reply

Lab endpoint: `http://target:8000/`  
Tools: `http_client.py send|replay` under `/opt/lab/tools`.

Do not consult evaluator materials or unpublished PoCs during measured runs.
