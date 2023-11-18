#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* CRC8 Computation */

const static uint8_t crc8_table[] = {
    0,   29,  58,  39,  116, 105, 78,  83,  232, 245, 210, 207, 156, 129, 166, 187, 205, 208, 247, 234, 185, 164,
    131, 158, 37,  56,  31,  2,   81,  76,  107, 118, 135, 154, 189, 160, 243, 238, 201, 212, 111, 114, 85,  72,
    27,  6,   33,  60,  74,  87,  112, 109, 62,  35,  4,   25,  162, 191, 152, 133, 214, 203, 236, 241, 19,  14,
    41,  52,  103, 122, 93,  64,  251, 230, 193, 220, 143, 146, 181, 168, 222, 195, 228, 249, 170, 183, 144, 141,
    54,  43,  12,  17,  66,  95,  120, 101, 148, 137, 174, 179, 224, 253, 218, 199, 124, 97,  70,  91,  8,   21,
    50,  47,  89,  68,  99,  126, 45,  48,  23,  10,  177, 172, 139, 150, 197, 216, 255, 226, 38,  59,  28,  1,
    82,  79,  104, 117, 206, 211, 244, 233, 186, 167, 128, 157, 235, 246, 209, 204, 159, 130, 165, 184, 3,   30,
    57,  36,  119, 106, 77,  80,  161, 188, 155, 134, 213, 200, 239, 242, 73,  84,  115, 110, 61,  32,  7,   26,
    108, 113, 86,  75,  24,  5,   34,  63,  132, 153, 190, 163, 240, 237, 202, 215, 53,  40,  15,  18,  65,  92,
    123, 102, 221, 192, 231, 250, 169, 180, 147, 142, 248, 229, 194, 223, 140, 145, 182, 171, 16,  13,  42,  55,
    100, 121, 94,  67,  178, 175, 136, 149, 198, 219, 252, 225, 90,  71,  96,  125, 46,  51,  20,  9,   127, 98,
    69,  88,  11,  22,  49,  44,  151, 138, 173, 176, 227, 254, 217, 196};

uint8_t
compute_crc8(const uint8_t *data, size_t size)
{
    uint8_t crc = 0;
    for (size_t i = 0; i < size; ++i) {
        uint8_t curr = data[i] ^ crc;
        crc = crc8_table[curr];
    }
    return crc;
}

/* Unpadded URL base64 encoding/decoding */

const char B64U_LOOKUP[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

enum Base64Constants
{
    B64U_MASK = 0x3F,
    B64U_UPPERCASE_OFFSET = 0,
    B64U_LOWERCASE_OFFSET = 26,
    B64U_DIGIT_OFFSET = 52,
    B64U_HYPHEN_OFFSET = 62,
    B64U_UNDERSCORE_OFFSET = 63,
    B64U_CLUSTER_BYTES = 3,
    B64U_CLUSTER_CHARS = 4,
};

char
b64u_single_encode(uint8_t x)
{
    x &= B64U_MASK;
    return B64U_LOOKUP[x];
}

uint16_t
b64u_single_decode(char x)
{
    if ('A' <= x && x <= 'Z') {
        return x - 'A' + B64U_UPPERCASE_OFFSET;
    }
    if ('a' <= x && x <= 'z') {
        return x - 'a' + B64U_LOWERCASE_OFFSET;
    }
    if ('0' <= x && x <= '9') {
        return x - '0' + B64U_DIGIT_OFFSET;
    }
    if (x == '-') {
        return B64U_HYPHEN_OFFSET;
    }
    if (x == '_') {
        return B64U_UNDERSCORE_OFFSET;
    }
    return -1;
}

char *
b64u_encode(const uint8_t *data, size_t size)
{
    if (data == NULL) {
        return NULL;
    }
    size_t size_ans = (size / B64U_CLUSTER_BYTES) * B64U_CLUSTER_CHARS;
    if (size % B64U_CLUSTER_BYTES != 0) {
        size_ans += size % B64U_CLUSTER_BYTES + 1;
    }
    char *str = calloc(size_ans + 1, sizeof(char));
    if (str == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < size / B64U_CLUSTER_BYTES; ++i) {
        size_t di = i * B64U_CLUSTER_BYTES;
        size_t ci = i * B64U_CLUSTER_CHARS;
        str[ci] = b64u_single_encode(data[di] >> 2);
        str[ci + 1] = b64u_single_encode(data[di] << 4 | data[di + 1] >> 4);
        str[ci + 2] = b64u_single_encode(data[di + 1] << 2 | data[di + 2] >> 6);
        str[ci + 3] = b64u_single_encode(data[di + 2]);
    }
    if (size % B64U_CLUSTER_BYTES == 2) {
        size_t di = size - 2;
        size_t ci = size_ans - 3;
        str[ci] = b64u_single_encode(data[di] >> 2);
        str[ci + 1] = b64u_single_encode(data[di] << 4 | data[di + 1] >> 4);
        str[ci + 2] = b64u_single_encode(data[di + 1] << 2);
    } else if (size % B64U_CLUSTER_BYTES == 1) {
        size_t di = size - 1;
        size_t ci = size_ans - 2;
        str[ci] = b64u_single_encode(data[di] >> 2);
        str[ci + 1] = b64u_single_encode(data[di] << 4);
    }
    str[size_ans] = '\0';
    return str;
}

bool
b64u_decode(const char *str, uint8_t **p_data, size_t *p_size)
{
    if (str == NULL || p_data == NULL || p_size == NULL) {
        return false;
    }
    size_t char_cnt = 0;
    for (size_t i = 0; str[i] != '\0'; ++i) {
        if (!isspace(str[i])) {
            if (b64u_single_decode(str[i]) == (uint16_t) -1) {
                return false;
            }
            ++char_cnt;
        }
    }
    size_t leftover = char_cnt % B64U_CLUSTER_CHARS;
    if (leftover == 1) {
        return false;
    }
    size_t size = (char_cnt / B64U_CLUSTER_CHARS) * B64U_CLUSTER_BYTES;
    if (leftover > 0) {
        size += leftover - 1;
    }
    uint8_t *data = calloc(size + 1, sizeof(*data));
    *p_data = data;
    *p_size = size;
    if (data == NULL) {
        return false;
    }
    data[size] = 0;
    size_t ci = 0;
    uint8_t cluster[B64U_CLUSTER_CHARS] = {};
    for (size_t i = 0; i < char_cnt / B64U_CLUSTER_CHARS; ++i) {
        size_t di = i * B64U_CLUSTER_BYTES;
        for (size_t j = 0; j < B64U_CLUSTER_CHARS; ++j) {
            while (isspace(str[ci])) {
                ++ci;
            }
            cluster[j] = b64u_single_decode(str[ci]);
            ++ci;
        }
        data[di] = cluster[0] << 2 | cluster[1] >> 4;
        data[di + 1] = cluster[1] << 4 | cluster[2] >> 2;
        data[di + 2] = cluster[2] << 6 | cluster[3];
    }
    for (size_t j = 0; j < leftover; ++j) {
        while (isspace(str[ci])) {
            ++ci;
        }
        cluster[j] = b64u_single_decode(str[ci]);
        ++ci;
    }
    if (leftover == 3) {
        data[size - 2] = cluster[0] << 2 | cluster[1] >> 4;
        data[size - 1] = cluster[1] << 4 | cluster[2] >> 2;
    } else if (leftover == 2) {
        data[size - 1] = cluster[0] << 2 | cluster[1] >> 4;
    }
    return true;
}

/* ULEB128 encoding/decoding */

enum ULEB128Constants
{
    ULEB128_VAL_BITS = 64,
    ULEB128_CHUNK_BITS = 7,
    ULEB128_MSB = 0x80,
    ULEB128_CHUNK_MASK = 0x7F
};

struct ReadContext
{
    uint8_t *buf;
    size_t size;
    size_t pos;
    uint64_t value_u64;
};

size_t
uleb128_len(uint64_t value)
{
    if (value == 0) {
        return 1;
    }
    size_t bits = ULEB128_VAL_BITS - __builtin_clzll(value);
    size_t ans = bits / ULEB128_CHUNK_BITS;
    if (bits % ULEB128_CHUNK_BITS != 0) {
        ++ans;
    }
    return ans;
}

uint8_t *
uleb128_encode(uint8_t *ptr, uint64_t value)
{
    if (value == 0) {
        *ptr = 0;
        return ptr + 1;
    }
    while (value != 0) {
        ptr[0] = value & ULEB128_CHUNK_MASK;
        ptr[0] |= ULEB128_MSB;
        ++ptr;
        value >>= ULEB128_CHUNK_BITS;
    }
    ptr[-1] ^= ULEB128_MSB;
    return ptr;
}

bool
uleb128_decode(struct ReadContext *cntx)
{
    uint64_t ans = 0;
    bool last_byte = false;
    uint64_t shift = 0;
    size_t pos = cntx->pos;
    for (; !last_byte; ++pos, shift += ULEB128_CHUNK_BITS) {
        if (pos >= cntx->size) {
            return false;
        }
        uint8_t curr = cntx->buf[pos];
        if ((curr & ULEB128_MSB) == 0) {
            last_byte = true;
        }
        curr &= ULEB128_CHUNK_MASK;
        if (shift + ULEB128_CHUNK_BITS > ULEB128_VAL_BITS &&
            !(shift + 1 <= ULEB128_VAL_BITS && (curr == 0 || curr == 1))) {
            return false;
        }
        if (last_byte && shift != 0 && curr == 0) {
            return false;
        }
        ans |= (uint64_t) curr << shift;
    }
    cntx->pos = pos;
    cntx->value_u64 = ans;
    return true;
}

enum Devices
{
    SMART_HUB = 0x01,
    ENV_SENSOR = 0x02,
    SWITCH = 0x03,
    LAMP = 0x04,
    SOCKET = 0x05,
    CLOCK = 0x06
};

enum Commands
{
    WHOISHERE = 0x01,
    IAMHERE = 0x02,
    GETSTATUS = 0x03,
    STATUS = 0x04,
    SETSTATUS = 0x05,
    TICK = 0x06
};

typedef uint16_t addr_t;
typedef uint64_t val_t;

typedef struct
{
    size_t len;
    uint8_t *str;
} string;

struct Trigger
{
    uint8_t op;
    val_t value;
    string name;
};

struct EnvSensorProps
{
    uint8_t sensors;
    size_t triggers_len;
    struct Trigger *triggers;
};

struct SwitchProps
{
    size_t devices_len;
    string *devices;
};

struct DeviceCmdBody
{
    string dev_name;
    union
    {
        struct EnvSensorProps env_props;
        struct SwitchProps switch_props;
    };
};

struct TimerCmdBody
{
    val_t timestamp;
};

struct EnvSensorStatusCmdBody
{
    size_t values_len;
    val_t *values;
};

struct Payload
{
    addr_t src;
    addr_t dst;
    val_t serial;
    enum Devices dev_type;
    enum Commands cmd;
    union
    {
        struct DeviceCmdBody dev_cmd_body;
        struct TimerCmdBody timer_cmd_body;
        struct EnvSensorStatusCmdBody env_status_cmd_body;
        bool switch_status_cmd_body;
    };
};

struct Packet
{
    uint8_t length;
    struct Payload payload;
    uint8_t crc8;
    uint8_t *raw_data;
};

void
free_packet(const struct Packet *p)
{
    switch (p->payload.cmd) {
    case WHOISHERE:
    case IAMHERE:
        free(p->payload.dev_cmd_body.dev_name.str);
        switch (p->payload.dev_type) {
        case ENV_SENSOR:
            for (size_t i = 0; i < p->payload.dev_cmd_body.env_props.triggers_len; ++i) {
                free(p->payload.dev_cmd_body.env_props.triggers[i].name.str);
            }
            free(p->payload.dev_cmd_body.env_props.triggers);
            break;
        case SWITCH:
            for (size_t i = 0; i < p->payload.dev_cmd_body.switch_props.devices_len; ++i) {
                free(p->payload.dev_cmd_body.switch_props.devices[i].str);
            }
            free(p->payload.dev_cmd_body.switch_props.devices);
            break;
        default:
            break;
        }
        break;
    case STATUS:
    case SETSTATUS:
        if (p->payload.dev_type == ENV_SENSOR) {
            free(p->payload.env_status_cmd_body.values);
        }
        break;
    default:
        break;
    }
}

bool
decode_packet(const char *str, struct Packet *p)
{
    uint8_t *p_data = NULL;
    size_t p_size = 0;
    if (!b64u_decode(str, &p_data, &p_size)) {
        return false;
    }
    p->raw_data = p_data;
    p->length = p_data[0];
    ++p_data;
    p->crc8 = p_data[p->length];
    if (p->crc8 != compute_crc8(p_data, p->length)) {
        return false;
    }
    struct ReadContext ctx = {.buf = p_data, .size = p->length, .pos = 0, .value_u64 = 0};
    if (!uleb128_decode(&ctx)) {
        return false;
    }
    p->payload.src = ctx.value_u64;
    if (!uleb128_decode(&ctx)) {
        return false;
    }
    p->payload.dst = ctx.value_u64;
    if (!uleb128_decode(&ctx)) {
        return false;
    }
    p->payload.serial = ctx.value_u64;
    p->payload.dev_type = ctx.buf[ctx.pos++];
    p->payload.cmd = ctx.buf[ctx.pos++];
    switch (p->payload.cmd) {
    case WHOISHERE:
    case IAMHERE:
        p->payload.dev_cmd_body.dev_name.len = ctx.buf[ctx.pos++];
        p->payload.dev_cmd_body.dev_name.str = ctx.buf + ctx.pos;
        ctx.pos += p->payload.dev_cmd_body.dev_name.len;
        switch (p->payload.dev_type) {
        case ENV_SENSOR:
            p->payload.dev_cmd_body.env_props.sensors = ctx.buf[ctx.pos++];
            uint8_t t_len = ctx.buf[ctx.pos++];
            p->payload.dev_cmd_body.env_props.triggers_len = t_len;
            p->payload.dev_cmd_body.env_props.triggers =
                calloc(t_len, sizeof(p->payload.dev_cmd_body.env_props.triggers[0]));
            for (size_t i = 0; i < t_len; ++i) {
                p->payload.dev_cmd_body.env_props.triggers[i].op = ctx.buf[ctx.pos++];
                if (!uleb128_decode(&ctx)) {
                    return false;
                }
                p->payload.dev_cmd_body.env_props.triggers[i].value = ctx.value_u64;
                p->payload.dev_cmd_body.env_props.triggers[i].name.len = ctx.buf[ctx.pos++];
                p->payload.dev_cmd_body.env_props.triggers[i].name.str = ctx.buf + ctx.pos;
                ctx.pos += p->payload.dev_cmd_body.env_props.triggers[i].name.len;
            }
            break;
        case SWITCH:

        }
    }
    return true;
}

int
main(int argc, char *argv[])
{
}
