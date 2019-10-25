HEADER_GG_HANDSHAKE_VALIDATION = 48,

typedef struct SPacketGGHandshakeValidate
{
	BYTE header;
	char sUserIP[64];
} TPacketGGHandshakeValidate;

