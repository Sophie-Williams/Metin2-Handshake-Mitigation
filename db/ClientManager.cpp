void CClientManager::HandshakeValidatePacket(const TPacketHandshakeValidate * data)
{
	TPacketHandshakeValidate ret_pack;
	memcpy(&ret_pack, data, sizeof(ret_pack));

	ForwardPacket(HEADER_DG_HANDSHAKE_VALIDATE_PACKET, &ret_pack, sizeof(ret_pack));
}

