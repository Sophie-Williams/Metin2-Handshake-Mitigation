#include "EventFunctionHandler.hpp"
#include "event.h"

EVENTINFO(desc_manager_garbage_collector_info)
{
};

EVENTFUNC(desc_manager_garbage_collector_event)
{
	DESC_MANAGER::instance().ConnectionCollector();
	return PASSES_PER_SEC(1);
}

bool DESC_MANAGER::GetHostHandshake(const struct sockaddr_in & c_rSockAddr)
{
	for (const auto & rRec : m_map_handshake)
	{
		if (rRec.second->GetHostName() == inet_ntoa(c_rSockAddr.sin_addr))
		{
			if (rRec.second->IsPhase(PHASE_HANDSHAKE))
				return true;
		}
	}

	return false;
}

int DESC_MANAGER::GetHostConnectionCount(const struct sockaddr_in & c_rSockAddr)
{
	int iCount = 0;
	for (const auto & rRec : m_set_pkDesc)
	{
		if (rRec->GetHostName() == inet_ntoa(c_rSockAddr.sin_addr))
			iCount++;
	}

	return iCount;
}

void DESC_MANAGER::RegisterInstrusiveConnection(const std::string & sHost)
{
	static const int MAXIMUM_HANDSHAKE_LIMIT = 3;
	static const DWORD HANDSHAKE_DELAY = 1500;

	auto fIt = m_connection_mapper.find(sHost);
	if (fIt == m_connection_mapper.end())
		fIt = m_connection_mapper.emplace(std::piecewise_construct, std::forward_as_tuple(sHost), std::forward_as_tuple(0, 0, false)).first;

	std::get<1>(fIt->second)++;
	if (std::get<0>(fIt->second) >= get_dword_time())
	{
		if (std::get<1>(fIt->second) >= MAXIMUM_HANDSHAKE_LIMIT)
			std::get<2>(fIt->second) = true;
	}
	else
	{
		std::get<0>(fIt->second) = get_dword_time()+HANDSHAKE_DELAY;
		std::get<1>(fIt->second) = 0;
	}
}

bool DESC_MANAGER::IsIntrusiveConnection(const std::string & sHost)
{
	auto fIt = m_connection_mapper.find(sHost);
	if (fIt == m_connection_mapper.end())
		return false;

	return std::get<2>(fIt->second);
}

void DESC_MANAGER::AddToHandshakeWhiteList(const TPacketHandshakeValidate * pack)
{
	if (g_bAuthServer)
		return;

	s_handshake_whitelist.insert(pack->sUserIP);
}

bool DESC_MANAGER::IsOnHandshakeWhitelist(const struct sockaddr_in & c_rSockAddr)
{
	return (s_handshake_whitelist.find(inet_ntoa(c_rSockAddr.sin_addr)) != s_handshake_whitelist.end());
}

void DESC_MANAGER::ConnectionCollector()
{
	static const DWORD HANDSHAKE_ELAPSE_TIME = 5;

	std::unordered_set<LPDESC> s_garbage;
	for (const auto & rRec : m_map_handshake)
	{
		if (rRec.second->IsPhase(PHASE_HANDSHAKE) && rRec.second->GetCreationTime()+HANDSHAKE_ELAPSE_TIME < get_global_time())
			s_garbage.insert(rRec.second);
	}

	std::for_each(s_garbage.begin(), s_garbage.end(), [this](const LPDESC & rDesc) { DestroyDesc(rDesc, true); });
}

