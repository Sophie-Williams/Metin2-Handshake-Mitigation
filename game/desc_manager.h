	private:
		LPEVENT	m_pkDescManagerGarbageCollector;
		std::unordered_map<std::string, std::tuple<DWORD, int, bool>> m_connection_mapper;
		std::unordered_set<std::string> s_handshake_whitelist;
		
		bool	GetHostHandshake(const struct sockaddr_in & c_rSockAddr);
		int	GetHostConnectionCount(const struct sockaddr_in & c_rSockAddr);
		void	RegisterInstrusiveConnection(const std::string & sHost);
		bool	IsIntrusiveConnection(const std::string & sHost);
		bool	IsOnHandshakeWhitelist(const struct sockaddr_in & c_rSockAddr);

	public:
		void	AddToHandshakeWhiteList(const TPacketHandshakeValidate * pack);
		void	ConnectionCollector();

