#include "STDHF.h"
#include "Msocket.h"
#include "MnetTools.h"
#include "Mtools.h"
#include <afunix.h>
#ifndef WIN32
#include "signal.h"
#endif
using std::thread;

Msocket::Msocket(MsocketRole role_x, MsocketProtocol protocol_x, bool auto_restart_x, unsigned int clients_num_limit_x)
{
	role = role_x;
	protocol = protocol_x;
	auto_restart = auto_restart_x;
	clients_num_limit = clients_num_limit_x;
	connected_to_server = [=](SOCKET sock) -> int {  mout << mdetail << "[" << oriAddrStr << "]connected_to_server:" << sock << mendl; return 0; };
	accepted_one_connect = [=](SOCKET sock) -> int { mout << mdetail << "[" << oriAddrStr << "]accepted_one_connect:" << sock << mendl; return 0; };
	client_protocol_established = [=](SOCKET sock) -> int { mout << mdetail << "[" << oriAddrStr << "]client_protocol_established:" << sock << mendl; return 0; };
	closed_one_connect = [=](SOCKET sock) -> int { mout << mdetail << "[" << oriAddrStr << "]closed_one_connect:" << sock << mendl; return 0; };
	data_arrived = [=](SOCKET sock, stringstream& data, string extra) -> int {
		mout << mdetail << "[" << oriAddrStr << "]data_arrived:(id:" << sock << ") length:" << Mtools::sslen(data) << "(" << extra << ")" << mendl; return 0;
	};
}

int Msocket::daemon()
{
	while (state != MsocketClosing) {
		if (state == MsocketLost && auto_restart) {
			state = MsocketPreparing;
			Sleep(500 + rand() % 1000);
			init();
			Sleep(500 + rand() % 1000);
		}
		Sleep(100 + rand() % 200);
	}
	return 0;
}

int Msocket::start(string address_port)
{
	if (state != MsocketPreparing) {
		mout << merror << "Msocket不能重复启动(start)!" << mendl;
		return -1;
	}
	int result = address_parse(address_port);
	if (result)
		return result;
	string addrTypes[MsocketAddrTypeEnd] = { "Local","Ipv4","Ipv6" };
	mout << mdetail << "地址[" << addrTypes[addrType] << "]" << ip << ":" << port << mendl;

	init();

	thread daemon_th(&Msocket::daemon, this);
	daemon_th.detach();

	return 0;
}

int Msocket::init()
{
#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	SOCKADDR_UN server_local_addr = { 0 };
	sockaddr_in server_addr = { 0 };
	sockaddr_in6 server_addr6 = { 0 };

	server_local_addr.sun_family = AF_UNIX;
	server_addr.sin_family = AF_INET;
	server_addr6.sin6_family = AF_INET6;
	switch (role) {
	case(MsocketServer):
	{
		mout << "init internet server!" << mendl;
#ifdef _WIN32
		WSADATA  Ws;

		if (WSAStartup(MAKEWORD(2, 2), &Ws) != 0) {
			mout << merror << "Init Windows Socket Failed::" << GetLastError() << mendl;
		}
#endif
		server_socket = socket((addrType == MsocketLocal ? AF_UNIX : (addrType == MsocketIpv6 ? AF_INET6 : AF_INET)),
			SOCK_STREAM, (addrType == MsocketLocal ? 0 : IPPROTO_TCP));
		if (server_socket < 0) {
			mout << merror << "socket:" << Mtools::errstr() << mendl;
			return false;
		}

		if (addrType != MsocketLocal) {
			int sock_op = 1;
			setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&sock_op, sizeof(sock_op));
		}

		int result;
		if (addrType == MsocketLocal) {
			_unlink(ip.c_str());
			strcpy_s(server_local_addr.sun_path, sizeof(server_local_addr.sun_path), ip.c_str());
			result = ::bind(server_socket, (struct sockaddr*)&server_local_addr, sizeof(server_local_addr));
		} else if (addrType == MsocketIpv6) {
			inet_pton(AF_INET6, ip.c_str(), &server_addr6.sin6_addr);
			server_addr6.sin6_port = MnetTools::net_int(port);
			result = ::bind(server_socket, (struct sockaddr*)&server_addr6, sizeof(server_addr6));
		} else {
			inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);
			server_addr.sin_port = MnetTools::net_int(port);
			result = ::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
		}

		if (result != 0) {
			mout << merror << "bind:" << Mtools::errstr() << mendl;
			closesocket(server_socket);
			return false;
		}
		if (listen(server_socket, 0) == -1) {
			mout << merror << "listen:" << Mtools::errstr() << mendl;
			closesocket(server_socket);
			return false;
		}
		thread accept_thread(&Msocket::connect_accept_loop, this);
		accept_thread.detach();
		state = MsocketOK;
		mout << ">Waiting for connect--" << mendl;
		break;
	}
	case(MsocketClient):
	{
		mout << "init Msocket client!" << mendl;
#ifdef _WIN32
		auto tmpwsadata = WSADATA();
		if (WSAStartup(MAKEWORD(2, 2), &tmpwsadata)) {
			mout << merror << "Msocket:WSAStartup():" << gai_strerror(WSAGetLastError()) << mendl;
			return false;
		}
#endif
		server_socket = socket((addrType == MsocketLocal ? AF_UNIX : (addrType == MsocketIpv6 ? AF_INET6 : AF_INET)),
			SOCK_STREAM, (addrType == MsocketLocal ? 0 : IPPROTO_TCP));
		if (server_socket < 0) {
			mout << merror << "socket:" << Mtools::errstr() << mendl;
			return false;
		}

		int result;
		if (addrType == MsocketLocal) {
			//https://devblogs.microsoft.com/commandline/windowswsl-interop-with-af_unix/ !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			strcpy_s(server_local_addr.sun_path, sizeof(server_local_addr.sun_path), ip.c_str());
			result = connect(server_socket, (struct sockaddr*)&server_local_addr, sizeof(server_local_addr));
		} else if (addrType == MsocketIpv6) {
			inet_pton(AF_INET6, ip.c_str(), &server_addr6.sin6_addr);
			server_addr6.sin6_port = MnetTools::net_int(port);
			result = connect(server_socket, (struct sockaddr*)&server_addr6, sizeof(server_addr6));
		} else {
			inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);
			server_addr.sin_port = MnetTools::net_int(port);
			result = connect(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
		}

		if (result == -1) {
			mout << merror << "Msocket[" << oriAddrStr << "]:connect():" << Mtools::errstr() << mendl;
			closesocket(server_socket);
			state = MsocketLost;
			return false;
		} else {
			mout << "connect succeed!" << mendl;
			thread recv_thread(&Msocket::data_recv_loop, this, server_socket);
			recv_thread.detach();
			state = MsocketOK;
			connected_to_server((int)server_socket);
		}
		break;
	}
	default:
		mout << merror << "Msocket[" << oriAddrStr << "]:" << "unkown role,it should be MsocketClient or MsocketServer!" << mendl;
		return false;
		break;
	}
	return true;
}

int Msocket::address_parse(string address_port)
{
	oriAddrStr = address_port;
	mout << mdebug << "原始地址:" << address_port << mendl;
	regex reg_auto("^(auto):(\\d+)");
	regex reg_local("^(local):(.*)");
	regex reg_domain("^(.*?):(\\d+)");
	smatch match;
	if (regex_match(address_port, match, reg_auto)) {
		mout << mdebug << "识别为自动选择本机ip:" << match[0] << mendl;
		auto re = MnetTools::get_local_ips();
		if (re.size() == 0) {
			mout << merror << "本机ip获取失败！" << mendl;
			return 4;
		}
		for (auto s : re)
			mout << mdebug << "获得ip：" << s << mendl;
		ip = re[0];
		addrType = (ip.find(":") == string::npos) ? MsocketIpv4 : MsocketIpv6;
		stringstream ss(match[2]);
		ss >> port;
	} else if (regex_match(address_port, match, reg_local)) {
		mout << mdebug << "识别为local:" << match[0] << mendl;
		ip = match[2];
		addrType = MsocketLocal;
	} else if (regex_match(address_port, match, MnetTools::reg_ipv4)) {
		mout << mdebug << "识别为ipv4:" << match[0] << mendl;
		ip = match[1];
		stringstream ss(match[2]);
		ss >> port;
		addrType = MsocketIpv4;
	} else if (regex_match(address_port, match, MnetTools::reg_ipv6)) {
		mout << mdebug << "识别为ipv6:" << match[0] << mendl;
		ip = match[1];
		stringstream ss(match[2]);
		ss >> port;
		addrType = MsocketIpv6;
	} else if (regex_match(address_port, match, reg_domain)) {
		mout << mdebug << "识别为域名:" << match[0] << mendl;
		string domain = match[1];
		auto ipv = MnetTools::get_ip_by_domain_name(domain);
		if (ipv.size() == 0) {
			mout << mwarning << "DNS解析失败！  domain: " << domain << mendl;
			return 2;
		}
		for (auto s : ipv)
			mout << mdebug << "获得ip：" << s << mendl;
		ip = ipv[0];
		addrType = (ip.find(":") == string::npos) ? MsocketIpv4 : MsocketIpv6;
		stringstream ss(match[2]);
		ss >> port;
	} else {
		mout << merror << "无法识别的地址！  address_port:" << address_port << mendl;
		return 1;
	}
	return 0;
}

void Msocket::connect_accept_loop()
{
	sockaddr_un connect_local_addr;
	sockaddr_in connect_addr;
	sockaddr_in6 connect_addr6;
#ifdef _WIN32
	int tem_local_len = sizeof(sockaddr_un);
	int tem_len = sizeof(sockaddr_in);
	int tem_len6 = sizeof(sockaddr_in6);
#else
	socklen_t tem_local_len = sizeof(sockaddr_un);
	socklen_t tem_len = sizeof(sockaddr_in);
	socklen_t tem_len6 = sizeof(sockaddr_in6);
#endif
	while (state == MsocketOK || state == MsocketPreparing) {
		Sleep(1);
		while (clients.size() >= clients_num_limit) {
			Sleep(10);
		}

		SOCKET connect_socket = accept(server_socket,
			(addrType == MsocketLocal ? (struct sockaddr*)&connect_local_addr : (addrType == MsocketIpv6 ? (struct sockaddr*)&connect_addr6 : (struct sockaddr*)&connect_addr)),
			(addrType == MsocketLocal ? &tem_local_len : (addrType == MsocketIpv6 ? &tem_len6 : &tem_len)));

		if (connect_socket == -1) {
			mout << merror << "Msocket[" << oriAddrStr << "]:accept():" << Mtools::errstr() << mendl;
			continue;
		}
#ifdef _WIN32
		int timeout = 10;
		if (setsockopt(connect_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)(&timeout), sizeof(timeout)) != 0) {
			mout << merror << "Msocket[" << oriAddrStr << "]:setsockopt()-connect opt set failed! :" << Mtools::errstr() << mendl;
			closesocket(connect_socket);
			continue;
		}
#endif
		char buff[256];
		inet_ntop((addrType == MsocketLocal ? AF_UNIX : (addrType == MsocketIpv6 ? AF_INET6 : AF_INET)),
			(addrType == MsocketLocal ? (void*)connect_local_addr.sun_path : (addrType == MsocketIpv6 ? (void*)&connect_addr6.sin6_addr : (void*)&connect_addr.sin_addr)),
			buff, 256);
		string tem_s = buff;
		mout << "Msocket[" << oriAddrStr << "]:" << tem_s + " connected!" << mendl;

		MsocketClientData client;
		client.socket_id = connect_socket;
		client.connect_time = time(nullptr);
		client.protocol_ok = ((protocol == MsocketTCP || protocol == MsocketPack) ? true : false);
		clients_lock.lock();
		clients[connect_socket] = client;
		clients_lock.unlock();

		thread recv_thread(&Msocket::data_recv_loop, this, connect_socket);
		recv_thread.detach();

		accepted_one_connect((int)connect_socket);
	}
	closesocket(server_socket);
}

int Msocket::close(SOCKET sock)
{
	if (sock != 0)
		closesocket(sock);
	else
		state = MsocketClosing;
	return 0;
}

void Msocket::data_recv_loop(const SOCKET my_connect)
{
	char* recv_buff = new char[recv_buffer_size];
	char* head_buff = new char[257];
	char* data_buff = new char[max_data_len + 1];
	stringstream recvss;
	stringstream data_ss;
	int len1 = -1;
	int len2 = -1;
	websocket_head wshead;
	while (state != MsocketClosing) {
		int get_n = recv(my_connect, recv_buff, recv_buffer_size, 0);
		if (get_n <= 0)
			break;

		recvss.write(recv_buff, get_n);
		switch (protocol) {
		case MsocketTCP:
		{
			data_arrived(my_connect, recvss, "");
			recvss.clear();
			recvss.str("");
		}
		break;
		case MsocketPack:
		case MsocketPackPW:
		{
		MSocketPackBegin:if (len1 == -1) {
			recvss.read((char*)&len1, sizeof(int));
			len1 = MnetTools::net_int(len1);
		}

		size_t all_len = Mtools::sslen(recvss);
		int gn = (int)recvss.tellg();
		if (int(all_len - gn) >= len1) {
			unsigned char head_len = 0;
			recvss.read((char*)&head_len, sizeof(unsigned char));
			recvss.read(head_buff, head_len);
			head_buff[head_len] = '\0';

			len2 = len1 - head_len - sizeof(unsigned char);
			if (len2 >= 0 && len2 <= (int)max_data_len) {
				recvss.read(data_buff, len2);
				data_ss.write(data_buff, len2);
				data_arrived(my_connect, data_ss, head_buff);
			} else {
				mout << merror << "invalid packet,total:" << len1 << ",head:" << head_len << mendl;
			}

			len1 = -1;
			data_ss.clear();
			data_ss.str("");

			gn = (int)recvss.tellg();
			if ((int)all_len == gn)//缓冲区已处理完
			{
				recvss.clear();
				recvss.str("");
			} else//缓冲区仍有数据
				goto MSocketPackBegin;
		}
		}
		break;
		case MsocketWebsocket:
		{
			if (clients[my_connect].protocol_ok) {
			websocketparsebegin:stringstream rstr;
				string tmps = recvss.str();

				long long ret = MnetTools::wsDecodeFrame(tmps, rstr, wshead);
				if (ret >= 0) {
					data_ss.write(rstr.str().data(), Mtools::sslen(rstr));
					if (wshead.got_pack) {
						data_arrived(my_connect, data_ss, "");
						data_ss.clear();
						data_ss.str("");
					}

					if (ret < (long long)tmps.length()) {
						mout << mdebug << "websocket:TCP数据粘包(" << ret << "/" << tmps.length() << ")!" << mendl;
						stringstream tmpss;
						tmpss.write(recvss.str().data() + ret, Mtools::sslen(recvss) - ret);
						recvss.clear();
						recvss.str("");
						recvss.swap(tmpss);
						goto websocketparsebegin;
					} else {
						recvss.clear();
						recvss.str("");
					}

				} else if (ret == -1) {
					mout << merror << "websocket:数据格式解析错误！" << mendl;
					recvss.clear();
					recvss.str("");
				} else if (ret == -WS_CLOSING_FRAME) {
					mout << mdetail << "websocket:客户端关闭连接！:" << my_connect << mendl;
					closesocket(my_connect);
					break;
				}
			} else {
				auto it = recvss.str().find("\r\n\r\n");
				if (it != string::npos) {
					string tmpstr = recvss.str();
					size_t iti = tmpstr.find("Sec-WebSocket-Key:");
					if (iti != string::npos) {
						iti = iti + 19;
						size_t it2 = tmpstr.find("\r", iti);
						string websocketKey = tmpstr.substr(iti, it2 - iti);

						mout << mdetail << "接收到websocket-KEY:【" << websocketKey << "】" << mendl;

						string response = "HTTP/1.1 101 Switching Protocols\r\n";
						response += "Upgrade: websocket\r\n";
						response += "Connection: Upgrade\r\n";
						response += "Sec-WebSocket-Accept: ";

						const std::string magicKey("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
						std::string serverKey = websocketKey + magicKey;

						string tmp_sha_str = MnetTools::sha1(serverKey);
						response += MnetTools::base64_encode(tmp_sha_str) + "\r\n\r\n";
						mout << mdetail << "websocket-回复:【" << response << "】" << mendl;
						send(response, my_connect, "", true);
					} else {
						mout << merror << "websocket:请求头解析错误!未找到Sec-WebSocket-Key！" << mendl;
						closesocket(my_connect);
						break;
					}
					if (it == Mtools::sslen(recvss) - 4) {
						recvss.clear();
						recvss.str("");
					} else {
						string tmpleft = recvss.str().substr(it + 4);
						recvss.clear();
						recvss.str(tmpleft);
					}
					client_protocol_established(my_connect);
					clients[my_connect].protocol_ok = true;
				} else {
					mout << mwarning << "websocket:请求头解析失败!" << mendl;
				}
			}
		}
		break;
		default:
			mout << merror << "recv-未知协议类型！" << mendl;
			break;
		}
	}
	delete[] recv_buff;
	delete[] head_buff;
	delete[] data_buff;
	closesocket(my_connect);
	mout << mdetail << "connect lost!@" << my_connect << mendl;
	closed_one_connect(my_connect);

	if (role == MsocketServer) {
		clients_lock.lock();
		clients.erase(my_connect);
		clients_lock.unlock();
	} else if (state != MsocketClosing)
		state = MsocketLost;
}

bool Msocket::send(stringstream& data_ss, SOCKET dest, string extra, bool use_raw_TCP_tempory)
{
	if (state == MsocketOK) {
		if (dest == 0) {
			if (role == MsocketClient)
				dest = server_socket;
			else if (clients.size() == 1) {
				dest = clients.begin()->first;
			} else {
				mout << mwarning << "send:未指定发送目标" << mendl;
				return false;
			}
		} else if (dest == broadcast_socket) {
			if (role != MsocketServer) {
				mout << mwarning << "Msocket[" << oriAddrStr << "]-send:广播socket只能由服务端使用！" << mendl;
				return false;
			}
			for (auto it : clients) {
				if (it.first != 0 && it.first != broadcast_socket)
					send(data_ss, it.first, extra);
			}
			return true;
		}
		if (role == MsocketServer && use_raw_TCP_tempory == false && (clients[dest].protocol_ok == false)) {
			mout << mwarning << "Msocket[" << oriAddrStr << "]-send:客户端协议尚未建立！" << mendl;
			return false;
		}

		stringstream final_ss;
		auto protocol_l = (use_raw_TCP_tempory ? MsocketTCP : protocol);
		switch (protocol_l) {
		case MsocketTCP:
			final_ss.swap(data_ss);
			break;
		case MsocketPackPW:
		case MsocketPack:
		{
			unsigned char head_len = (unsigned char)extra.length();
			int datalen = (int)Mtools::sslen(data_ss);
			int dlen = (int)extra.length() + datalen + (int)sizeof(unsigned char);
			dlen = MnetTools::net_int(dlen);
			final_ss.write((char*)&dlen, sizeof(int));
			final_ss.write((char*)&head_len, sizeof(unsigned char));
			final_ss.write(extra.data(), head_len);
			final_ss.write(data_ss.str().data(), datalen);
		}
		break;
		case MsocketWebsocket:
		{
			string result;
			string tmp = data_ss.str();
			MnetTools::wsEncodeFrame(tmp, result, WS_TEXT_FRAME);
			final_ss.str(result);
		}
		break;
		default:
			final_ss.swap(data_ss);
			break;
		}
		int len = (int)Mtools::sslen(final_ss);
		int bytes = ::send(dest, final_ss.str().data(), len, 0);
		if (bytes != len) {
			mout << merror << "send:(" << bytes << "/" << len << ")" << Mtools::errstr() << mendl;
			closesocket(dest);
			return false;
		}
		return true;
	} else {
		static int ernum = 0;
		if (ernum % 30 == 0) {
			mout << mwarning << "send:socket is not connectd!" << mendl;
		}
		ernum++;
		return false;
	}
	return false;
}

bool Msocket::send(string data, SOCKET dest, string extra, bool use_raw_TCP_tempory)
{
	stringstream ss(data);
	return send(ss, dest, extra, use_raw_TCP_tempory);
}

bool Msocket::send(string data, string extra, bool use_raw_TCP_tempory)
{
	stringstream ss(data);
	return send(ss, 0, extra, use_raw_TCP_tempory);
}

bool Msocket::send(stringstream& data_ss, string extra, bool use_raw_TCP_tempory)
{
	return send(data_ss, 0, extra, use_raw_TCP_tempory);
}

Msocket::~Msocket() {}
