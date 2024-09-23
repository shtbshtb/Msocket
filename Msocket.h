#pragma once
#include "STDHF.h"
#include <functional>
#include <regex>
#include <mutex>
#include "MnetTools.h"

using std::string;
using std::stringstream;
using std::cout;
using std::cerr;
using std::endl;
using std::map;
using std::regex;
using std::smatch;
using std::sregex_iterator;
using std::sregex_token_iterator;

enum MsocketRole { MsocketClient, MsocketServer };
enum MsocketProtocol { MsocketTCP, MsocketPack, MsocketPackPW, MsocketWebsocket };
enum MsocketStatus { MsocketPreparing, MsocketOK, MsocketLost, MsocketClosing, MsocketRestarting };
enum MsocketAddrType { MsocketLocal, MsocketIpv4, MsocketIpv6, MsocketAddrTypeEnd };

#ifndef _WIN32
typedef int SOCKET;
#define Sleep(x) usleep((x)*1000)
#define closesocket(x) shutdown(x, SHUT_WR)
#endif

struct MsocketClientData
{
	bool protocol_ok = false;
	SOCKET socket_id;
	time_t connect_time;
	unsigned long long data_received = 0;
	unsigned long long data_sent = 0;
	string remark;
};


class MsocketOp
{
public:
	MsocketOp(int type_x) { type = type_x; }
	inline bool operator == (const MsocketOp& op) const { return op.type == type; }
	~MsocketOp() {};
private:
	int type;
};

class Msocket
{
public:
	Msocket(MsocketRole role_x, MsocketProtocol protocol_x, bool auto_restart = false, unsigned int clients_num_limit = 1);
	Msocket(const Msocket& ori) = delete;
	~Msocket();

	//回调函数
	std::function<int(SOCKET sock)> connected_to_server;//client
	std::function<int(SOCKET sock)> accepted_one_connect;//server
	std::function<int(SOCKET sock)> client_protocol_established;//server
	std::function<int(SOCKET sock)> closed_one_connect;//client,server
	std::function<int(SOCKET sock, stringstream& data, string extra)> data_arrived;//client,server

	//参数示例: "local:conn1" "127.0.0.1:81" "[::1]:81" "www.baidu.com:81"
	int start(std::string address_port);
	bool send(stringstream& data_ss, SOCKET dest = 0, string extra = "", bool use_raw_TCP_tempory = false);
	bool send(stringstream& data_ss, string extra = "", bool use_raw_TCP_tempory = false);
	bool send(string data_ss, SOCKET dest = 0, string extra = "", bool use_raw_TCP_tempory = false);
	bool send(string data_ss, string extra = "", bool use_raw_TCP_tempory = false);
	int close(SOCKET sock = 0);

	void setMaxDataLen(uint32 len) { max_data_len = len; }
	uint32 getConnCnt() { return (role == MsocketClient) ? (state == MsocketOK ? 1 : 0) : (uint32)clients.size(); }

	const static SOCKET broadcast_socket = 0xFFFFFFFF;
private:
	bool auto_restart;
	string oriAddrStr;
	string ip;
	unsigned short port;
	MsocketRole role;
	MsocketProtocol protocol;
	MsocketStatus state = MsocketPreparing;

	SOCKET server_socket;//作为客户端时是连接到服务器的socket，作为服务器时是自身socket
	const static int recv_buffer_size = 4 * 1024 * 1024;//接收缓冲区大小
	uint32 max_data_len = 16 * 1024 * 1024;

	unsigned int clients_num_limit = 1;
	map<SOCKET, MsocketClientData>clients;
	std::mutex clients_lock;//clients锁

	int daemon();
	int address_parse(string address);
	int init();
	void connect_accept_loop();
	void data_recv_loop(const SOCKET my_connect);
	MsocketAddrType addrType = MsocketIpv4;
};

