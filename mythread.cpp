#include "mythread.h"
#include <QDebug>
pcap_t* pcap_handle;   //libpcap句柄
char error_content[PCAP_ERRBUF_SIZE];
  char *net_interface;     //网络接口
bpf_u_int32 net_mask; //子网掩码
   bpf_u_int32 net_ip;
  const u_char* data;

  QString mythread::SrcMAC = "";
  QString mythread::DesMAC = "";
  QString mythread::Ptotocoltype = "";
  QString mythread::Length = "";
mythread::mythread(){

}
