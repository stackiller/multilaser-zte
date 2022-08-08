#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <stdbool.h>

#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <poll.h>

#define H_len 20
#define Null NULL
#define MSG_MX_SIZE 4000000 // max response body size: 2MB

char *REQ_LOGIN =
"POST / HTTP/1.1\n"
"Host: %s\n"
"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\n"
"Accept-Language: en-US,en;q=0.5\n"
"Accept-Encoding: gzip, deflate\n"
"Content-Type: application/x-www-form-urlencoded\n"
"Content-Length: 181\n"
"Origin: http://%s\n"
"Connection: keep-alive\n"
"Referer: http://%s/\n"
"Cookie: _TESTCOOKIESUPPORT=1\n"
"Upgrade-Insecure-Requests: 1\n\n";

char *REQ_LOGIN_BODY = "action=login&Username=user&Password=1f95048350c43ce7679cc079965a4b1583bce2b8ee9cf6b11f62b3f2e4e382dd&Frm_Logintoken=%s&UserRandomNum=43956951&Frm_Loginchecktoken=%s\n";

char *REQ_GET =
"GET /%s HTTP/1.1\n"
"Host: %s\n"
"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\n"
"Accept-Language: en-US,en;q=0.5\n"
"Accept-Encoding: gzip, deflate\n"
"Connection: keep-alive\n"
"Referer: http://%s/%s\n"
"Cookie: _TESTCOOKIESUPPORT=1; SID=%s\n"
"Upgrade-Insecure-Requests: 1\n"
"Connection: close\n\n";

char *REQ_WIFI_NAME = "getpage.gch?pid=1002&nextpage=net_wlanm_secrity1_t.gch";
char *REQ_MAC = "getpage.gch?pid=1002&nextpage=IPv46_status_wan2_if_t.gch";

/* Var declarations */
struct sockaddr_in dest;

char flags[]  = { 'M', 'N' };
int c_flags[] = {  0,   0  };

/* Prototypes  */
int run(char*);
int set_Addr(char*);

void free_bylist(void**);
void memset_bylist(void**, int**);

char* Split(char*, char, char);

char* Get_loginToken(char*);
char* Get_formLoginToken(char*);

char* Get_SID(char*);
char* Get_Wifiname(char*, char*);
char* Get_Mac(char*, char*);
char* Get_Pass(char*, char*);

char* Send_request(char *);
char* Login_request(char*);

void usage(char*);

/* Get info */
int
run(char* addr) {
  int rc;
  char *buffer, *SID;

  if ((rc = set_Addr(addr)) < 0) {
    printf("run: fail on create socket.\n");
    return -1;
  }

  /* login request */
  buffer = Login_request(addr);

  if(buffer == Null) {
    printf("run: buffer is Null.\n");
    return 0;
  }

  /* get SID */
  SID = Get_SID(buffer);

  printf("SID: %s\n", SID);

  char *free_list[] = { buffer, SID, Null };

  if(SID == Null) {
    free_bylist((void*) free_list);
    return 0;
  }

  if (c_flags[1] == 1)
    printf("Wifi: %s\n", Get_Wifiname(addr, SID));

  if (c_flags[0] == 1)
    printf("Mac: %s\n", Get_Mac(addr, SID));

  free_bylist((void*) free_list);

  return 0;
}

/* Set sockaddr_in struct datas */ 
int
set_Addr(char *host) {
  dest.sin_family = AF_INET;
  dest.sin_port = htons(80);

  if ((dest.sin_addr.s_addr = inet_addr(host)) == -1) {
    perror("Send_request: invalid host.");
    return -1;
  }

  return 0;
}

/* Release memory of each ptrs item */
void
free_bylist(void **ptrs) {
  int i=0;
  do {
    free(ptrs[i]);
    i++;
  } while(ptrs[i] != Null);
}

/* Memset through the elements of ptrs list */
void
memset_bylist(void **ptrs, int **sizes)
{
  int i = 0;
  do {
    memset(ptrs[i], 0x0, *sizes[i]);
    i++;
  } while(ptrs[i] != Null);
}

/* Split a string by ch1 to ch2 */
char*
Split(char *str, char ch1, char ch2)
{
  int i, j = 0;
  char *Splited = (char*) calloc(1024,1);

  for (i=1; i < strlen(str); i++)
  {
    if (str[i-1] == ch1)
    {
      while (str[i] != ch2)
      {
        Splited[j] = str[i];
        i++; j++;
      }
      return Splited;
    }
  }

  free(Splited);
  return Null;
}

/* Get validation token of form */
char*
Get_formLoginToken(char *msg)
{
  char *token, *token2;

  if((token = strstr(msg, "Frm_Loginchecktoken")) == Null)
    return Null;
  
  token = Split(token, ',' , ')');
  token2 = Split(token, '"' , '"');
  
  free(token);

  return token2;
}

/* Get login token */ 
char*
Get_loginToken(char *msg)
{
  char *token, *token2;

  if((token = strstr(msg, "Frm_Logintoken")) == Null)
    return Null;

  token = Split(token, ',' , ')');
  token2 = Split(token, '"' , '"');

  free(token);

  return token2;
}

/* Get SID */
char*
Get_SID(char *msg)
{
  char *token = strstr(msg, "Set-Cookie: SID");

  if((token = strstr(msg, "Set-Cookie: SID")) == Null)
    return Null;

  char *token2 = Split(token, '=', ';');

  return token2;
}

/* Get wireless name */
char*
Get_Wifiname(char *addr, char *SID)
{
  char _req[1024];

  memset(_req, 0x0, 1024);
  sprintf(_req, REQ_GET, REQ_WIFI_NAME, addr, addr, REQ_WIFI_NAME, SID);
  
  char *resp = Send_request(_req);

  if (resp == Null) return Null;

  char *token = strstr(resp, "Transfer_meaning('ESSID',");
  token = strstr(token, "Transfer_meaning('ACLPolicy','')");
  token = strstr(token, "Transfer_meaning('ESSID',");
  token = strchr(token, ',');

  token = Split(token, 39, 39);

  free(resp);

  return token;
}

/* Get mac address */
char*
Get_Mac(char *addr, char *SID)
{
  char _req[1024];

  memset(_req, 0x0, 1024);
  sprintf(_req, REQ_GET, REQ_MAC, addr, addr, "start.ghtml", SID);
  
  char *resp = Send_request(_req);

  if (resp == Null) return Null;

  char *token = strstr(resp, "TextPPPWorkIFMac1");
  token = strstr(token, "value");
  token = Split(token, '=', 32);

  free(resp);

  return token;
}

/* Send requests */
char*
Send_request(char *msg) {
  int rc, bytes, sockfd;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd == -1) {
    perror("Send_request: fail to create socket.\n");
    return Null;
  }

  rc = connect(sockfd, (struct sockaddr*)&dest, sizeof(dest));

  if (rc == -1) {
    perror("Send_request: connect fail.\n");
    return Null;
  }

  rc = send(sockfd, msg, MSG_MX_SIZE, 0);

  if (rc <= 0) {
    perror("Send_request: send fail.\n");
    return Null;
  }

  char *buffer_lines = (char*) calloc(100, 1);
  char *buffer = (char*) calloc(MSG_MX_SIZE, 1);

  while((bytes = recv(sockfd, buffer_lines, 100, 0)) > 0) {
    strncat(buffer, buffer_lines, bytes);
    memset(buffer_lines, 0x0, 100);
  }

  free(buffer_lines);

  return buffer;
}

/* Make login request */
char*
Login_request(char *addr) {
  char *buffer, request[3][1024];

  for(int i=0; i < 3; i++)
    memset(request[i], 0x0, 1024);

  sprintf(request[1], REQ_LOGIN, addr, addr, addr);

  buffer = Send_request(request[1]);

  if (buffer == Null) return Null;

  char *tokens[] = {
    Get_loginToken(buffer),
    Get_formLoginToken(buffer),
  };

  if (tokens[0] == Null) {
    free(buffer);
    return Null;
  }

  sprintf(request[2], REQ_LOGIN_BODY, tokens[0], tokens[1]);

  strcat(request[0], request[1]);
  strcat(request[0], request[2]);

  free(buffer);

  buffer = Send_request(request[0]);

  if(buffer == Null) return Null;

  return buffer;
}

/* Usage */
void
usage(char *binary) {
  printf(
    "run:\n%s <host> -<flags>\n\n"
    "( getters ) flags:\n"
    "M : router mac address.\n"
    "N : wireless name.\n"
    , binary
  );
}

void
Get_flags(char *s_flags) {
  for (int i=0; i < 3; i++)
  {
    for (int j=0; j < 3; j++)
    {
      if (s_flags[i] == flags[j])
      {  
        if (s_flags[i] == 'M' )
          c_flags[0] = 1;

        if (s_flags[i] == 'N' )
          c_flags[1] = 1;

        if (s_flags[i] == 'P' )
          c_flags[2] = 1;
      }
    }
  }
}

/*

['M', 'N', 'P']
['M', 'N', 'O']

*/

int
main(int argc, char **argv) {
  if (argc < 3 || argc > 3 || strlen(argv[2]) > 3 ) {
    usage(argv[0]);
    return 0;
  }

  Get_flags(argv[2]);

  run(argv[1]);
}