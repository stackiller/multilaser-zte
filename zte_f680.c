#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <stdbool.h>

#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <poll.h>

#define Null NULL
#define MSG_MX_SIZE 2000000 // max response body size: 2MB
#define PTR_ARRAY_SIZE(array) (sizeof(array) / 8)

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

char *REQ_WIFI_NAME =
"GET /getpage.gch?pid=1002&nextpage=net_wlanm_secrity1_t.gch HTTP/1.1\n"
"Host: %s\n"
"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0\n"
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\n"
"Accept-Language: en-US,en;q=0.5\n"
"Accept-Encoding: gzip, deflate\n"
"Connection: keep-alive\n"
"Referer: http://%s/getpage.gch?pid=1002&nextpage=net_wlanm_essid1_t.gch\n"
"Cookie: _TESTCOOKIESUPPORT=1; SID=%s\n"
"Upgrade-Insecure-Requests: 1\n"
"Connection: close\n"
"\n";

char* Send_request(char*, char *);

/* Get substring ? wtf xD */
char*
subStr(char *str1, char *str2) {
  return strstr(str1, str2);
}

/* Split a string by ch1 to ch2 */
char*
split(char *str, char ch1, char ch2)
{
  int i, j = 0;
  char *splited = (char*) calloc(1024,1);

  for(i=1; i < strlen(str); i++)
  {
    if(str[i-1] == ch1)
    {
      while(str[i] != ch2)
      {
        splited[j] = str[i];
        i++; j++;
      }
      return splited;
    }
  }

  free(splited);
  return Null;
}

/* Get validation token of form */
char*
Get_formLoginToken(char *msg) {
  char *token, *token2;

  if((token = strstr(msg, "Frm_Loginchecktoken")) == Null) {
    return Null;
  }
  
  token = split(token, ',' , ')');
  token2 = split(token, '"' , '"');
  
  free(token);

  return token2;
}

/* Get login token */ 
char*
Get_loginToken(char *msg) {
  char *token, *token2;

  if((token = strstr(msg, "Frm_Logintoken")) == Null) {
    return Null;
  }

  token = split(token, ',' , ')'); // erro
  token2 = split(token, '"' , '"');

  free(token);

  return token2;
}

/* Obtém o SID */
char*
Get_SID(char *msg) {
  char *token = strstr(msg, "Set-Cookie: SID");

  if((token = strstr(msg, "Set-Cookie: SID")) == Null) {
    return Null;
  }

  char *token2 = split(token, '=', ';');

  return token2;
}

/* Get wireless name */
char*
Get_WifiName(char *host, char *sid) {
  char _req[1024];

  sprintf(_req, REQ_WIFI_NAME, host, host, sid);

  char *resp = Send_request(host, _req);

  char *token = strstr(resp, "Transfer_meaning('ESSID',");
  token = strstr(token, "Transfer_meaning('ACLPolicy','')");
  token = strstr(token, "Transfer_meaning('ESSID',");
  token = strchr(token, ',');

  token = split(token, 39, 39);

  free(resp);

  return token;
}

char*
Send_request(char *host, char *msg) {
  int rc, bytes;

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in dest;

  dest.sin_family = AF_INET;
  dest.sin_port = htons(80);
  dest.sin_addr.s_addr = inet_addr(host);

  rc = connect(sockfd, (struct sockaddr*)&dest, sizeof(dest));

  if (rc < 0) {
    perror("Send_request: connect fail.\n");
    return 0;
  }

  rc = send(sockfd, msg, 1024, 0);

  if (rc < 0) {
    perror("Send_request: send fail.\n");
    return Null;
  }

  char *buffer_lines = (char*) calloc(500, 1);
  char *buffer = (char*) calloc(MSG_MX_SIZE, 1);

  while((bytes = recv(sockfd, buffer_lines, 500, 0)) > 0) {
    strcat(buffer, buffer_lines);
    memset(buffer_lines, 0x0, 500);
  };

  close(sockfd);

  free(buffer_lines);

  return buffer;
}

/* get info of host */
int
run(char* host)
{
  char *buffer, *sid, *wname;
  char request[3][1024];

  for(int i=0; i < 3; i++) {
    memset(request[i], 0x0, 1024);
  }

  sprintf(request[1], REQ_LOGIN, host, host, host);

  /* Send login request */
  buffer = Send_request(host, request[1]);

  if(buffer == Null) {
    printf("run: buffer Null\n");
    return 0;
  }

  char *tokens[] = {
    Get_loginToken(buffer),
    Get_formLoginToken(buffer),
  };

  if(tokens[0] == Null || tokens[1] == Null) {
    return 0;
  }

  sprintf(request[2], REQ_LOGIN_BODY, tokens[0], tokens[1]);

  strcat(request[0], request[1]);
  strcat(request[0], request[2]);

  free(buffer);

  buffer = Send_request(host, request[0]);

  if(buffer == Null) {
    printf("run: buffer is Null\n");
    return 0;
  }

  /* Get SID */
  sid = Get_SID(buffer);

  if(sid == Null) {
    return 0;
  }

  wname = Get_WifiName(host, sid);
  
  printf("HOST: %s\n", host);
  printf("WIFI: %s\n\n", wname);    

  free(buffer); free(sid); free(wname);
  free(tokens[0]); free(tokens[1]);

  return 0;
}


int
main(int argc, char **argv)
{
  if(argc < 3 || argc > 3) {
    printf(
      "run:\n%s <host> -<flags>\n\n"
      "flags:\n"
      "S ( = set  ) : use this flag if you want to read the flgas (except M) as definitions and not as getters.\n"
      "M ( = mac  ) : get router mac address.\n"
      "N ( = name ) : wireless name.\n"
      "P ( = pass ) : wireless password.\n"
      ,argv[0]
    );
    return 0;
  }

  run(argv[2]);
}