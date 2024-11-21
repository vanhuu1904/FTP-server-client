#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>

#define BUFFER_LEN 300

char *CMD_LIST = "LIST";   // list directory
char *CMD_PASV = "PASV\n"; // enter in pasive mode
char *CMD_QUIT = "QUIT\n";
char *CMD_RETR = "RETR"; // retrieve file
char *CMD_CWD = "CWD";   // change working directory
char *CMD_STOR = "STOR"; // storing file
char *FILE_NOT_FOUND = "550";

char *substr(const char *src, int m, int n)
{
    int len = n - m;

    char *dest = (char *)malloc(sizeof(char) * (len + 1));

    for (int i = m; i < n && (*(src + i) != '\0'); i++)
    {
        *dest = *(src + i);
        dest++;
    }

    *dest = '\0';

    return dest - len;
}

struct hostent *server;

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int linearSearch(char arr[], int len, char ss)
{
    for (int i = 0; i < len; i++)
    {
        if (arr[i] == ss)
        {
            return i;
        }
    }
    return -1;
}

int calculatePasivePort(char *strip)
{
    char *token = strtok(strip, ",");
    int numbers[6];
    int i = 0;
    while (token)
    {
        numbers[i++] = atoi(token);
        token = strtok(NULL, ",");
    }
    int pasivePort = numbers[4] * 256 + numbers[5];

    return pasivePort;
}

int portFromServerResp(char *buff)
{
    int init = linearSearch(buff, strlen(buff), '(');
    int fin = linearSearch(buff, strlen(buff), ')');

    char *strip = substr(buff, init + 1, fin);

    return calculatePasivePort(strip);
}

void writefd(int fd, char *buff)
{

    int n = write(fd, buff, strlen(buff));
    if (n < 0)
        error("ERROR writing to socket");
}
int readfd(int fd, char *buf, int len)
{
    int n = read(fd, buf, len);
    if (n < 0)
        error("Error reading socket");
    return n;
}

void readfdPrint(int fd)
{

    char *buff = (char *)calloc(BUFFER_LEN, sizeof(char));
    readfd(fd, buff, BUFFER_LEN);
    printf("%s\n", buff);
    free(buff);
}

int openSocket(int port, struct hostent *server)
{
    struct sockaddr_in serv_addr;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");
    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr_list[0], (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    return sockfd;
}

void quit(int controlfd)
{
    int buflen = 255;
    char *buff = (char *)calloc(buflen, sizeof(char));
    writefd(controlfd, CMD_QUIT);
    readfd(controlfd, buff, buflen);
    printf("%s\n", buff);
    free(buff);
}

int main(int argc, char *argv[])
{
    int controlfd, portno;
    char buffer[BUFFER_LEN];

    if (argc < 3)
    {
        fprintf(stderr, "usage %s hostname port\n", argv[0]);
        exit(0);
    }

    portno = atoi(argv[2]);
    server = gethostbyname(argv[1]);
    controlfd = openSocket(portno, server);
    bzero(buffer, BUFFER_LEN);
    readfd(controlfd, buffer, BUFFER_LEN);
    printf("%s\n", buffer);
    while (1)
    {
        printf(">>>");
        bzero(buffer, BUFFER_LEN);
        fgets(buffer, 255, stdin);
        char *cmdcpy = (char *)calloc(sizeof(char), strlen(buffer));
        strcpy(cmdcpy, buffer);

        bzero(buffer, BUFFER_LEN);
        writefd(controlfd, cmdcpy);
        readfd(controlfd, buffer, BUFFER_LEN);
        printf("%s\n", buffer);

        free(cmdcpy);
    }
    printf("Connection terminated\n");
    close(controlfd);
    return 0;
}
