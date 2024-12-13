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

int startwith(const char *a, const char *b)
{
    return strncmp(a, b, strlen(b)) == 0 ? 1 : 0;
}

typedef struct
{
    char *remoteFileName;
    char *localFileName;
    char *command;
} RetrFile;

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

void listRemote(int controlfd, char *command)
{
    char *buff = (char *)calloc(BUFFER_LEN, sizeof(char));
    writefd(controlfd, CMD_PASV);
    readfd(controlfd, buff, BUFFER_LEN);
    printf("%s\n", buff);

    int pasivePort = portFromServerResp(buff);
    int pasivefd = openSocket(pasivePort, server);
    writefd(controlfd, command);
    readfdPrint(controlfd);
    while (readfd(pasivefd, buff, BUFFER_LEN) > 0)
    {
        printf("%s", buff);
    }
    writefd(controlfd, "\n");
    printf("\n");
    readfdPrint(controlfd);
    free(buff);
    close(pasivefd);
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

char *cleanFilename(char *originfn)
{
    int k = linearSearch(originfn, strlen(originfn), '\n');
    if (k == -1)
    {
        return originfn;
    }
    return substr(originfn, 0, k);
}

void writeInFile(char *filename, int passivefd)
{
    filename = cleanFilename(filename);

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd < 0)
    {
        fprintf(stderr, "Error opening file\n");
        return;
    }
    /* Read from the socket, then write to the file.  */
    int block_size = 0x1000;
    int bytes_read = 0;
    char *buf = malloc(block_size);

    while ((bytes_read = read(passivefd, buf, block_size)) > 0)
    {
        write(fd, buf, bytes_read);
    }
    free(buf);
    close(fd);
    return;
}

RetrFile *getFileParams(char *command, RetrFile *ret)
{
    char *token = strtok(command, " ");
    char *cmd;
    int i = 0;
    while (token)
    {
        if (i == 1)
        {
            ret->remoteFileName = (char *)calloc(strlen(token), sizeof(char));
            strcpy(ret->remoteFileName, token);
        }
        else if (i == 2)
        {
            ret->localFileName = (char *)calloc(strlen(token), sizeof(char));
            strcpy(ret->localFileName, token);
        }
        else if (i == 0)
        {
            cmd = (char *)calloc(strlen(token), sizeof(char));
            strcpy(cmd, token);
        }

        i++;
        token = strtok(NULL, " ");
    }

    int total = strlen(ret->remoteFileName) + strlen(cmd) + 2;
    ret->command = (char *)calloc(total, sizeof(char));
    strcat(ret->command, cmd);
    strcat(ret->command, " ");
    strcat(ret->command, ret->remoteFileName);
    strcat(ret->command, "\n");

    free(cmd);

    return ret;
}

void retrFile(int controlfd, char *command)
{
    char *buff = (char *)calloc(BUFFER_LEN, sizeof(char));
    writefd(controlfd, CMD_PASV);
    readfd(controlfd, buff, BUFFER_LEN);
    printf("%s\n", buff);

    int pasivePort = portFromServerResp(buff);
    int pasivefd = openSocket(pasivePort, server);
    RetrFile *retFile = (RetrFile *)malloc(sizeof(RetrFile));
    retFile->command = command;
    getFileParams(command, retFile);
    writefd(controlfd, retFile->command);
    // read response to RETR
    bzero(buff, BUFFER_LEN);
    readfd(controlfd, buff, BUFFER_LEN);
    printf("%s", buff);
    if (startwith(buff, FILE_NOT_FOUND))
    {
        // RETR file not found
        printf("File %s not found in remote server.\n",
               cleanFilename(retFile->remoteFileName));
        return;
    }
    writeInFile(retFile->localFileName != NULL ? retFile->localFileName : retFile->remoteFileName, pasivefd);
    free(retFile);
    writefd(controlfd, "\n");
    readfdPrint(controlfd);
    free(buff);
    close(pasivefd);
}

void storFile(int controlfd, char *command)
{
    char *buff = (char *)calloc(BUFFER_LEN, sizeof(char));
    char filename[256]; 
    if (sscanf(command, "STOR %255s", filename) != 1)
    {
        fprintf(stderr, "Error extracting filename from STOR command\n");
        return;
    }
    writefd(controlfd, CMD_PASV);
    readfd(controlfd, buff, BUFFER_LEN);
    printf("%s\n", buff);

    int fd = open(filename, O_RDWR);
    if (fd < 0)
    {
        fprintf(stderr, "Error opening file\n");
        return;
    }
    writefd(controlfd, command);
    int pasivePort = portFromServerResp(buff);
    int pasivefd = openSocket(pasivePort, server);
    // read response to RETR
    bzero(buff, BUFFER_LEN);
    readfd(controlfd, buff, BUFFER_LEN);
    printf("%s", buff);
    int flen = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

#ifdef __APPLE__
    off_t offset = 0;
    off_t length = flen;
    int result = sendfile(fd, pasivefd, offset, &length, NULL, 0);
    if (result == -1)
    {
        perror("Error during file transfer");
    }
#else
    sendfile(pasivefd, fd, NULL, flen);
#endif
    close(fd);
    // Close the data socket after sending data
    close(pasivefd);
    free(buff);
    readfdPrint(controlfd);
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

        if (startwith(buffer, CMD_LIST))
        {
            listRemote(controlfd, cmdcpy);
        }
        else if (startwith(buffer, CMD_RETR))
        {
            retrFile(controlfd, cmdcpy);
        }
        else if (startwith(buffer, CMD_STOR))
        {
            storFile(controlfd, cmdcpy);
        }
        else if (strcmp(CMD_QUIT, buffer) == 0)
        {
            quit(controlfd);
            break;
        }
        else
        {
            bzero(buffer, BUFFER_LEN);
            writefd(controlfd, cmdcpy);
            readfd(controlfd, buffer, BUFFER_LEN);
            printf("%s\n", buffer);
        }

        free(cmdcpy);
    }
    printf("Connection terminated\n");
    close(controlfd);
    return 0;
}
