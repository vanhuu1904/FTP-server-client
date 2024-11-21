#include <stdio.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <stdint.h>
#include <fcntl.h>
#define MAX_LINE_LENGTH 300
#define PORT 123456
static const char *cmd_funcs[] = {
    "USER", "PASS", "SYST", "QUIT", "LIST", "PASV", "CWD", "CDUP", "PWD", "RETR", "STOR",
    "DELE", "RMD", "MKD", "TYPE", NULL};

#define FTP_USER 0
#define FTP_PASS 1
#define FTP_SYST 2
#define FTP_QUIT 3
#define FTP_LIST 4
#define FTP_PASV 5
#define FTP_CWD 6
#define FTP_CDUP 7
#define FTP_PWD 8
#define FTP_RETR 9
#define FTP_STOR 10
#define FTP_DELE 11
#define FTP_RMD 12
#define FTP_MKD 13
#define FTP_TYPE 14

int gen_port()
{
    srand(time(NULL));
    int port = (rand() + 1025) % 0xffff;
    return port;
};

typedef struct Account
{
    char username[25];
    char password[20];
    char rootfolder[50];
    int online;
} Account;

struct connection
{
    int fd;
    int logged_in;
    int passive;
    int pasv_sock;
    char *working_dir;
    Account *u;
};

struct command
{
    int type;
    char *arg;
};

struct command *str_to_cmd(char *raw)
{
    if (raw == NULL)
    {
        return NULL;
    }
    /* Allocate the cmd struct. */
    struct command *cmd = malloc(sizeof(*cmd));
    memset(cmd, 0, sizeof(*cmd));
    /* Find the type of command this is. */
    int i = 0;
    while (1)
    {
        if (cmd_funcs[i] == NULL)
        {
            free(cmd);
            return NULL;
        }
        if (!strncmp(raw, cmd_funcs[i], strlen(cmd_funcs[i])))
        {
            cmd->type = i;
            break;
        }
        i++;
    }

    /* If the command doesn't take any arguments, return.*/
    if (strlen(cmd_funcs[i]) == strlen(raw))
    {
        return cmd;
    }

    /* Copy over the rest of the string as argument. */
    char *src = raw + strlen(cmd_funcs[i]) + 1;
    char *dest = malloc(strlen(src) + 1);
    strcpy(dest, src);
    dest[strlen(src)] = '\0';

    cmd->arg = dest;

    return cmd;
};

char *read_line(int fd, int block_size)
{
    char c[block_size];
    char *buf = NULL;
    int len = 0;

    while (1)
    {
        int amount_read = read(fd, c, block_size);
        if (amount_read <= 0)
        {
            break;
        }
        /* Copy the read message to the buffer. */
        buf = realloc(buf, len + block_size);
        memcpy(buf + len, c, amount_read);
        len += amount_read;

        /* Check if we reached the end of the message. */
        for (int i = 0; i < block_size; i++)
        {
            if ((c[i] == '\r') || (c[i] == '\n') || (c[i] == '\0'))
            {
                c[i] = '\0';
                memcpy(buf + len - amount_read, c, amount_read);
                goto ret;
            }
        }
    }

ret:
    buf = realloc(buf, len + 1);
    buf[len] = '\0';
    return buf;
};

char welcome[] = "220 Service ready for new user.\n";
char login_success[] = "230 User logged in, proceed.\n";
char login_invalid[] = "430 Invalid username/password.\n";
char logout_success[] = "221 Service closing control connection.\n";
char need_pass[] = "331 User name okay, need password.\n";
char bad_sequence[] = "503 Bad sequence of commands.\n";
char not_implemented[] = "502 Command not implemented.\n";
char port_success[] = "200 Command Okay.\n";
char need_login[] = "530 Not logged in.\n";

char opening_data_conn[] = "150 Opening data connection.\n";
char closing_data_conn[] = "226 Closing data connection. Requested file action successful. \n";
char cant_open_data[] = "425 Can't open data connection.\n";
char succ[] = "200 Command Okay.\n";
char internal_err[] = "451 Internal server error.\n";
char invalid_param[] = "504 Command not implemented for that parameter.\n";

char pwd[150];
int indexDB;
Account account[10];
int accountNum;

int open_data_conn(struct connection *conn)
{
    if (conn == NULL)
    {
        return -1;
    }
    if (conn->passive == 1)
    {
        /* Passive mode. */
        write(conn->fd, opening_data_conn, strlen(opening_data_conn));

        if (conn->pasv_sock == 0)
        {
            /* A PASV command was not sent before this. */
            write(conn->fd, cant_open_data, strlen(cant_open_data));
            return -1;
        }

        /* PASV command should have set a passive socket to accept from. */
        struct sockaddr_in addr;
        socklen_t addr_size = sizeof(addr);
        int data_sock = accept(conn->pasv_sock, (struct sockaddr *)&addr, &addr_size);

        if (data_sock < 0)
        {
            write(conn->fd, cant_open_data, strlen(cant_open_data));
            return -1;
        }

        close(conn->pasv_sock);
        return data_sock;
    }
    return -1;
};

int close_data_conn(int fd, struct connection *conn)
{
    if (conn == NULL)
    {
        return -1;
    }
    if (fd < 0)
    {
        return -1;
    }

    close(fd);
    conn->passive = 0;
    conn->pasv_sock = 0;

    return 0;
};

void readAccount()
{
    FILE *inputFile = fopen("database.txt", "r");

    if (!inputFile)
    {
        perror("Error opening file\n");
        return;
    }

    char line[MAX_LINE_LENGTH];

    while (fgets(line, sizeof(line), inputFile))
    {
        Account tmp;
        int result = sscanf(line, "%s %s %s", tmp.username, tmp.password, tmp.rootfolder);
        account[accountNum++] = tmp;
    }
    fclose(inputFile);
}

void ftp_cmd_user(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    if (cmd->arg == NULL)
    {
        write(conn->fd, login_invalid, strlen(login_invalid));
        return;
    }
    if (conn->u != NULL)
    {
        conn->u->online--;
        conn->logged_in = 0;
        printf("User %s logged out.\n", conn->u->username);
        conn->u = NULL;
    }

    /* Look for the username. */
    for (int i = 0; i < accountNum; i++)
    {
        if (!strcmp(account[i].username, cmd->arg))
        {
            write(conn->fd, need_pass, strlen(need_pass));
            conn->u = account + i;
            return;
        }
    }

    /* The username was not found. */
    write(conn->fd, login_invalid, strlen(login_invalid));
    return;
};

void ftp_cmd_pass(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    if (cmd->arg == NULL)
    {
        write(conn->fd, login_invalid, strlen(login_invalid));
        return;
    }

    /* Check if username has been specified. */
    if (conn->u == NULL)
    {
        write(conn->fd, bad_sequence, strlen(bad_sequence));
        return;
    }

    /* Check the password. */
    if (!strcmp(cmd->arg, conn->u->password))
    {
        /* Correct password. */
        // char *slash = "/";
        // conn->working_dir = realloc(conn->working_dir, strlen(conn->working_dir) + 3 + strlen(conn->u->rootfolder));
        // strcat(conn->working_dir, conn->u->rootfolder);
        // strcat(conn->working_dir, slash);
        chdir(conn->u->rootfolder);
        conn->logged_in = 1;
        conn->u->online++;
        write(conn->fd, login_success, strlen(login_success));
        printf("User %s logged in.\n", conn->u->username);
        return;
    }

    /* The password is invalid. */
    conn->logged_in = 0;
    conn->u = NULL;
    write(conn->fd, login_invalid, strlen(login_invalid));
};

void ftp_cmd_quit(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    if ((conn->u != NULL) && (conn->logged_in))
    {
        conn->u->online--;
        printf("User %s logged out.\n", conn->u->username);
    }

    conn->logged_in = 0;
    conn->u = NULL;

    write(conn->fd, logout_success, strlen(logout_success));
    close(conn->fd);
    return;
};

int handle_cmd(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return 1;
    }
    if (conn == NULL)
    {
        return 1;
    }

    printf("Message Received: %s %s\n", cmd_funcs[cmd->type], cmd->arg);

    /* Non-privilidged commands. */
    switch (cmd->type)
    {
    case FTP_USER:
        ftp_cmd_user(cmd, conn);
        return 0;

    case FTP_PASS:
        ftp_cmd_pass(cmd, conn);
        return 0;

    case FTP_QUIT:
        ftp_cmd_quit(cmd, conn);
        return 1;

    default:
        break;
    }

    /* User-privilidged commands. */
    if (conn->logged_in == 0)
    {
        write(conn->fd, need_login, strlen(need_login));
        return 0;
    }

    return 0;
};

void mainloop(struct connection *conn)
{
    /* Send the welcome message. */
    write(conn->fd, welcome, strlen(welcome));

    /* Repeatedly recieve commands from the client. */
    while (1)
    {
        char *msg = read_line(conn->fd, 4);
        if (strlen(msg) < 3)
        {
            /* There's no command. */
            free(msg);
            continue;
        }

        /* Parse the message. */
        struct command *cmd = str_to_cmd(msg);
        free(msg);

        if (cmd == NULL)
        {
            /* A valid command was not detected. */
            write(conn->fd, not_implemented, strlen(not_implemented));
            continue;
        }

        if (handle_cmd(cmd, conn))
        {
            /* A non-zero return value indicates the connection terminated. */
            free(cmd);
            break;
        }

        if (cmd->arg != NULL)
        {
            free(cmd->arg);
        }
        free(cmd);
    }
    return;
}

int main()
{
    readAccount();
    int sockFD, bindOutput, clientLen;
    struct sockaddr_in servaddr, cliaddr;
    sockFD = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFD < 0)
    {
        printf("\nSocket Error\n");
        exit(0);
    }
    else
    {
        printf("\nSocket is created\n");
    }
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);
    bindOutput = bind(sockFD, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (bindOutput < 0)
    {
        printf("\nCant bind\n");
        exit(0);
    }
    else
    {
        printf("\nBinded\n");
    }
    listen(sockFD, 5);
    while (1)
    {
        socklen_t clientLen = sizeof(cliaddr);
        int acceptOutput = accept(sockFD, (struct sockaddr *)&cliaddr, &clientLen);
        if (acceptOutput < 0)
        {
            printf("Cant accept\n");
            exit(0);
        }
        struct connection *conn = malloc(sizeof(*conn));
        memset(conn, 0, sizeof(*conn));
        conn->fd = acceptOutput;
        
        pid_t pid;
        if ((pid = fork()) == 0)
        {
            close(sockFD);
            mainloop(conn);
            close(conn->fd);
            exit(0);
        }
        close(conn->fd);
    }
    return 0;
}