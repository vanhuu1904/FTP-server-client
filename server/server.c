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
#include <arpa/inet.h>
#define MAX_LINE_LENGTH 300
#define PORT 1234
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

char *construct_full_path(char *file_name, char *working_dir)
{
    if (!file_name || !working_dir)
    {
        return NULL;
    }

    char *fpath = malloc(strlen(file_name) + strlen(working_dir) + 2);
    if (fpath == NULL)
    {
        return NULL;
    }

    fpath[0] = '.';
    fpath[1] = '\0';

    /* conn->working_dir always begins with a slash*/
    strcat(fpath, working_dir);
    strcat(fpath, file_name);

    return fpath;
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

char welcome[] = "220 Service ready for new user.\r\n";
char login_success[] = "230 User logged in, proceed.\r\n";
char login_invalid[] = "430 Invalid username/password.\r\n";
char logout_success[] = "221 Service closing control connection.\r\n";
char need_pass[] = "331 User name okay, need password.\r\n";
char system_info[] = "215 LINUX\r\n";
char bad_sequence[] = "503 Bad sequence of commands.\r\n";
char not_implemented[] = "502 Command not implemented.\r\n";
char port_success[] = "200 Command Okay.\r\n";
char typei_success[] = "200 Switching to binary mode (image).\r\n";
char typea_success[] = "200 Switching to ASCII mode.\r\n";
char file_unavailable[] = "550 File unavailable. \r\n";
char need_login[] = "530 Not logged in.\r\n";
char delete_success[] = "250 Delete success. \r\n";

char opening_data_conn[] = "150 Opening data connection.\r\n";
char closing_data_conn[] = "226 Closing data connection. Requested file action successful. \r\n";
char cant_open_data[] = "425 Can't open data connection.\r\n";
char succ[] = "200 Command Okay.\r\n";
char internal_err[] = "451 Internal server error.\r\n";
char invalid_param[] = "504 Command not implemented for that parameter.\r\n";

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
            printf("test");
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

void ftp_cmd_pasv(struct command *cmd, struct connection *conn)
{
    int port = gen_port();
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    int port1 = port & 0xFF;
    int port2 = (port >> 8) & 0xFF;

    conn->pasv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->pasv_sock < 0)
    {
        conn->pasv_sock = 0;
        write(conn->fd, internal_err, strlen(internal_err));
        return;
    }

    /* Bind socket, and set it to listening mode. */
    struct sockaddr_in paddr;
    int addr_len = sizeof(paddr);
    paddr.sin_family = AF_INET;
    paddr.sin_addr.s_addr = INADDR_ANY;
    paddr.sin_port = htons(port);

    if (bind(conn->pasv_sock, (struct sockaddr *)&paddr, addr_len))
    {
        close(conn->pasv_sock);
        conn->pasv_sock = 0;
        write(conn->fd, internal_err, strlen(internal_err));
        return;
    }

    listen(conn->pasv_sock, 1);

    conn->passive = 1;
    // Get the server's IP address
   struct sockaddr_in serv_addr;
    socklen_t len = sizeof(serv_addr);
    if (getsockname(conn->fd, (struct sockaddr *)&serv_addr, &len) < 0)
    {
        perror("getsockname failed");
        write(conn->fd, internal_err, strlen(internal_err));
        return;
    }

    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &serv_addr.sin_addr, ip_str, sizeof(ip_str)) == NULL)
    {
        perror("inet_ntop failed");
        write(conn->fd, internal_err, strlen(internal_err));
        return;
    }

    // Converts IP addresses from strings to numeric elements
    int h1, h2, h3, h4;
    if (sscanf(ip_str, "%d.%d.%d.%d", &h1, &h2, &h3, &h4) != 4)
    {
        fprintf(stderr, "Invalid IP format: %s\n", ip_str);
        write(conn->fd, internal_err, strlen(internal_err));
        return;
    }
    dprintf(conn->fd, "227 Entering passive mode (%d,%d,%d,%d,%d,%d) \n",
            h1, h2, h3, h4,
            port2, port1);
    return;
};

void ftp_cmd_list(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    int data_sock = open_data_conn(conn);
    if (data_sock < 0)
    {
        return;
    }

    /* First, open the directory. */
    char *path = malloc(strlen(conn->working_dir) + 2);
    path[0] = '.';
    path[1] = '\0';
    strcat(path, conn->working_dir);

    DIR *cdfd = opendir(path);
    struct dirent *ent;

    /* Send directory entries. */
    struct stat fs;
    char time_buf[20];
    while ((ent = readdir(cdfd)) != NULL)
    {
        /* Ignore current and parent directories */
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        /* Construct the path of the file relative to the working directory. */
        char *file_path = malloc(strlen(path) + strlen(ent->d_name) + 1);
        strcpy(file_path, path);
        strcat(file_path, ent->d_name);
        if (stat(file_path, &fs) < 0)
        {
            free(file_path);
            continue;
        }

        struct passwd *owner_info = getpwuid(fs.st_uid);
        struct group *group_info = getgrgid(fs.st_gid);
        struct tm *modification_time = localtime(&fs.st_mtime);
        if (modification_time == NULL || strftime(time_buf, sizeof(time_buf), "%b %d %H:%M", modification_time) == 0)
        {
            strncpy(time_buf, "??? ?? ??::??", sizeof(time_buf));
            time_buf[sizeof(time_buf) - 1] = '\0';
        }
        free(file_path);
        /* Determine file type. */
        char ftype = '-';

        if (S_ISREG(fs.st_mode))
        {
            ftype = '-';
        }
        else if (S_ISDIR(fs.st_mode))
        {
            ftype = 'd';
        }
        else if (S_ISCHR(fs.st_mode))
        {
            ftype = 'c';
        }
        else if (S_ISBLK(fs.st_mode))
        {
            ftype = 'b';
        }
        else if (S_ISLNK(fs.st_mode))
        {
            ftype = 'l';
        }

        /* Determine file permissions. */
         char permissions[10];
        snprintf(permissions, sizeof(permissions), 
                 "%c%c%c%c%c%c%c%c%c",
                 (fs.st_mode & S_IRUSR) ? 'r' : '-',
                 (fs.st_mode & S_IWUSR) ? 'w' : '-',
                 (fs.st_mode & S_IXUSR) ? 'x' : '-',
                 (fs.st_mode & S_IRGRP) ? 'r' : '-',
                 (fs.st_mode & S_IWGRP) ? 'w' : '-',
                 (fs.st_mode & S_IXGRP) ? 'x' : '-',
                 (fs.st_mode & S_IROTH) ? 'r' : '-',
                 (fs.st_mode & S_IWOTH) ? 'w' : '-',
                 (fs.st_mode & S_IXOTH) ? 'x' : '-');

        dprintf(data_sock, "%c%s %lu %s %s %8ld %s %s\r\n",
                ftype,
                permissions,
                (unsigned long)fs.st_nlink,
                owner_info != NULL ? owner_info->pw_name : "UNKNOWN_OWNER",
                group_info != NULL ? group_info->gr_name : "UNKNOWN_GROUP",
                (long)fs.st_size,
                time_buf,
                ent->d_name);
    }

    closedir(cdfd);
    free(path);

    write(conn->fd, closing_data_conn, strlen(closing_data_conn));
    close_data_conn(data_sock, conn);
    return;
};

void ftp_cmd_cwd(struct command *cmd, struct connection *conn)
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
        return;
    }

    /* CWD should not be used to move to the parent directory. */
    for (int i = 0; i < strlen(cmd->arg); i++)
    {
        if (!strncmp(cmd->arg + i, "..", 2))
        {
            write(conn->fd, invalid_param, strlen(invalid_param));
            return;
        }
    }

    char *slash = "/";
    conn->working_dir = realloc(conn->working_dir, strlen(conn->working_dir) + 3 + strlen(cmd->arg));
    strcat(conn->working_dir, cmd->arg);
    strcat(conn->working_dir, slash);

    write(conn->fd, succ, strlen(succ));
    return;
};

/* PWD - Print Working Directory. */
void ftp_cmd_pwd(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    dprintf(conn->fd, "257 Your current working directory is '%s'\n", conn->working_dir);
    return;
};

void ftp_cmd_retr(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    /* Construct the path to the file. */
    char *fpath = malloc(strlen(conn->working_dir) + strlen(cmd->arg) + 2);
    fpath[0] = '.';
    fpath[1] = '\0';

    strcat(fpath, conn->working_dir);
    strcat(fpath, cmd->arg);

    /* Open the file.*/
    int fd = open(fpath, O_RDWR);
    if (fd < 0)
    {
        write(conn->fd, file_unavailable, strlen(file_unavailable));
        return;
    }

    /* Now that we're sure the file exists and can be transferred, open data conn.*/
    int data_sock = open_data_conn(conn);
    if (data_sock < 0)
    {
        close(fd);
        return;
    }

    /* Get the file size, then send the file. */
    off_t flen = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

#ifdef __APPLE__
    off_t offset = 0;
    off_t length = flen;
    int result = sendfile(fd, data_sock, offset, &length, NULL, 0);
    if (result == -1)
    {
        perror("Error during file transfer");
        write(conn->fd, internal_err, strlen(internal_err));
    }
#else
    sendfile(data_sock, fd, NULL, flen);
#endif
    close(fd);

    /* Transfer complete. */
    write(conn->fd, closing_data_conn, strlen(closing_data_conn));
    close_data_conn(data_sock, conn);
    return;
};

/* STOR - Store file. */
void ftp_cmd_stor(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    /* First, open the file. */
    char *fpath = malloc(strlen(conn->working_dir) + strlen(cmd->arg) + 3);
    fpath[0] = '.';
    fpath[1] = '\0';

    strcat(fpath, conn->working_dir);
    strcat(fpath, cmd->arg);

    int fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
    free(fpath);

    if (fd < 0)
    {
        write(conn->fd, file_unavailable, strlen(file_unavailable));
        return;
    }

    /* Open the data connection. */
    int data_sock = open_data_conn(conn);
    if (data_sock < 0)
    {
        close(fd);
        return;
    }

    /* Read from the socket, then write to the file.  */
    int block_size = 0x1000;
    int bytes_read = 0;
    char *buf = malloc(block_size);

    while ((bytes_read = read(data_sock, buf, block_size)) > 0)
    {
        write(fd, buf, bytes_read);
    }
    free(buf);
    close(fd);

    write(conn->fd, closing_data_conn, strlen(closing_data_conn));
    close_data_conn(data_sock, conn);
    return;
};

/* DELE - Delete file. */
void ftp_cmd_dele(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    char *fpath = construct_full_path(cmd->arg, conn->working_dir);

    int s = unlink(fpath);
    free(fpath);

    if (s < 0)
    {
        write(conn->fd, file_unavailable, strlen(file_unavailable));
        return;
    }

    write(conn->fd, delete_success, strlen(delete_success));
    return;
};

void ftp_cmd_rmd(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    char *fpath = construct_full_path(cmd->arg, conn->working_dir);

    int s = rmdir(fpath);
    free(fpath);

    if (s < 0)
    {
        write(conn->fd, file_unavailable, strlen(file_unavailable));
        return;
    }

    write(conn->fd, delete_success, strlen(delete_success));
    return;
};

void ftp_cmd_mkd(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    char *fpath = construct_full_path(cmd->arg, conn->working_dir);

    int s = mkdir(fpath, 0744);
    free(fpath);

    if (s < 0)
    {
        write(conn->fd, file_unavailable, strlen(file_unavailable));
        return;
    }

    write(conn->fd, succ, strlen(succ));
    return;
};

void ftp_cmd_cdup(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL)
    {
        return;
    }
    if (conn == NULL)
    {
        return;
    }

    int cur_len = strlen(conn->working_dir);
    if (cur_len <= 2)
    {
        write(conn->fd, succ, strlen(succ));
        return;
    }

    int len = 0;
    for (int i = cur_len - 2; i >= 0; i--, len++)
    {
        if (conn->working_dir[i] == '/')
        {
            conn->working_dir[i + 1] = '\0';
            break;
        }
    }

    /* Now resize the string. */
    conn->working_dir = realloc(conn->working_dir, cur_len - len + 1);

    write(conn->fd, succ, strlen(succ));
    return;
};

void ftp_cmd_type(struct command *cmd, struct connection *conn)
{
    if (cmd == NULL || conn == NULL)
    {
        return;
    }

    if (cmd->arg == NULL)
    {
        return;
    }

    if (strcmp(cmd->arg, "I") == 0)
    {
        // Handle binary mode
        write(conn->fd, typei_success, strlen(typei_success));
        // You may want to implement further logic based on the binary mode.
    }
    else if (strcmp(cmd->arg, "A") == 0)
    {
        // Handle ASCII mode
        write(conn->fd, typea_success, strlen(typea_success));
        // You may want to implement further logic based on the ASCII mode.
    }
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

    switch (cmd->type)
    {
    case FTP_SYST:
        write(conn->fd, system_info, strlen(system_info));
        break;

    case FTP_LIST:
        ftp_cmd_list(cmd, conn);
        break;

    case FTP_PASV:
        ftp_cmd_pasv(cmd, conn);
        break;

    case FTP_CWD:
        ftp_cmd_cwd(cmd, conn);
        break;

    case FTP_CDUP:
        ftp_cmd_cdup(cmd, conn);
        break;

    case FTP_PWD:
        ftp_cmd_pwd(cmd, conn);
        break;

    case FTP_RETR:
        ftp_cmd_retr(cmd, conn);
        break;

    case FTP_STOR:
        ftp_cmd_stor(cmd, conn);
        break;

    case FTP_DELE:
        ftp_cmd_dele(cmd, conn);
        break;

    case FTP_RMD:
        ftp_cmd_rmd(cmd, conn);
        break;

    case FTP_MKD:
        ftp_cmd_mkd(cmd, conn);
        break;
    case FTP_TYPE:
        ftp_cmd_type(cmd, conn);
        break;

    default:
        write(conn->fd, not_implemented, strlen(not_implemented));
        break;
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
        conn->working_dir = malloc(2);
        conn->working_dir[0] = '/';
        conn->working_dir[1] = '\0';
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