/*
AORTA: Another Onion Router Transproxy Application.
===================================================

Version 1.1

Copyright (C) 2017 Rob van der Hoeven


Usage:
======

Aorta transparently routes all TCP and DNS traffic from a program under its
control through the Tor network. Usage is as follows:

    aorta [aorta parameters] [program] [program parameters]

possible (optional) aorta parameters are:

 -t   enable terminal output (for programs like wget, w3m etc.)
 -c   DO NOT CHECK if Tor handles all Internet traffic
 -a   DO NOT CHECK if the targeted program is already active

ONLY use a DO NOT CHECK option if you are *very sure* that the check is
indeed not needed.

examples:

    aorta firefox https://check.torproject.org
    aorta chromium expyuzz4wqqyqhjn.onion
    aorta -t w3m expyuzz4wqqyqhjn.onion
    aorta -t git clone http://dccbbv6cooddgcrq.onion/tor.git
    aorta bash


Requirements:
=============

Linux kernel >= 3.14          (check: uname -a)

iptables with cgroup support  (check: sudo iptables -m cgroup -h | grep cgroup)

local Tor configuration (/etc/tor/torrc) should have the following lines:

    VirtualAddrNetworkIPv4 10.192.0.0/10
    AutomapHostsOnResolve 1
    TransPort 9040
    DNSPort 9041

NOTE: if you change the Tor configuration the Tor daemon must be restarted.


Compilation:
============

gcc -Wall -o aorta aorta.c


Installation:
=============

execute the following commands as root:

    cp aorta /usr/local/bin/aorta
    chown root:root /usr/local/bin/aorta
    chmod u+s /usr/local/bin/aorta


Support:
========

https://hoevenstein.nl/aorta-a-transparent-tor-proxy-for-linux-programs


License:
========

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <termios.h>

#define TOR_TCP_PORT              "9040"
#define TOR_DNS_PORT              "9041"
#define TOR_ONION_NETWORK         "10.192.0.0/10"
// the .onion address below is for the torproject.org website
#define TOR_CONNECTION_TEST_HOST  "expyuzz4wqqyqhjn.onion"
// the .onion address below is for the facebook.com website
//#define TOR_CONNECTION_TEST_HOST  "facebookcorewwwi.onion"
#define AORTA_CGROUP_CLASSID      "0x19840001"

#define HAPPY(TEXT) "\x1b[32;1m" TEXT "\x1b[0m"
#define ANGRY(TEXT) "\x1b[31;1m" TEXT "\x1b[0m"
#define BOLD(TEXT)  "\x1b[37;1m" TEXT "\x1b[0m"

typedef int (*exec_function)(const char *path, char *const argv[]);

int check_tor_connection=1;
int check_if_program_is_active=1;
int enable_terminal_output=0;

const char iptables_path[]=
    "/sbin/iptables";

const char usage[]=
    "\n" BOLD("AORTA version 1.1")"\n\n"
    BOLD("usage   :")"  aorta [aorta parameters] [program] [program parameters]\n"
    BOLD("example :")"  aorta firefox https://check.torproject.org\n\n"
    "possible (optional) aorta parameters are:\n\n"
    " -t   " "enable terminal output (for programs like wget, w3m etc.)\n"
    " -c   " BOLD("DO NOT CHECK") " if Tor handles all Internet traffic\n"
    " -a   " BOLD("DO NOT CHECK") " if the targeted program is already active\n\n"
    BOLD("ONLY") " use a " BOLD("DO NOT CHECK") " option if you are " BOLD("*very sure*") " that the check is\n"
    "indeed not needed.\n\n";

const char program_is_active_warning[]=
    "\n" ANGRY("WARNING") "\n\n"
    "The program you want to start is already running. Some programs will clone\n"
    "a running program. If so, this cloned program will NOT USE THE Tor NETWORK.\n"
    "You can detect this behavior as follows:\n\n"
    " - AORTA exits after the program is started\n"
    " - The title bar of Firefox/Chrome does not show (on AORTA).\n"
    " - https://check.torproject.org reports: You are not using Tor.\n\n"
    "Do you want to continue (y/N)? ";

const char http_request[]=
    "HEAD / HTTP/1.1\r\n"
    "User-Agent: AORTA/1.1 (%.32s)\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: identity\r\n"
    "Host: " TOR_CONNECTION_TEST_HOST "\r\n"
    "Connection: Keep-Alive\r\n\r\n";

// iptables rules to forward traffic to the local Tor daemon
//
// NOTE: the iptables COMMAND should be the third parameter and must be 2 chars long

const char *aorta_rules[] =
{
    // create an aorta chain inside the nat table

    "-t nat -N aorta",

    // DNS queries for onion addresses are resolved to an address in the
    // TOR_ONION_NETWORK range. traffic in this network must always be
    // processed by the local Tor daemon

    "-t nat -A aorta -p tcp -m tcp -d " TOR_ONION_NETWORK " -j REDIRECT --to-ports " TOR_TCP_PORT,

    // do not touch non-routable addresses, except for DNS traffic

    "-t nat -A aorta -d 127.0.0.0/8    -p udp -m udp ! --dport 53 -j RETURN",
    "-t nat -A aorta -d 127.0.0.0/8    -p tcp -m tcp ! --dport 53 -j RETURN",
    "-t nat -A aorta -d 10.0.0.0/8     -p udp -m udp ! --dport 53 -j RETURN",
    "-t nat -A aorta -d 10.0.0.0/8     -p tcp -m tcp ! --dport 53 -j RETURN",
    "-t nat -A aorta -d 192.168.0.0/16 -p udp -m udp ! --dport 53 -j RETURN",
    "-t nat -A aorta -d 192.168.0.0/16 -p tcp -m tcp ! --dport 53 -j RETURN",
    "-t nat -A aorta -d 172.16.0.0/12  -p udp -m udp ! --dport 53 -j RETURN",
    "-t nat -A aorta -d 172.16.0.0/12  -p tcp -m tcp ! --dport 53 -j RETURN",

    // redirect to local Tor daemon

    "-t nat -A aorta -p tcp -m tcp -j REDIRECT --to-ports " TOR_TCP_PORT,
    "-t nat -A aorta -p udp -m udp --dport 53 -j REDIRECT --to-ports " TOR_DNS_PORT,

    // output traffic from processes inside our cgroup is processed by aorta chain

    "-t nat -A OUTPUT -m cgroup --cgroup " AORTA_CGROUP_CLASSID " -j aorta",
    0
};

char *argv_to_commandline(char *const argv[])
{
    static char commandline[1024];
    char **arg;
    int space;

    arg=(char**) argv;
    commandline[0]=0;
    space=sizeof(commandline)-3;

    while (*arg && ((space-=strlen(*arg)) > 0))
    {
        if (*commandline)
            strcat(commandline, " ");

        strcat(commandline, *arg++);
    }

    return commandline;
}

void execute(int enable_terminal_output, exec_function f, const char *path, char *const argv[])
{
    int fd_null, fd_stdout, fd_stderr, err;

    fd_stdout=dup(STDOUT_FILENO);
    fd_stderr=dup(STDERR_FILENO);
    fcntl(fd_stdout, F_SETFD, FD_CLOEXEC);
    fcntl(fd_stderr, F_SETFD, FD_CLOEXEC);

    // it would be silly to suppress the output of a shell....

    if (!enable_terminal_output && (strcmp(argv[0], "bash") != 0) && (strcmp(argv[0], "sh") != 0))
    {
        fd_null=open("/dev/null", O_APPEND);
        dup2(fd_null, STDOUT_FILENO);
        dup2(fd_null, STDERR_FILENO);
        close(fd_null);
    }

    // if something went wrong, restore output so the problem can be reported

    if (f(path, argv) == -1)
    {
        err=errno;
        dup2(fd_stdout, STDOUT_FILENO);
        dup2(fd_stderr, STDERR_FILENO);
        error(EXIT_FAILURE, err, ANGRY("FAILED") " to execute [%s]", argv_to_commandline(argv));
    }
}

int iptables_execute(const char *commandline)
{
    char *argv[50], *arg, buffer[256];
    int  argc, iptables_status;
    pid_t iptables_pid;
    char *check_command="-C";
    char *append_command="-A";

    memset(buffer, 0, sizeof(buffer));
    strncpy(buffer, commandline, sizeof(buffer)-1);

    argc=0;
    argv[argc++]= (char *) iptables_path;
    arg = strtok(buffer, " ");

    while (arg && argc < 49)
    {
        argv[argc++] = arg;
        arg = strtok(0, " ");
    }

    argv[argc] = 0;

    // before an append command, first check if the rule is already present

    if (strcmp(argv[3], append_command) == 0)
    {
        argv[3]=check_command;
        iptables_pid=fork();

        if (iptables_pid == -1)
            error(EXIT_FAILURE, errno, NULL);

        if (iptables_pid == 0)
            execute(0, execv, argv[0], argv);

        waitpid(iptables_pid, &iptables_status, 0);

        // exit code 0 means rule is already present.

        if (WEXITSTATUS(iptables_status) == 0)
            return 0;

        argv[3]=append_command;
    }

    // add rule

    iptables_pid=fork();

    if (iptables_pid == -1)
        error(EXIT_FAILURE, errno, NULL);

    if (iptables_pid == 0)
        execute(0, execv, argv[0], argv);

    waitpid(iptables_pid, &iptables_status,0);
    return WEXITSTATUS(iptables_status);
}

void iptables_add_rules(const char** rule)
{
    while (*rule)
        iptables_execute(*rule++);
}

void create_net_cls_cgroup(char *directory, char *classid)
{
    int fd;
    char path[256];

    sprintf(path, "/sys/fs/cgroup/net_cls/%s", directory);

    if ((mkdir(path, 0755) == -1) && (errno != EEXIST))
       error(EXIT_FAILURE, errno, ANGRY("FAILED") " to create cgroup [%s].", path);

    if ((fd=open(strcat(path, "/net_cls.classid"), O_WRONLY | O_APPEND | O_CLOEXEC)) == -1)
        error(EXIT_FAILURE, errno, ANGRY("FAILED") " to open [%s].", path);

    if (write(fd, classid, strlen(classid)) == -1)
       error(EXIT_FAILURE, errno, ANGRY("FAILED") " to write classid [%s].", classid);

    close(fd);
}

void join_net_cls_cgroup(char *directory)
{
    int fd;
    char buffer[256];

    sprintf(buffer, "/sys/fs/cgroup/net_cls/%s/cgroup.procs", directory);

    if ((fd=open(buffer, O_WRONLY | O_APPEND | O_CLOEXEC)) == -1)
        error(EXIT_FAILURE, errno, ANGRY("FAILED") " to open [%s].", buffer);

    if (write(fd, buffer, sprintf(buffer,"%d",getpid())) == -1)
        error(EXIT_FAILURE, errno, ANGRY("FAILED") " to add PID to cgroup.procs.");

    close(fd);
}

void new_hostname(char *hostname)
{
    // A new hostname can be handy because:
    //
    // - When a shell is started by aorta, the hostname will be part of its prompt
    // - X11 programs like Firefox and Chromium show it on their title bars.
    //
    // So, a new hostname can give a visual indication that a program is using
    // the Tor network.
    //
    // BUT: new_hostname() makes the X-server think it is accessed from another
    // system. *Some* Linux distributions (ArchLinux) use a strict X-server access
    // configuration which prevent programs running on another system from
    // accessing the X11 screen. In this case programs will fail to run.
    //
    // There are 2 solutions for this problem:
    //
    // 1) Comment-out or remove the new_hostname function call
    // 2) Make the X-server configuration less restrictive by running the command:
    //
    //    xhost +local:
    //
    //    This command won't survive a restart. For this you have to add it
    //    to .xinitrc, just before the gui is started.

    if (unshare(CLONE_NEWUTS) == -1)
        error(EXIT_FAILURE, errno, ANGRY("FAILED") " to unshare uts namespace.");

    if (sethostname(hostname, strlen(hostname)) == -1)
        error(EXIT_FAILURE, errno, ANGRY("FAILED") " to change hostname to [%s].", hostname);
}

void test_tor_connection(char *program_name)
{
    struct addrinfo *address_info, hints;
    struct sockaddr_in *ip_address;
    char ip_address_str[INET_ADDRSTRLEN];
    char http_buffer[2048];
    int r,fd, count, pos, length;

    if (!check_tor_connection)
    {
        printf("\n" ANGRY("WARNING") " NOT testing if Tor handles all Internet traffic.\n");
        return;
    }

    printf("\n" HAPPY("TESTING") " if Tor handles all Internet traffic\n\n");
    printf("...Resolving        - " HAPPY("%s") "\n", TOR_CONNECTION_TEST_HOST);
    printf("...IP address       - ");

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;

    if ((r=getaddrinfo(TOR_CONNECTION_TEST_HOST , "80", &hints, &address_info)))
    {
        printf(ANGRY("FAILED") " Tor connection test, result [%s]\n", gai_strerror(r));
        exit(EXIT_FAILURE);
    }

    if (address_info->ai_next)
    {
        printf(ANGRY("FAILED") " to resolve onion address error [%s]\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    ip_address = (struct sockaddr_in *) address_info->ai_addr;
    inet_ntop(AF_INET, &(ip_address->sin_addr), ip_address_str, INET_ADDRSTRLEN);

    // check if the address is non-routable and inside the TOR_ONION_NETWORK
    // range. Only check the first 3 positions.

    if (strncmp(ip_address_str, TOR_ONION_NETWORK, 3))
    {
        printf(ANGRY("FAILED") " address [%s] ouside expected range [%s]\n", ip_address_str, TOR_ONION_NETWORK);
        exit(EXIT_FAILURE);
    }

    printf(HAPPY("%s") "\n", ip_address_str);

    if ((fd = socket(address_info->ai_family, address_info->ai_socktype, address_info->ai_protocol)) == -1)
        error(EXIT_FAILURE, errno, ANGRY("FAILED") " to get socket");

    printf("...Connecting       - ");
    fflush(stdout);

    if (connect(fd, address_info->ai_addr, address_info->ai_addrlen) == -1)
        error(EXIT_FAILURE, errno, ANGRY("FAILED") " to connect");

    printf(HAPPY("Done!") "\n");
    printf("...Sending request  - ");
    fflush(stdout);

    // request a test page

    snprintf(http_buffer, sizeof(http_buffer)-1, http_request, program_name);
    http_buffer[sizeof(http_buffer)-1]=0;

    pos=0;
    length=strlen(http_buffer);

    while (pos < length)
    {
        if ((count=write(fd, http_buffer+pos, length - pos)) == -1)
        {
            if (errno == EINTR)
                continue;

            error(EXIT_FAILURE, errno, ANGRY("FAILED") " to send request");
        }

        pos+=count;
    }

    printf(HAPPY("Done!") "\n");
    printf("...Getting response - ");
    fflush(stdout);

    // read the response

    pos=0;
    do
    {
        if ((count=read(fd, http_buffer+pos, sizeof(http_buffer)-1-pos)) == -1)
        {
            if (errno == EINTR)
                continue;

            error(EXIT_FAILURE, errno, ANGRY("FAILED") " to read response");
        }

        pos+=count;
        http_buffer[pos]=0;

        // check for end of HTTP header

        if (strstr(http_buffer,"\r\n\r\n"))
        {
            printf(HAPPY("Done!") "\n\n");
            break;
        }
    }
    while (count);

    close(fd);
    printf(HAPPY("PASSED") " Tor connection test\n");
}

int test_if_program_is_active(char *program_name)
{
    DIR *directory;
    struct dirent* dir_info;
    char file_name[256], cmdline[256], *pos, *cmdline_name;
    int fd,count, active;

    if (!check_if_program_is_active)
    {
        printf("\n" ANGRY("WARNING") " NOT testing if [%s] is currently active.\n", program_name);
        return 0;
    }

    // a shell does not clone itself and need not be checked

    if ((strcmp(program_name, "bash") == 0) || (strcmp(program_name, "sh") == 0))
        return 0;

    active=0;

    if ((directory=opendir("/proc")) == 0)
        error(EXIT_FAILURE, errno, ANGRY("FAILED") " to open /proc directory");

    errno=0;

    while ((dir_info = readdir(directory)))
    {
        // find numeric (PID) directories containing program info

        if (dir_info->d_type != DT_DIR)
            continue;

        for (pos=dir_info->d_name; *pos && *pos >='0' && *pos <='9'; pos++){};

        if (*pos)
            continue;

        // read and test program name, read /proc/<PID>/cmdline instead of
        // /proc/<PID>/comm because comm truncates long program names

        sprintf(file_name, "/proc/%s/cmdline", dir_info->d_name);

        if ((fd=open(file_name, O_RDONLY | O_CLOEXEC)) == -1)
            error(EXIT_FAILURE, errno, ANGRY("FAILED") " to open file [%s]", file_name);

        if ((count=read(fd, cmdline, sizeof(cmdline)-1)) == -1)
        {
            if (errno == EINTR)
            {
                errno=0;
                continue;
            }

            error(EXIT_FAILURE, errno, ANGRY("FAILED") " to read file [%s]", file_name);
        }

        close(fd);
        cmdline[count]=0;

        if ((pos=strchr(cmdline,' ')))
            *pos=0;

        if ((cmdline_name=strrchr(cmdline, '/')) == 0)
            cmdline_name=cmdline;
        else
            cmdline_name++;

        if (strstr(cmdline_name, program_name))
            active++;
    }

    if (errno)
        error(EXIT_FAILURE, errno, ANGRY("FAILED") " to read directory entry");

    closedir(directory);
    return active;
}

char read_char()
{
    int c;
    struct termios old_attributes, new_attributes;

    tcgetattr(STDIN_FILENO, &old_attributes);
    new_attributes = old_attributes;
    new_attributes.c_lflag &= ~ICANON;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_attributes);
    c=getchar();
    tcsetattr( STDIN_FILENO, TCSANOW, &old_attributes);
    return (char) c;
}

void run_child_program(int argc, char* argv[])
{
    char c;

    test_tor_connection(argv[0]);

    if (test_if_program_is_active(argv[0]))
    {
        printf(program_is_active_warning);
        c=read_char();
        printf("\n");

        if (c != 'Y' && c != 'y')
        {
            printf(ANGRY("NOT RUNNING") BOLD(" %s") "\n", argv_to_commandline(argv));
            exit(EXIT_FAILURE);
        }
    }

    printf( "\n" HAPPY("RUNNING") BOLD(" %s") "\n", argv_to_commandline(argv));
    execute(enable_terminal_output, execvp,argv[0], argv);
}

int main(int argc, char *argv[])
{
    int argc_aorta=1;
    char **arg=argv;
    pid_t child_pid;
    int   child_status;

    if (argc == 1)
    {
        printf(usage);
        return 0;
    }

    create_net_cls_cgroup("aorta", AORTA_CGROUP_CLASSID);
    join_net_cls_cgroup("aorta");
    iptables_add_rules(aorta_rules);

    child_pid=fork();

    if (child_pid == -1)
        error(EXIT_FAILURE, errno, NULL);

    if (child_pid == 0)
    {
        new_hostname("AORTA");

        if (setuid(getuid()) == -1)
            error(EXIT_FAILURE, errno, /*VERY*/ANGRY("FAILED") " to drop privileges");

        while (*++arg)
        {
            if (**arg != '-')
                break;

            argc_aorta++;

            if (strcmp(*arg, "-h") == 0 || strcmp(*arg, "--help") == 0)
            {
                printf(usage);
                return 0;
            }

            if (strcmp(*arg, "-c") == 0)
            {
                check_tor_connection=0;
                continue;
            }

            if (strcmp(*arg, "-a") == 0)
            {
                check_if_program_is_active=0;
                continue;
            }

            if (strcmp(*arg, "-t") == 0)
            {
                enable_terminal_output=1;
                continue;
            }

            error(EXIT_FAILURE, errno, ANGRY("ERROR") " unknown command line option [%s]", *arg);
        }

        run_child_program(argc-argc_aorta, argv+argc_aorta);
    }

    waitpid(child_pid, &child_status,0);
    printf("\n" HAPPY("AORTA CLOSED ...") "\n");
    return WEXITSTATUS(child_status);
}
