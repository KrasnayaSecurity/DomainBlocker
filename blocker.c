#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "HydroCarbon/stdfn.h"
#include "HydroCarbon/network.h"

#define FILE_OPEN_ERROR "A file failed to open.  Did you run with root?\nProcess terminating...\n"
#define HOSTS_MARKER "# DO NOT MODIFY THIS LINE OR BELOW! These entries are automatically added to prevent access to malicious sites."
#define VERSION "0.3.0"

int main(int argc, char* argv[])
{
    intro("Site Blocker", "Krasnaya Security", 2014, "MIT");
    while (1)
    {
        char* response;
        char bf_text[1024*500];
        char h_text[1024*500];
        char* h_bs;
        char* new_hosts;
        int bf_size;
        int h_size;
        char user_agent[512];
        char* user = bash("whoami");
        char* hostname = bash("hostname");

        sprintf(user_agent, "Krasnaya Security DomainBlocker - Blocked domains definitions update from %s at %s running version %s", user, hostname, VERSION);

        printf("Getting blocked domain definitions...\n");
        response = request(user_agent, "http://redsec.ru/blocked_sites.txt");

        FILE* block_file = fopen(".blocked_sites", "w+b");
        FILE* hosts = fopen("/etc/hosts", "r+b");
        FILE* hosts_tmp = fopen(".hosts", "w+b");

        // Make sure that files can be opened
        if (block_file == NULL) {
            printf(FILE_OPEN_ERROR);
            exit(0);
        }
        if (hosts == NULL) {
            printf(FILE_OPEN_ERROR);
            exit(0);
        }
        if (hosts_tmp == NULL) {
            printf(FILE_OPEN_ERROR);
            exit(0);
        }

        // Print the text of the web request to the temporary .blocked_sites file
        fprintf(block_file, "Blocked domain definitions:\n------------------------------\n%s\n------------------------------\n", response);

        // Reading .blocked_sites

        // Get the size of the file
        bf_size = getFileSize(block_file);
        //printf("The size of .blocked_sites is %d bytes.\n", bf_size);

        rewind(block_file); // Set the file position back to the beginning
        fread(bf_text, bf_size, 1, block_file); // Read the new blocked domains into a variable
        printf("%s\n", bf_text); // Print out the new blocked domains

        // Reading hosts

        h_size = getFileSize(hosts);
        //printf("The size of hosts is %d bytes.\n", h_size);

        rewind(hosts);
        fread(h_text, h_size, 1, hosts);
        //printf("%s\n", h_text);

        // Checks if the hosts file seperator is in the hosts file, allowing us to determine if the program has been run before
        if (strstr(h_text, HOSTS_MARKER) == NULL) {
            printf("The hosts file does not include my blocked domains.\n");
            strcat(h_text, "\n\n\n");
            strcat(h_text, HOSTS_MARKER);
            strcat(h_text, "|");
            printf("I have added the hosts file seperator.\n%s\n", h_text);
        }
        //printf("\n%s\n", h_text);

        // Seperate the manual and automatic hosts file parts
        h_bs = strtok(h_text, "|");
        strcat(h_bs, "|\n");
        //printf("System and user defined hosts file:\n%s\n", h_bs);

        // Print the system and custom hosts file section to .hosts
        fprintf(hosts_tmp, "%s", h_bs);
        // Transfer hosts pre seperation to new hosts variable
        new_hosts = h_bs;
        strcat(new_hosts, "\n");
        strcat(new_hosts, response);
        printf("Final content for hosts file update:\n------------------------------\n%s\n------------------------------\n", new_hosts);

        // Closing and reopening the hosts file in a different mode to write to it without appending
        fclose(hosts);
        hosts = fopen("hosts", "w");

        // Write the content to the hosts file
        //fwrite(new_hosts, 1, 1024, hosts);
        fprintf(hosts, "%s", new_hosts);

        fclose(block_file);
        fclose(hosts);
        fclose(hosts_tmp);
        printf("\n\n");
        sleep(3600);
    }
    return 0;
}
