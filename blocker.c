#include <stdio.h>
#include <string.h>
#include "stdfn.h"

#define FILE_OPEN_ERROR "A file failed to open.\nProcess terminating...\n"
#define HOSTS_MARKER "# DO NOT MODIFY THIS LINE OR BELOW! These entries are automatically added to prevent access to malicious sites."

int main(int argc, char* argv[])
{
    char* request;
    char bf_text[1024*500];
    char h_text[1024*500];
    char* h_bs;
    char* h_as;
    char* new_hosts;
    int bf_size;
    int h_size;

    intro("Site Blocker", "Krasnaya Security", 2014, "MIT");

    printf("Getting blocked domain definitions...\n");
    request = bash("curl http://redsec.ru/blocked_sites.txt");
    //printf("%s", request);

    FILE* block_file = fopen(".blocked_sites", "w+b");
    FILE* hosts = fopen("hosts", "r+b");
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
    fprintf(block_file, "%s", request);

    // Reading .blocked_sites

    // Get the size of the file
    bf_size = getFileSize(block_file);
    printf("The size of .blocked_sites is %d bytes.\n", bf_size);

    rewind(block_file); // Set the file position back to the beginning
    fread(bf_text, bf_size, 1, block_file); // Read the new blocked domains into a variable
    printf("%s\n", bf_text); // Print out the new blocked domains

    // Reading hosts

    h_size = getFileSize(hosts);
    printf("The size of hosts is %d bytes.\n", h_size);

    rewind(hosts);
    fread(h_text, h_size, 1, hosts);
    printf("%s\n", h_text);

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
    printf("System and user defined hosts file:\n%s\n", h_bs);

    // Print the system and custom hosts file section to .hosts
    fprintf(hosts_tmp, "%s", h_bs);
    // Transfer hosts pre seperation to new hosts variable
    new_hosts = h_bs;
    strcat(new_hosts, "\n");
    strcat(new_hosts, request);
    printf("Final content for hosts file:\n%s\n", new_hosts);

    // Closing and reopening the hosts file in a different mode to write to it without appending
    fclose(hosts);
    hosts = fopen("hosts", "w");

    // Write the content to the hosts file
    //fwrite(new_hosts, 1, 1024, hosts);
    fprintf(hosts, "%s", new_hosts);

    fclose(block_file);
    fclose(hosts);
    fclose(hosts_tmp);
    return 0;
}
