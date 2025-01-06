#include <stdio.h>
#include <string.h>
#include <stdlib.h>
// extern "C"
// {
    #include "../include/libevent-server.h"
// }
// using namespace std;

// Define the type for HTTP method handlers
// typedef int (*http_handler_t)(const char *path, const char *body, size_t body_len);

// typedef struct {
//     http_handler_t handle_get;
//     http_handler_t handle_post;
//     http_handler_t handle_patch;
//     http_handler_t handle_delete;
// } server_handler_table_t;

// // Each server instance will use its own handler table.
// server_handler_table_t handler_table;
// int handle_get_program1(const char *path, const char *body, size_t body_len) {
    int handle_get_program1(UriComponents uriComp) {
    printf("Program 1 handling GET request for path:\n");
    printf("URI components:\n");
    for (size_t i = 0; i < uriComp.count; i++) {
        printf("%s\n", uriComp.components[i]);
    }
    return 0;
}

// Initialize Program 1's handlers
server_handler_table_t program1_handlers = {
    .handle_get = handle_get_program1,
    .handle_post = NULL,
    .handle_patch = NULL,
    .handle_delete = NULL,
};

// typedef struct HeaderNode {
//     char *key;
//     char *value;
//     struct HeaderNode *next;
// } HeaderNode;

int main() {
    // run("8080", "server.key", "server.crt", &program1_handlers);
    printf("Starting listener\n");
    start_server("4000", "server.key", "server.crt", &program1_handlers);
    return 0;
}