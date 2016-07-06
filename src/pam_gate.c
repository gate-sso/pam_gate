// standard stuff
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>


// pam stuff
#include <security/pam_modules.h>

// libcurl
#include <curl/curl.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    //printf("Acct mgmt\n");
    return PAM_SUCCESS;
}

struct gate_response_string {
    char *ptr;
    size_t len;
};

void init_string(struct gate_response_string *s) {
    s->len = 0;
    s->ptr = malloc(s->len + 1);
    if (s->ptr == NULL) {
        fprintf(stderr, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }
    s->ptr[0] = '\0';
}

/*
 * Makes getting arguments easier. Accepted arguments are of the form: name=value
 *
 * @param pName- name of the argument to get
 * @param argc- number of total arguments
 * @param argv- arguments
 * @return Pointer to value or NULL
 */
static const char *getArg(const char *pName, int argc, const char **argv) {
    int len = strlen(pName);
    int i;

    for (i = 0; i < argc; i++) {
        if (strncmp(pName, argv[i], len) == 0 && argv[i][len] == '=') {
            // only give the part url part (after the equals sign)
            return argv[i] + len + 1;
        }
    }
    return 0;
}

/*
 * Function to handle stuff from HTTP response.
 *
 * @param buf- Raw buffer from libcurl.
 * @param len- number of indices
 * @param size- size of each index
 * @param userdata- any extra user data needed
 * @return Number of bytes actually handled. If different from len * size, curl will throw an error
 */
static int writeFn(void *buf, size_t len, size_t size, struct gate_response_string *s) {

    size_t new_len = s->len + len * size;
    s->ptr = realloc(s->ptr, new_len + 1);
    if (s->ptr == NULL) {
        fprintf(stderr, "realloc() failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(s->ptr + s->len, buf, size * len);
    s->ptr[new_len] = '\0';
    s->len = new_len;


    return len * size;
}


static int getUrlWithUser(const char *pUrl, const char *pCaFile) {

    CURL *pCurl = curl_easy_init();
    int res = -1;


    if (!pCurl) {
        return 0;
    }

    struct gate_response_string s;
    init_string(&s);

    //printf("URL: %s\n", pUrl);

    curl_easy_setopt(pCurl, CURLOPT_URL, pUrl);
    curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, writeFn);
    curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &s);

    //curl_easy_setopt(pCurl, CURLOPT_USERPWD, pUserPass);
    curl_easy_setopt(pCurl, CURLOPT_NOPROGRESS, 1); // we don't care about progress
    curl_easy_setopt(pCurl, CURLOPT_FAILONERROR, 1);
    // we don't want to leave our user waiting at the login prompt forever
    curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, 1);

    // SSL needs 16k of random stuff. We'll give it some space in RAM.
    curl_easy_setopt(pCurl, CURLOPT_RANDOM_FILE, "/dev/urandom");
    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2);
    curl_easy_setopt(pCurl, CURLOPT_USE_SSL, CURLUSESSL_ALL);




    // synchronous, but we don't really care
    res = curl_easy_perform(pCurl);
    curl_easy_cleanup(pCurl);
    //printf("Res: %s\n", s.ptr);
    //printf("Res Integer: %d\n", atoi(s.ptr));


    res = atoi(s.ptr);

    //printf("Result %s Length %d\n", s.ptr, (int)strlen(s.ptr));
    if (strlen(s.ptr) > 2 || strlen(s.ptr) < 1)
        res = 1;

    return res;
}

int get_ip_addresses(char **addresses) {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;
    char ip_addresses[100][20];
    getifaddrs(&ifap);
    int addr_counter = 0;
    int addr_mem = 0;
    char *ip_fmt_str;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            if (strncmp(addr, (const char *) "127.0.0.1", strlen("127.0.0.1"))) {
                strcpy(ip_addresses[addr_counter], addr);
                addr_counter++;
            }

        }
    }

    addr_mem = (16 * addr_counter) + 1;
    ip_fmt_str = (char *) malloc(addr_mem);
    *addresses = (char *) malloc(addr_mem);
    memset(ip_fmt_str, 0, addr_mem);

    //strcat(ip_fmt_str, (const char *) "[");


    for (int count = 0; count < addr_counter; count++) {
        //strcat(ip_fmt_str, (const char *) "\"");
        strcat(ip_fmt_str, (const char *) ip_addresses[count]);
        //strcat(ip_fmt_str, (const char *) "\"");
        strcat(ip_fmt_str, (const char *) ",");
    }
    ip_fmt_str[strlen(ip_fmt_str) - 1] = '\0';
    //printf("returning ip_fmt_str %s\n", ip_fmt_str);
    strcpy(*addresses, ip_fmt_str);
    free(ip_fmt_str);
    freeifaddrs(ifap);
    //printf("returning addr_counter %s\n", *addresses);
    return addr_counter;
}


/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int ret = 0;

    const char *pUsername = NULL;
    const char *pUrl = NULL;
    const char *pCaFile = NULL;

    char pUrlWithUser[1000];

    struct pam_message msg;
    struct pam_conv *pItem;
    struct pam_response *pResp;
    const struct pam_message *pMsg = &msg;

    char *ip_addresses;

    int print_debug = 0;


    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = "Password: ";


    if (pam_get_user(pamh, &pUsername, NULL) != PAM_SUCCESS) {
        fprintf(stderr, "Gate Pam authentication - can't get user\n");
        return PAM_AUTH_ERR;

    }

    pUrl = getArg("url", argc, argv);
    if (!pUrl) {
        fprintf(stderr, "Gate Pam authentication - don't know the URL for host\n");
        return PAM_AUTH_ERR;
    }

    pCaFile = getArg("cafile", argc, argv);
    if (pam_get_item(pamh, PAM_CONV, (const void **) &pItem) != PAM_SUCCESS || !pItem) {
        fprintf(stderr, "Couldn't get pam_conv\n");
        return PAM_AUTH_ERR;
    }

    pItem->conv(1, &pMsg, &pResp, pItem->appdata_ptr);

    ret = PAM_SUCCESS;

    memset(pUrlWithUser, 0, 1000);

    get_ip_addresses(&ip_addresses);

    sprintf(pUrlWithUser, "%s/?user=%s&password=%s&addresses=%s", pUrl, pUsername, pResp[0].resp, ip_addresses);

    if (print_debug)
        printf("got ip addresses %s\n", ip_addresses);

    free(ip_addresses);
    if (print_debug)
        printf("URL %s\n", pUrlWithUser);
    if (getUrlWithUser(pUrlWithUser, pCaFile) != 0) {
        ret = PAM_AUTH_ERR;
    }
    /*if (getUrl(pUrl, pUsername, pResp[0].resp, pCaFile) != 0) {
        printf("Gate Pam authentication - Sorry I can't do this.\n");
        ret = PAM_AUTH_ERR;
    }*/
    memset(pResp[0].resp, 0, strlen(pResp[0].resp));
    free(pResp);

    return ret;
}
