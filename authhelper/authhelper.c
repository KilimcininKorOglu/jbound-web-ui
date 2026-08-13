/*
 * unbound-web-authhelper: the only privileged part of the panel.
 *
 * Installed setuid root, mode 4750, owner root:unbound-web, so only the panel
 * service account can run it. It authenticates one local account through PAM
 * and reports the facts the panel applies its policy to.
 *
 * Contract:
 *   argv[1]  username
 *   stdin    password, one trailing newline is dropped
 *   stdout   on success: uid=1001 gid=1001 user=x shell=/bin/bash groups=a,b
 *   exit     0 authenticated, 1 bad password, 2 account rejected, 3 usage
 *
 * The password never reaches stdout, stderr, argv or the environment.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <regex.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EXIT_OK 0
#define EXIT_AUTH 1
#define EXIT_ACCOUNT 2
#define EXIT_USAGE 3

#define MAX_PASSWORD 1024
#define MAX_GROUPS 64

extern char **environ;

static char password[MAX_PASSWORD + 1];

static void wipe_password(void) { explicit_bzero(password, sizeof(password)); }

static void fail(int code, const char *message) {
    fprintf(stderr, "authhelper: %s\n", message);
    wipe_password();
    exit(code);
}

/* Answers the PAM prompts. Info and error messages are dropped, because
 * forwarding them would leak whether an account exists. */
static int converse(int count, const struct pam_message **messages,
                    struct pam_response **responses, void *appdata) {
    (void)appdata;
    if (count <= 0) return PAM_CONV_ERR;

    struct pam_response *replies = calloc((size_t)count, sizeof(*replies));
    if (replies == NULL) return PAM_BUF_ERR;

    for (int i = 0; i < count; i++) {
        if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            replies[i].resp = strdup(password);
            if (replies[i].resp == NULL) {
                free(replies);
                return PAM_BUF_ERR;
            }
        }
    }
    *responses = replies;
    return PAM_SUCCESS;
}

static void read_password(void) {
    size_t len = 0;
    ssize_t got;
    while (len < MAX_PASSWORD &&
           (got = read(STDIN_FILENO, password + len, MAX_PASSWORD - len)) > 0) {
        len += (size_t)got;
    }
    if (len > 0 && password[len - 1] == '\n') len--;
    password[len] = '\0';
}

static void check_username(const char *name) {
    regex_t re;
    if (regcomp(&re, "^[a-z_][a-z0-9_-]\\{0,31\\}$", 0) != 0)
        fail(EXIT_USAGE, "cannot compile the username pattern");
    int rc = regexec(&re, name, 0, NULL, 0);
    regfree(&re);
    if (rc != 0) fail(EXIT_USAGE, "username rejected by the pattern");
}

/* Prints the account facts the panel applies its policy to. Group names are
 * resolved here so the Go binary needs no NSS and stays free of cgo. */
static void print_account(const char *name) {
    struct passwd *pw = getpwnam(name);
    if (pw == NULL) fail(EXIT_ACCOUNT, "account not found after authentication");

    gid_t groups[MAX_GROUPS];
    int ngroups = MAX_GROUPS;
    if (getgrouplist(name, pw->pw_gid, groups, &ngroups) < 0) ngroups = MAX_GROUPS;

    printf("uid=%u gid=%u user=%s shell=%s groups=", (unsigned)pw->pw_uid,
           (unsigned)pw->pw_gid, pw->pw_name, pw->pw_shell ? pw->pw_shell : "");
    for (int i = 0; i < ngroups; i++) {
        struct group *gr = getgrgid(groups[i]);
        if (gr == NULL) continue;
        printf("%s%s", i == 0 ? "" : ",", gr->gr_name);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    /* A setuid binary must not trust anything it inherited. */
    environ = NULL;
    umask(077);

    if (argc != 2) fail(EXIT_USAGE, "usage: unbound-web-authhelper <username>");
    const char *username = argv[1];
    check_username(username);

    read_password();
    if (password[0] == '\0') fail(EXIT_AUTH, "empty password");

    struct pam_conv conv = {converse, NULL};
    pam_handle_t *pamh = NULL;

    int rc = pam_start("unbound-web", username, &conv, &pamh);
    if (rc != PAM_SUCCESS) fail(EXIT_USAGE, "pam_start failed");

    rc = pam_authenticate(pamh, 0);
    if (rc != PAM_SUCCESS) {
        pam_end(pamh, rc);
        fail(EXIT_AUTH, "authentication failed");
    }

    /* Locked and expired accounts are rejected here, not by pam_authenticate,
     * which is why this call can never be skipped. */
    rc = pam_acct_mgmt(pamh, 0);
    if (rc != PAM_SUCCESS) {
        pam_end(pamh, rc);
        fail(EXIT_ACCOUNT, "account rejected");
    }

    pam_end(pamh, PAM_SUCCESS);
    wipe_password();

    print_account(username);
    return EXIT_OK;
}
