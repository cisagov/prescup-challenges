#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>

void logerr(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fflush(stderr);
}

#ifndef USE_COLOR
#define USE_COLOR 1
#endif

static void render_intro(const char *s)
{
#if USE_COLOR
    fputs("\033[0;32m", stdout); /* green */
#endif
    fputs(s, stdout);
#if USE_COLOR
    fputs("\033[0m", stdout); /* reset */
#endif
}

static const char *INTRO_WOPR_DEFCON =
    "============================================================\n"
    "                    W.O.P.R. MAINFRAME                      \n"
    "               GLOBAL THERMONUCLEAR WAR MODULE              \n"
    "============================================================\n"
    " SYSTEM STATUS: ONLINE   |  SITE-LINK: STANDBY  |  AUTH: ---\n"
    "------------------------------------------------------------\n"
    "  DEFCON  | 5 | 4 | 3 | 2 | 1 |\n"
    "          |   |   |   |   | # |\n"
    "------------------------------------------------------------\n"
    "  TARGETING NETWORK: ROUTE=CONUS  ROUTERS=12  LATENCY=7ms\n"
    "  STRATEGY SEED: 0x5EEDC0DE  EVALS/SEC: 011,274\n"
    "------------------------------------------------------------\n"
    "                     . . .  . .   .   .                     \n"
    "                 .       .    .        .    .               \n"
    "        _|_                .      .              .          \n"
    "   __--=====--__     .           .      .                   \n"
    "  /__ --------  \\             .        .         .          \n"
    "  || |  |  | |  |  _  _  _  _  _  _  _  _  _  _  _          \n"
    "  ||_|__|__|_|__| |_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|          \n"
    "  |________________|_______________________________        \n"
    "      \\\\   \\\\    \\\\        ////      ////      ////        \n"
    "       \\\\   \\\\    \\\\  -->  ////  --> ////  --> ////        \n"
    "        \\\\   \\\\    \\\\      ////      ////      ////         \n"
    "------------------------------------------------------------\n"
    " NOTE: Unauthorized access will be logged.\n"
    " TYPE 'help' FOR COMMANDS.\n"
    "------------------------------------------------------------\n";

void printToken(void)
{
    logerr("Inside printToken!\n");
    FILE *fp = fopen("/app/functionToken.txt", "r");
    if (!fp)
    {
        logerr("Could not open function token file.\n");
        return;
    }

    int c;
    while ((c = fgetc(fp)) != EOF)
    {
        putchar(c);
    }

    fclose(fp);
}

/* Call this when user types the "token" command */
void handle_token_command(void)
{
    char buf[64];

    printf("Enter leaked address of printToken (e.g., 0x1234567812345678): ");
    fflush(stdout);

    int ch; // Account for any trailing new lines
    while ((ch = getchar()) == '\n')
        ;
    ungetc(ch, stdin);

    if (!fgets(buf, sizeof(buf), stdin))
    {
        printf("Input error.\n");
        logerr("Input error in handle_token_command.\n");
        return;
    }

    errno = 0;
    char *end = NULL;
    unsigned long long val = strtoull(buf, &end, 0); /* base 0 handles 0x... */

    if (errno != 0 || end == buf)
    {
        printf("Invalid address format.\n");
        return;
    }

    void *user_addr = (void *)(uintptr_t)val;
    void *real_addr = (void *)&printToken;

    logerr("Guessing %p == %p.\n", user_addr, real_addr);
    if (user_addr == real_addr)
    {
        logerr("Printing leak token\n");
        FILE *fp = fopen("/app/leakToken.txt", "r");
        if (!fp)
        {
            logerr("Could not open leak token file.\n");
            return;
        }

        int c;
        while ((c = fgetc(fp)) != EOF)
        {
            putchar(c);
        }

        fclose(fp);
    }
    else
    {
        printf("Incorrect address.\n");
    }
}

typedef struct
{
    void *prev;
    void *next;

    void *data;
} LinkedList;

typedef struct
{
    size_t size;

    char *key;
} SecurityKey;

typedef struct
{
    char mission[8];
    pthread_t thread;
    int state;
    SecurityKey *key;
} Thread;

LinkedList *ll_create(void *data)
{
    LinkedList *n = malloc(sizeof(LinkedList));
    if (!n)
        return NULL;
    n->prev = NULL;
    n->next = NULL;
    n->data = data;
    return n;
}

void ll_push_front(LinkedList **head, LinkedList *n)
{
    if (!n)
        return;

    n->prev = NULL;
    n->next = *head;

    if (*head)
        (*head)->prev = n;

    *head = n;
}

void ll_push_back(LinkedList **head, LinkedList *n)
{
    if (!n)
        return;

    if (!*head)
    {
        n->prev = NULL;
        n->next = NULL;
        *head = n;
        return;
    }

    LinkedList *cur = *head;
    while (cur->next)
        cur = cur->next;

    cur->next = n;
    n->prev = cur;
    n->next = NULL;
}

/* Intentionally buggy: leaves head dangling when removing the sole node */
void ll_remove(LinkedList **head, LinkedList *n)
{
    if (!n)
    {
        return;
    }

    if (n->prev)
    {
        ((LinkedList *)n->prev)->next = n->next;
    }
    else if (n->next)
    {
        // n is the head and has a next node: move head forward
        *head = n->next;
    }
    // else {
    //     // n is the only node in the list:
    //     // BUG: do not update *head, so it keeps pointing to n
    // }

    if (n->next)
    {
        ((LinkedList *)n->next)->prev = n->prev;
    }

    free(n);
}

void *ll_get_nth(const LinkedList *head, size_t n)
{
    const LinkedList *node = head;

    while (node != NULL && n > 0)
    {
        node = (const LinkedList *)node->next; // next is void*, so cast
        n--;
    }

    if (node == NULL)
        return NULL;

    return node->data;
}

void *load_missile_payload(size_t payload_size)
{
    int fd;
    ssize_t n;
    size_t total = 0;
    unsigned char *buf;

    if (payload_size == 0)
    {
        return NULL;
    }

    buf = malloc(payload_size);
    if (!buf)
    {
        return NULL;
    }

    fd = open("/devices/clearance_codes", O_RDONLY);
    if (fd < 0)
    {
        free(buf);
        return NULL;
    }

    while (total < payload_size)
    {
        n = read(fd, buf + total, payload_size - total);
        if (n <= 0)
        {
            // read error or EOF – abort
            close(fd);
            free(buf);
            return NULL;
        }
        total += (size_t)n;
    }

    close(fd);
    return buf;
}

void printThreadStatus(Thread *t)
{
    if (!t)
    {
        return;
    }
    printf("%4s: ", t->mission);

    switch (t->state)
    {
    case 0:
        puts("Request processing");
        break;
    case 1:
        puts("Waking missile system");
        break;
    case 2:
        puts("Verifying clearance codes");
        break;
    case 3:
        puts("Launching...");
        break;
    case 4:
        puts("Launch completed or aborted");
        break;
    default:
        puts("Unknown");
        break;
    }
}

void *launch_missile(void *arg)
{
    Thread *thread = (Thread *)arg;

    // Step 1
    //  Wake missile system
    thread->state = 1;
    sleep((rand() % 5) + 1);

    // Step 2
    //  Checking clearance code
    thread->state = 2;
    sleep((rand() % 3) + 1);
    if (thread->key == NULL || thread->key->key == NULL)
    {
        thread->state = 4;
        return NULL;
    }

    // Step 3
    //  Launch missile
    thread->state = 3;
    sleep((rand() % 10) + 5);

    // Step 4 terminated
    thread->state = 4;

    return NULL;
}

void *addKey(size_t payload_size)
{
    LinkedList *newNode = ll_create(NULL);
    SecurityKey *key = (SecurityKey *)malloc(sizeof(SecurityKey));
    char *payload = (char *)load_missile_payload(payload_size);

    if (!key || !payload || !newNode)
    {
        logerr("Could not allocate key\n");
        return NULL;
    }

    // printf("Key address: %p\n", key);

    key->key = payload;
    key->size = payload_size;
    newNode->data = key;

    return newNode;
}

int deleteKey(LinkedList *keyNode)
{
    // printf("Keys/Next: %p %p %p %p\n", &keys, keys, next, keys->next );
    free(((SecurityKey *)keyNode->data)->key);
    // printf("Key: %p\n", keyNode->data);
    free(keyNode->data);
}

void *prepareLaunch(SecurityKey *key)
{
    LinkedList *newNode = ll_create(NULL);
    Thread *thread = (Thread *)malloc(sizeof(Thread));

    if (!thread || !newNode)
    {
        logerr("Could not approve missile launch\n");
        return NULL;
    }

    // printf("Thread address: %p\n", thread);

    newNode->data = thread;
    thread->state = 0;

    printf("4-char mission identifier: ");
    scanf("%4s", thread->mission);

    thread->key = key;

    return newNode;
}

LinkedList *removeThreadIfDone(LinkedList **head, LinkedList *remove)
{
    if (!remove)
    {
        return NULL;
    }
    Thread *t = (Thread *)remove->data;
    LinkedList *next = remove->next;
    if (t->state >= 4)
    {
        free(t);
        ll_remove(head, remove);
        if (*head == remove)
        {
            *head = NULL;
        }
    }

    return next;
}

void dump_help()
{
    printf("loadkey - Checks for authorization to launch\n");
    printf("clearkey - Relinquish claimed authorization codes\n");
    printf("launch - Launch missile system\n");
    printf("help - Prints this message\n");
    printf("quit - Exit after all missiles complete\n");
}

// REMOVE
//  static void hexdump(const void *base, size_t n)
//  {
//      const unsigned char *p = base;
//      for (size_t i = 0; i < n; i += 16)
//      {
//          printf("%04zx  ", i);
//          for (size_t j = 0; j < 16 && i + j < n; ++j)
//              printf("%02x ", p[i + j]);
//          printf(" |");
//          for (size_t j = 0; j < 16 && i + j < n; ++j)
//          {
//              unsigned char c = p[i + j];
//              putchar((c >= 32 && c < 127) ? c : '.');
//          }
//          puts("|");
//      }
//  }

// REMOVE
//  static int get_libc_range(uintptr_t *start_out, uintptr_t *end_out)
//  {
//      FILE *fp = fopen("/proc/self/maps", "r");
//      if (!fp)
//          return -1;

//     char line[512];
//     uintptr_t start = 0, end = 0;
//     int found = 0;

//     while (fgets(line, sizeof(line), fp)) {
//         // Example line:
//         // 7f2b6d4a6000-7f2b6d667000 r-xp 00000000 fd:01 123456 /lib/x86_64-linux-gnu/libc-2.31.so
//         if (strstr(line, "libc") == NULL)
//             continue;

//         if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
//             found = 1;
//             break;
//         }
//     }

//     fclose(fp);

//     if (!found)
//         return -1;

//     if (start_out) *start_out = start;
//     if (end_out)   *end_out   = end;
//     return 0;
// }

int main(void)
{
    setbuf(stdout, NULL);
    srand((unsigned)time(NULL));
    LinkedList *threads = NULL;
    LinkedList *keys = NULL;
    int num_threads = 0;

    struct WriteReq
    {
        size_t idx;
        unsigned int val;
    } queue[20];

    int queued = 0;

    // printf("System: %p", &system);

    for (int i = 0; i < 1; i++)
    {
        void *newNode = addKey(1000);
        ll_push_front(&keys, newNode);
    }

    render_intro(INTRO_WOPR_DEFCON);

    for (;;)
    {
        char input[20] = "\0";

        printf("\n\n> ");
        if (scanf("%10s", input) != 1)
        {
            continue;
        }

        if (strcmp(input, "quit") == 0)
        {
            break;
        }

        if (strcmp(input, "help") == 0)
        {
            dump_help();
        }

        if (strcmp(input, "loadkey") == 0)
        { 
            // Load a new key
            size_t payload_size;
            printf("Payload size: ");
            if (scanf("%zu", &payload_size) != 1)
                break;
            void *newNode = addKey(payload_size);
            ll_push_front(&keys, newNode);
        }

        if (strcmp(input, "clearkey") == 0)
        {
            // Clear the oldest added key
            LinkedList *next = keys;
            if (!next)
            {
                continue;
            }

            while (next->next != NULL)
            {
                next = next->next;
            }

            deleteKey(next);
            ll_remove(&keys, next);
            // printf("Keys/Next: %p %p %p\n", &keys, keys, next);
        }

        if (strcmp(input, "launch") == 0)
        {
            ll_push_front(&threads, prepareLaunch(keys->data));

            pthread_create(&(((Thread *)threads->data)->thread), NULL, launch_missile, threads->data);
            num_threads++;
            // Note if you enable the printing, the exploit definitely won't work. Still useful for debugging!
            // printf("Thread: %p\n", (((Thread *)threads->data)->thread));
            // printf("Key/size: %p 0x%x\n", (((SecurityKey *)keys->data)->key), ((SecurityKey *)keys->data)->size);
            // printf("Libc: %p 0x%x\n", (((SecurityKey *)keys->data)->key), ((SecurityKey *)keys->data)->size);
            // uintptr_t libc_start, libc_end;
            // if (get_libc_range(&libc_start, &libc_end) == 0) {
            //     printf("libc range: [%p - %p) (size: 0x%zx)\n",
            //         (void *)libc_start,
            //         (void *)libc_end,
            //         (size_t)(libc_end - libc_start));
            // } else {
            //     printf("Could not find libc mapping\n");
            // }
            // printf("System: %p\n", &system);
        }

        if (strcmp(input, "debugdump") == 0)
        {
            SecurityKey *key = ((SecurityKey *)keys->data);
            for (int i = 0; i < key->size; i++)
            {
                printf("%c", key->key[i]);
            }
            // printf("Key/size: %p 0x%x\n", (key->key), key->size);
            // hexdump((void *) &(key->key), key->size);
        }

        if (strcmp(input, "debugpatch") == 0)
        {
            if (queued >= 20)
            {
                puts("Write queue full");
                continue;
            }

            printf("Index: ");
            if (scanf("%zu", &queue[queued].idx) != 1)
                break;

            printf("Value (0-255): ");
            if (scanf("%u", &queue[queued].val) != 1)
                break;

            queued++;
            continue; // Allow writes to be queued
        }

        if (strcmp(input, "token") == 0)
        {
            handle_token_command();
        }

        // Apply all queued writes AFTER possible thread creation
        for (int i = 0; i < queued; i++)
        {
            if (keys && queue[i].idx < ((SecurityKey *)keys->data)->size)
            {
                // Same as before, printing here will delay and cause the exploit to fail, but still useful
                // printf("Writing %p %d\n", ((SecurityKey *)keys->data)->key + queue[i].idx, (unsigned char)queue[i].val);
                ((SecurityKey *)keys->data)->key[queue[i].idx] = (unsigned char)queue[i].val;
            }
        }
        // if(queued != 0){
        //     printf("Got %p %p\n", ((SecurityKey *)keys->data)->key, *((SecurityKey *)keys->data)->key);
        //     printf("Got %p %p\n", ((SecurityKey *)keys->data)->key + 8, *(((SecurityKey *)keys->data)->key + 8));
        // }
        queued = 0;

        LinkedList *next = threads;
        while (next != NULL)
        {
            printThreadStatus((Thread *)next->data);
            next = removeThreadIfDone(&threads, next);
        }
    }

    LinkedList *next = threads;
    while (next != NULL)
    {
        pthread_join(((Thread *)next->data)->thread, NULL);
        next = next->next;
    }
}
