#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

typedef struct myStructure {
    char *name;
    int level;
    int hitpoints;
} character;

char globalStr[13] = "NotRealToken";
character player;

char intro[] = "                \\||/\n"
"                |  @___oo\n"
"      /\\  /\\   / (__,,,,|\n"
"     ) /^\\) ^\\/ _)\n"
"     )   /^\\/   _)\n"
"     )   _ /  / _)\n"
" /\\  )/\\/ ||  | )_)\n"
"<  >      |(,,) )__)\n"
" ||      /    \\)___)\\\n"
" | \\____(      )___) )___\n"
"  \\______(_______;;; __;;;\n"
" <=======(==0 DRAGON DUNGEON 0==)=======> \n"
"    (Enter help for available actions)\n";
//Ascii art from https://www.asciiart.eu/mythology/dragons

int
menuPrompt (int n, ...)
{
    va_list l;
    char buf[10];
    int choice = 0;
    va_start (l, n);

    //Get user input
    printf ("\nAction: ");
    fgets (buf, 35 + 5, stdin);
    buf[strcspn(buf, "\n")] = 0; //Clear new line
    puts ("");

    if(strncmp(buf, "help", 4) == 0){
        for (int i = 0; i < n; i++)
        {
            char *a = va_arg (l, char *);
            if(a == 0){
                printf("------\n"); //Print a break to separate various menu items 
            }else{
                printf ("%s\n", a);
            }
        }
    }
    else{
        int len = strlen(buf);
        for (int i = 0; i < n; i++)
        {
            char *a = va_arg (l, char *);
            if(a == 0) continue; // Ignore if break
            if(len > 0 && strncmp(a, buf, len) == 0){
                return i + 1;
            }
        }
    }

    va_end (l);
    return choice;
}

int getName(character *player){
    int choice = menuPrompt(1, "name: Declare your name brave hero\n");

    if(choice == 1){
        //Get user input
        printf ("Name: ");
        fgets (player->name, 50, stdin);
        player->name[strcspn(player->name, "\n")] = 0; //Clear new line
        puts ("");
    }

    return choice;
}

int firstLevel(character *player){
    int choice = menuPrompt(4, 
        "move: Your destiny awaits...", 
        0x0,
        "ponder: Consider your fate...", 
        "run: The sun filters in from the cave entrance behind you...");
    if(choice == 1) {
        printf("TODO: Add an epic venture through caves, levelling up fighting goblins, then an even more epic boss fight with the dragon. Add lots of RPG choices. Gonna be great!\n");
        exit(0);
    }
    else if(choice == 3){
        printf("You think back and ponder to yourself... Who am I again?\n");
        while(!getName(player)){/*Pass*/};
        printf("Your name is %s, captain of the guard and heir to the throne of the kingdom Fantasalia.\n", player->name);
        printf("A vile dragon has recently moved into the mountain nearby, threatening your people.\n");
        printf("After a long march to the Dragon King's layer, you've finally arrived.\n");
        printf("Exhausted, but determined, you lift up your sword and continue into the cave.\n");
    }
    else if(choice == 4){
        printf("Yeah, that's a probably wise choice.\n");
        printf("After once again making the long trek back to the kingdom, you return to find the dragon has destroyed everything.\n");
        printf("The people curse your name, and you are exiled as %s the cowardly...\n", player->name);
        exit(0);
    }
    return choice;
}


int main(int argc, char** argv){
    char playerName[100] = "Arthur";
    player.name = playerName;
    player.level = 1;
    player.hitpoints = 10;
    setbuf(stdout, NULL);

    //Dump memory addresses
    FILE *fp;
    fp = fopen("/home/user/pointers.txt", "w"); 

    if (fp == NULL) {
        printf("Error opening file!\n");
        return -1;
    }

    fprintf(fp, "%#llx\n", (unsigned long long)playerName);
    fprintf(fp, "%#llx\n", (unsigned long long)&player);

    fclose(fp);


    printf("%s", intro);    
    while(firstLevel(&player) != 1){/*pass*/};
}
