// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

// nines is a galactic blackjack game!
//
// It's simplified, and goes to 9 instead of 21
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

const char* PASS = "/home/gyre/managerpass.txt";

int get_file(char *cashfile) {
	FILE* cash = fopen(cashfile, "r");
	char line[50];
	fgets(line, 50, cash);
	printf("%s\n", line);
	fclose(cash);
	return atoi(line);
}

void write_file(char *cashfile, int bank) { 
	FILE* cash = fopen(cashfile, "w");
	fprintf(cash, "%d", bank);
	fclose(cash);
}

int gen_random_card(){ 
        srand(time(0)); 
        int card = rand() %6 + 1; 
	if (card > 5){ 
		card = 4;
	}
        return card;
}

int slap(int count){ 

	int new_count = count + gen_random_card();
        printf("The count is %d\n", new_count);
	sleep(1);
	return new_count;
}

int play_game(){ 
	int user_count = 0; 
	int dealer_count = 0; 
	int slap_or_sit = 0; 
	
	printf("\nFor player:\n"); 
	user_count = slap(user_count);
	user_count = slap(user_count);

	printf("\nFor Dealer:\n"); 
	dealer_count = slap(dealer_count);

	printf("\nFor Player: Slap (0) or Sit (1)?: "); 
	scanf("%d", &slap_or_sit);
	getchar();
	while (slap_or_sit == 0) {
		user_count = slap(user_count); 

		if (user_count > 9) {
                        printf("Blast! You Lose!");
                        return 1;
                }

		printf("Slap (0) or Sit (1)?: "); 
	        scanf("%d", &slap_or_sit);
		getchar();
	}

	printf("\nDealer's play:\n"); 
	while (dealer_count < 8) { 
		dealer_count = slap(dealer_count);
		if (dealer_count > 10) { 
			printf("Dealer blasts! You Win!");
			return 2;
		}
	}

	if (user_count > dealer_count) { 
		printf("You Win!");
		return 2;
	}
	else if (user_count < dealer_count){
		printf("You Lose!");
		return 1;
	}
	else {
		printf("Draw!");
		return 0;
	}
}

int main(){
	printf("Welcome to Nines!\n\n");

	char play_again[10] = "yes\n"; 
	int bank = 0; 
	int outcome = 0; 
	int wager = 0; 
	
	printf("\nCurrent Funds: ");
	bank = get_file("cash"); 
	while (strcmp(play_again, "yes\n") == 0) { 
		printf("Bet: ");
		scanf("%d", &wager); 
		getchar();
		while (wager < 1) { 
			printf("You have to make a positive bet: ");
			scanf("%d *[^\n]", &wager);
			getchar();
		}
		outcome = play_game(); 
		if (outcome == 1) { 
			bank = bank - wager;
		}
		else if (outcome == 2) { 
			bank = bank + wager;
		}
		printf("\nCurrent Funds: %d", bank);
		write_file("cash", bank); 
		printf("\n\nType yes to play again: "); 
		fgets(play_again, 100, stdin); 
	}
}
