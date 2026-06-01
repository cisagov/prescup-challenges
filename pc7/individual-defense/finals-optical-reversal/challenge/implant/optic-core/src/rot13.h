
#pragma once
static inline char r13(char c){
    if('a'<=c && c<='z') return (char)('a'+((c-'a'+13)%26));
    if('A'<=c && c<='Z') return (char)('A'+((c-'A'+13)%26));
    return c;
}
