#include <stdio.h>

#include "../inc/teep_generate_key_pair.h"

int main(void){
    teep_err_t          result;
    teep_mechanism_t mechanism_sign;

    result = teep_generate_es256_key_pair(&mechanism_sign.key, NULLUsefulBufC);

    

}


