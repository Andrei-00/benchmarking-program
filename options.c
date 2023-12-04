#include "options.h"
#include "stdio.h"
#include "string.h"
#include "time.h"
#include "math.h"
#include "AES_128/TI_aes_128.h"
#include "SHA_256/sha2.h"
#include "huffman/huffman.h"

#define BUFF_COMMAND_SIZE 4096
#define BUFF_SIZE 1024
#define AES_BLOCK_SIZE 16
#define GET_TIME (float)clock()/CLOCKS_PER_SEC

void processor_type();

void processor_frequency();

void mem_size();

void data_transfer();

void generate_file();

void generate_file_buffer();

void copy_one();

void copy_buffer();

void operations_speed();

void aes_benchmark();

__uint32_t* convert_to_sha_message();

void sha_256_benchmark();

void huffman_benchmark();

void benchmark();

void operations();

void handle_command_error();

void status_error(const char *command);

void continue_to_options();

void read_dummy_char();

void print_hex_string(unsigned char *s);

float weights[4] = {0.1, 0.2, 0.5, 0.2};

float times[4];

void option() {

    unsigned char opt_nr_user;
    int done = 0;

    while(1) {
        system("clear");

        printf("Alegeti una din urmatoarele optiuni:\n");
        printf("1. Tip procesor\n");
        printf("2. Frecventa procesor\n");
        printf("3. Dimensiune memorie\n");
        printf("4. Viteza transfer bloc de date\n");
        printf("5. Viteza executie operatii aritmetico logice\n");
        printf("6. Calcularea scorului de benchmark\n");
        printf("0. Exit\n");
        printf("Introduceti numarul optiunii: ");

        scanf("%c", &opt_nr_user);
        printf("\n");
        switch(opt_nr_user) {
            case '1':
                system("clear");
                printf("Tip procesor\n");
                processor_type();
            break;

            case '2':
                system("clear");
                printf("Frecventa procesor\n");
                processor_frequency();
                break;
            
            case '3':
                system("clear");
                printf("Dimensiune memorie\n");
                mem_size();
                break;

            case '4':
                system("clear");
                printf("Viteza transfer bloc de date\n");
                data_transfer();
                break;
            
            case '5':
                system("clear");
                printf("Viteza executie operatii aritmetico logice\n");
                operations_speed();
                break;
            
            case '6':
                system("clear");
                printf("Score Benchmark\n");
                benchmark();
                break;
            case '0':
                done = 1;
                break;

            default:
                printf("Introduceti o optiune valida!\n");
            break;
        }
        
        if(done == 1) {
            break;
        }

       read_dummy_char();
    }
   
}

void processor_type() {

    FILE *cmd, *fp;
    int status;
    char buff[BUFF_COMMAND_SIZE];

    fp = fopen("temp", "w");
    cmd = popen("cat /proc/cpuinfo | grep -m 1 -P \"model name\"", "r");
    if (cmd == NULL) {
        printf("Eroare executie comanda de sistem\n");
        return;
    }

    while (fgets(buff, BUFF_COMMAND_SIZE, cmd) != NULL)
    {
        printf("%s", buff);
    }
    
    status = pclose(cmd);

    if(status == -1) {
        status_error("cat or grep");
    }

    fclose(fp);
    continue_to_options();
}

void processor_frequency() {
    FILE *cmd, *fp;
    int status;
    char buff[BUFF_COMMAND_SIZE];

    fp = fopen("temp", "w");
    cmd = popen("cat /proc/cpuinfo | grep -m 1 -P \"cpu MHz\"", "r");
    if (cmd == NULL) {
        printf("Eroare executie comanda de sistem\n");
        return;
    }

    while (fgets(buff, BUFF_COMMAND_SIZE, cmd) != NULL)
    {
        printf("%s", buff);
    }
    
    status = pclose(cmd);

    if(status == -1) {
        status_error("cat or grep");
    }

    fclose(fp);
    continue_to_options();
}

void mem_size() {
    FILE *cmd, *fp;
    int status;
    char buff[BUFF_COMMAND_SIZE];

    fp = fopen("temp", "w");
    cmd = popen("cat /proc/meminfo | grep -m 1 -P \"MemTotal\"", "r");
    if (cmd == NULL) {
        printf("Eroare executie comanda de sistem\n");
        return;
    }

    while (fgets(buff, BUFF_COMMAND_SIZE, cmd) != NULL)
    {
        printf("%s", buff);
    }
    
    status = pclose(cmd);

    if(status == -1) {
        status_error("cat or grep");
    }

    fclose(fp);
    continue_to_options();
}

void data_transfer() {

    int done = 0;

    read_dummy_char();

    while (1)
    {   
        printf("Alegeti modul de copiere:\n");
        printf("1. Caracter cu caracter\n");
        printf("2. Folosind un buffer\n");
        printf("3. Folosind un pipe\n");
        unsigned char opt_nr = 0;
        scanf("%c", &opt_nr);

        switch (opt_nr)
        {
        case '1':
            generate_file();
            copy_one();
            done = 1;
            break;

        case '2':
            generate_file_buffer();
            copy_buffer();
            done = 1;
            break;

        case '3':
            generate_file();
            done = 1;
            break;

        default:
            printf("Introduceti o optiune valida!\n");
            break;
        } 

        if (done == 1)
            break;       
    }
    

    continue_to_options();
}

void generate_file() {
    
    // read_dummy_char();
    printf("Alegeti numarul de bytes al fisierului de copiat: ");
    size_t file_size;
    scanf("%lu", &file_size);
    printf("\n");
    read_dummy_char();

    float start_time = GET_TIME;

    FILE *fp;
    fp = fopen("to_copy", "wb+");
    char c = 0;
    for(int i = 0; i < file_size; i++)
        fwrite(&c, sizeof(char), 1, fp);
    fclose(fp);

    float end_time = GET_TIME;
    float elapsed_time = end_time - start_time;

    printf("Timpul scurs pentru a scrie fisierul: %f secunde\n", elapsed_time);
    times[0] = elapsed_time;
    // read_dummy_char();

}

void generate_file_buffer() {
    printf("Alegeti numarul de bytes al fisierului de copiat: ");
    size_t file_size;
    char buffer[BUFF_SIZE];
    scanf("%lu", &file_size);
    printf("\n");
    read_dummy_char();

    float start_time = GET_TIME;

    FILE *fp;
    fp = fopen("to_copy", "wb+");
    char c = 'c';
    memset(buffer, c, BUFF_SIZE);
    while (1)
    {
        if(file_size > BUFF_SIZE) {
            fwrite(buffer, sizeof(char), BUFF_SIZE, fp);
            file_size -= BUFF_SIZE;
        } else {
            fwrite(buffer, sizeof(char), file_size, fp);
            break;
        }
    }
    fclose(fp);

    float end_time = GET_TIME;
    float elapsed_time = end_time - start_time;

    printf("Timpul scurs pentru a scrie fisierul: %f secunde\n", elapsed_time);
    times[0] += elapsed_time;
    // read_dummy_char();
}

void copy_one() {
    
    // start measuring the time for the copying operation
    float start_time = GET_TIME;

    FILE *fp1, *fp2;
    fp1 = fopen("to_copy", "rb");
    fp2 = fopen("copy", "wb");

    char c;

    while(fread(&c, sizeof(char), 1, fp1) == 1) {
        fwrite(&c, sizeof(char), 1, fp2);
    }

    float elapsed_time = GET_TIME - start_time;

    fclose(fp1);
    fclose(fp2);

    printf("Timpul scurs pentru a copia fisierul: %f secunde", elapsed_time);
    times[0] += elapsed_time;
    // read_dummy_char();
}

void copy_buffer() {
    size_t size_read = 0;
    size_t size_write = 0;
    unsigned char buff[BUFF_SIZE];

    // start measuring the time for the copying operation
    float start_time = GET_TIME;

    FILE *fp1, *fp2;
    fp1 = fopen("to_copy", "rb");
    fp2 = fopen("copy", "wb");

    char c;

    while(1) {
        size_read = fread(buff, sizeof(char), BUFF_SIZE, fp1);
        if (size_read < 0) {
            printf("Eroare citire input copiere!");
        } else if (size_read == 0) {
            // eof
            break;
        } else {
            size_write = fwrite(buff, sizeof(char), size_read, fp2);   
            if (size_write <= 0) {
                printf("Eroare citire output copiere!");
                break;
            }
        }
    }

    float elapsed_time = GET_TIME - start_time;

    fclose(fp1);
    fclose(fp2);

    printf("Timpul scurs pentru a copia fisierul: %f secunde", elapsed_time);
    times[0] += elapsed_time;
}

void operations_speed() {

    int done = 0;

    read_dummy_char();

    while (1)
    {   
        printf("Alegeti tipul de test:\n");
        printf("1. Criptare/decriptare AES-128\n");
        printf("2. Hash SHA-256\n");
        printf("3. Encodare/decodare Huffman\n");
        unsigned char opt_nr = 0;
        scanf("%c", &opt_nr);

        switch (opt_nr)
        {
        case '1':
            aes_benchmark();
            done = 1;
            break;

        case '2':
            sha_256_benchmark();
            done = 1;
            break;
        
        case '3':
            huffman_benchmark();
            done = 1;
            break;

        default:
            printf("Introduceti o optiune valida!\n");
            break;
        } 

        if (done == 1)
            break;       
    }
    

    continue_to_options();
}

void aes_benchmark() {
    unsigned char state[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    unsigned char state2[] = {"\"3DUfw"};
    //unsigned char ciphertext[] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    //                              0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    
    unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    
    unsigned char key1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    unsigned char key2[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    
    //open the file to encrypt and get its size
    FILE *fp = fopen("copy", "rb");
    size_t file_size = 0;
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    //read the file in memory
    char *to_encrypt = (char*)malloc(file_size * sizeof(char));;
    char buffer[BUFF_SIZE];
    size_t size_to_go = file_size;
    size_t offset = 0;

    while(1) {
        if(size_to_go < BUFF_SIZE) {
            fread(buffer, sizeof(char), size_to_go, fp);
            memcpy(to_encrypt + offset, buffer, size_to_go);
            break;
        } else {
            fread(buffer, sizeof(char), BUFF_SIZE, fp);
            memcpy(to_encrypt + offset, buffer, BUFF_SIZE);
            offset += BUFF_SIZE;
            size_to_go -= BUFF_SIZE;        
        }
    }

    //printf("Shakespeare:\n%s", to_encrypt);

    //encrypt the file one block at a time (16 bytes)

    //start measuring the time for the encryption phase
    float start_time = GET_TIME;

    size_to_go = file_size;
    offset = 0;
    size_t encrypted_size = (ceil((double)file_size / AES_BLOCK_SIZE)) * AES_BLOCK_SIZE;

    char *encrypted = (char*)malloc(encrypted_size * sizeof(char));

    while(1) {
        if (size_to_go < AES_BLOCK_SIZE) {
            memcpy(state, to_encrypt + offset, size_to_go);
            aes_enc_dec(state, key1, 0);
            memcpy(key1, key, AES_BLOCK_SIZE);
            memcpy(encrypted + offset, state, AES_BLOCK_SIZE);
            break;
        } else {
            memcpy(state, to_encrypt + offset, AES_BLOCK_SIZE);
            aes_enc_dec(state, key1, 0);
            //printf("%s\n", state);
            memcpy(key1, key, AES_BLOCK_SIZE);
            memcpy(encrypted + offset, state, AES_BLOCK_SIZE);
            offset += AES_BLOCK_SIZE;
            size_to_go -= AES_BLOCK_SIZE;
        }
    }

    float elapsed_time = GET_TIME - start_time;
    printf("Timpul necesar pentru encriptare: %f\n", elapsed_time);
    times[1] = elapsed_time;

    //decrypt the file one block at a time
    
    //start measuring time for the decrypting phase
    start_time = GET_TIME;

    size_to_go = file_size;
    offset = 0;

    char *decrypted = (char*)malloc(encrypted_size * sizeof(char));
    memcpy(key1, key, AES_BLOCK_SIZE);
    while(1) {
        if (size_to_go < AES_BLOCK_SIZE) {
            memcpy(state, encrypted + offset, AES_BLOCK_SIZE);
            aes_enc_dec(state, key1, 1);
            memcpy(decrypted + offset, state, AES_BLOCK_SIZE);
            break;
        } else {
            memcpy(state, encrypted + offset, AES_BLOCK_SIZE);
            aes_enc_dec(state, key1, 1);
            memcpy(key1, key, AES_BLOCK_SIZE);
            memcpy(decrypted + offset, state, AES_BLOCK_SIZE);
            offset += AES_BLOCK_SIZE;
            size_to_go -= AES_BLOCK_SIZE;
        }
    }

    decrypted[file_size] = 0;

    elapsed_time = GET_TIME - start_time;
    printf("Timpul scurs pentru decriptare: %f\n", elapsed_time);
    //printf("%s\n", decrypted);
    times[1] += elapsed_time;

    free(encrypted);
    free(to_encrypt);
    free(decrypted);
}

__uint32_t* convert_to_sha_message(char *to_hash, size_t file_size, size_t *M_size, size_t *used_Ms) {

    // add the 64 bits required for length encoding
    // size_t actual_size = (file_size * 8);
    size_t actual_size = (file_size * 8);
    // calculate size of array M (multiple of 16)
    size_t size_of_M = ceil(((double)actual_size / 32) / 16) * 16;
    //size_t size_of_M = actual_size / 32 + 1;

    printf("Size of array M: %lu\n", size_of_M);
    
    __uint32_t *M = (__uint32_t*)calloc(size_of_M, sizeof(__uint32_t));
    
    // write each 32 bit words of data in M
    size_t offset = 0;
    size_t size_to_go = file_size;
    size_t i = 0;
    while(1) {
        // read 32 bits (4 bytes)
        if(size_to_go < 4) {
            // printf("Last\n");
            memcpy(&M[i], to_hash + offset, 4);
            break;
        } else {
            // printf("Intre\n");
            memcpy(&M[i], to_hash + offset, 4*sizeof(char));
            offset += 4*sizeof(char);
            size_to_go -= 4*sizeof(char);
        }
        i++;
    }
    i++;
    *used_Ms = i;

    *M_size = size_of_M;
    return M;
}

void sha_256_benchmark() {

    //open the file to hash and get its size
    FILE *fp = fopen("sherlock.txt", "rb");
    size_t file_size = 0;
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    //read the file in memory
    char *to_hash = (char*)calloc(file_size, sizeof(char));
    char buffer[BUFF_SIZE];
    size_t size_to_go = file_size;
    size_t offset = 0;

    while(1) {
        if(size_to_go < BUFF_SIZE) {
            fread(buffer, sizeof(char), size_to_go, fp);
            memcpy(to_hash + offset, buffer, size_to_go);
            break;
        } else {
            fread(buffer, sizeof(char), BUFF_SIZE, fp);
            memcpy(to_hash + offset, buffer, BUFF_SIZE);
            offset += BUFF_SIZE;
            size_to_go -= BUFF_SIZE;        
        }
    }

    float start_time = GET_TIME;
    __uint32_t *M;
    size_t M_size;
    size_t used_Ms;
    M = convert_to_sha_message(to_hash, file_size, &M_size, &used_Ms);
    
   
    // //check M
    //printf("Size: %lu\n", M_size);
    //printf("Used containers: %lu\n", used_Ms);
    FILE *fp1 = fopen("sha","w");
    for(int i = 0; i < used_Ms; i++) {
        char s[5];
        memcpy(s, &M[i], 4*sizeof(char));
        s[4] = 0;
        //fprintf(fp1, "%s", s);
        // printf("!!!%s!!!", s);
        fwrite(&M[i], sizeof(char), 4, fp1);
        //fwrite(s, sizeof(char), 4*sizeof(char), fp1);
    }
    printf("\n");
    // char s[5];
    // memcpy(s, &M[1364547], 4);
    // s[4] = 0;
    // printf("Text:\n%s", s);
    uint32_t Ha[8];
    uint64_t L = 1;
    // uint32_t M1[1364560];https://github.com/drichardson/huffman.git
    // M1[0] = 0xbd000000;
    SHA_2(&M[0], L, Ha, SHA_256);
    //printf("Hash!\n");
    /*for(int i = 0; i < 8; i++) {
        printf("%x\n", Ha[i]);
    }*/
    float elapsed_time = GET_TIME - start_time;
    printf("Timpul scurs pentru crearea hash-ului: %f\n", elapsed_time);
    times[2] = elapsed_time;
    fclose(fp);
    fclose(fp1);
    free(to_hash);
    free(M);
}

void huffman_benchmark() {

    FILE *fp = fopen("copy", "rb");
    FILE *fp2 = fopen("huff.out", "wb");
    // printf("Maybe?\n");
    float start_time = GET_TIME;
    huffman_encode_file(fp, fp2);
    fclose(fp);
    fclose(fp2);
    fp = fopen("huff.out", "rb");
    fp2 = fopen("huff_decoded", "wb");
    huffman_decode_file(fp, fp2);
    float elapsed_time = GET_TIME - start_time;
    times[3] = elapsed_time;
    fclose(fp);
    fclose(fp2);
}

void benchmark() {

    generate_file();
    printf("Generate file done\n");
    
    generate_file_buffer();
    printf("Generate file buffer done\n");
    
    copy_one();
    printf("Copy one done\n");

    copy_buffer();
    printf("Copy buffer done\n");

    aes_benchmark();
    printf("AES done\n");
    
    sha_256_benchmark();
    printf("SHA-256 done\n");

    huffman_benchmark();
    printf("Huffman done\n");

    float score = sqrt(weights[0] * times[0] * weights[1] * times[1] *
                       weights[2] * times[2] * weights[3] * times[3]);

    printf("Final score: %f\n", score);
    continue_to_options();
}

void operations() {

    continue_to_options();
}

void handle_command_error() {
    printf("Eroare executie comanda de sistem\n");
}

void status_error(const char *command) {
    printf("Eroare executie %s, status: -1\n", command);
}

void continue_to_options() {
    printf("\nApasati tasta  pentru a continua...");
    read_dummy_char();
}

void read_dummy_char() {
    char dummy;
    scanf("%c", &dummy);
}

void print_hex_string(unsigned char *s) {
    int len = sizeof(s) / sizeof(char);
    for (int i = 0; i < len; i++) {
        printf("%c", s[i]);
    }
}