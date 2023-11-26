#include "options.h"
#include "stdio.h"
#include "string.h"
#include "time.h"

#define BUFF_COMMAND_SIZE 4096
#define GET_TIME (float)clock()/CLOCKS_PER_SEC

void processor_type();

void processor_frequency();

void mem_size();

void data_transfer();

void generate_file();

void copy_one();

void operations();

void handle_command_error();

void status_error(const char *command);

void continue_to_options();

void read_dummy_char();

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
            generate_file();
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
    char c = 'c';
    for(int i = 0; i < file_size; i++)
        fwrite(&c, sizeof(int), 1, fp);
    fclose(fp);

    float end_time = GET_TIME;
    float elapsed_time = end_time - start_time;

    printf("Timpul scurs pentru a scrie fisierul: %f secunde\n", elapsed_time);
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
    // read_dummy_char();
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