
/*****************************************************************************************
** DenniScan - Scanner de vulnerabilidades web - P0cL4bs Team - ** PUBLIC VERSION **. 
** Autor: Jessé aka Constantine.
** 
** Versão 1: Wordpress e Joomla (apenas bugs de arbitrary file upload).
** Bugs adicionados...
**  Gravity Forms 1.8.19 - Wordpress plugin
** 
** Compilar...
**  gcc -g -Wall -pthread -std=c99 -lpthread denniscan.c -o denniscan ; ./denniscan
*****************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Configurações. */
#define DEFAULT_OUTPUT      "results.txt"  /* Arquivo de saída com resultado do scan. */
#define MAX                 256

/* Macros. */
#define say printf
#define die(STR) {printf(STR);exit(0);}
#define alloc_and_copy(DST,SRC,SRC_SIZE) \
  DST = (char *) xmalloc(SRC_SIZE+1); \
  memset(DST, '\0', SRC_SIZE+1); \
  memcpy(DST, SRC, SRC_SIZE)
  
#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE  0
#endif

typedef struct {                /* -> Estrutura para controle dos parâmetros recebidos via linha de comando. */
  char *output;                 /* Nome do arquivo de saída para salvar o resultado do scaneamento, por padrão usa 'results.txt'. */
  char *input;                  /* Nome do arquivo contendo a lista de domínios a serem scaneados. */
  char *host;                   /* Domínio do host que será scaneado. */
  int port;                     /* Número da porta utilizada para conexão. Por padrão usa 80. */
  char *sock_server;            /* Endereço do servidor SOCKS5 que será utilizado como proxy. */
  int sock_port;                /* Porta do servidor SOCKS5. */
  int use_socks;                /* Se for setado proxy contém valor 'TRUE' caso contrário 'FALSE'. */
  int threads;                  /* Número de threads utilizadas para o scaneamento. */
} instance_t;

typedef struct {                /* -> Parâmetro para função de controle das vulnerabilidades. */
  char *host;                   /* Host alvo. */
  int counter;                  /* Indexação do host na lista. */
} thread_param_t;

typedef struct {                /* -> Estrutura para controle das requisições HTTP. */
  char *buffer;                 /* Dados da resposta da requisição HTTP. */
  int size;                     /* Tamanho dos dados retornados. */
} http_response_t;

typedef struct {                /* -> Estrutura para controle das estatísticas globais. */
  int total_hosts_scanned;      /* Total de domínios scaneados. */
  int total_vulns_found;        /* Total de vulnerabilidades encontradas. */
} statistics_t;

instance_t instance;
statistics_t statistics;
int thread_counter = 1;
int thread_total_counter = 0;
int extra_control = FALSE;

void core (void);
void finish (void);
void show_banner (char *argv, int id);
void *scanner (void *param_data);
void * xmalloc(unsigned int size);
static unsigned int check_is_domain (const char *domain);
static http_response_t *send_http_get(const char *host);
static unsigned int wp_multiples_bug (const char *host);
void show_information (const char *host, const int index, const char *message);

int main (int argc, char **argv) {
  instance.sock_server = NULL;
  instance.output = NULL;
  instance.input = NULL;
  instance.host = NULL;
  instance.port = 0;
  instance.threads = 0;
  instance.sock_port = 0;
  instance.use_socks = FALSE;
  
  statistics.total_hosts_scanned = 0;
  statistics.total_vulns_found = 0;
  
  #define COPY_TO_INSTANCE_STRUCT(PTR) \
  if (a+1 < argc) \
    if ((PTR = (char *) xmalloc(strlen(argv[a+1])+1)) != NULL) { \
      memset(PTR, '\0', strlen(argv[a+1])+1); \
      memcpy(PTR, argv[a+1], strlen(argv[a+1])); \
    } \
  
  for (int a=0; a<argc; a++) {
    if (strcmp(argv[a], "-l") == 0) { COPY_TO_INSTANCE_STRUCT(instance.input) }
    if (strcmp(argv[a], "-o") == 0) { COPY_TO_INSTANCE_STRUCT(instance.output) }
    if (strcmp(argv[a], "-h") == 0) { COPY_TO_INSTANCE_STRUCT(instance.host) }
    if (strcmp(argv[a], "-p") == 0) { if (a+1 < argc) instance.port = atoi(argv[a+1]); }
    if (strcmp(argv[a], "-s") == 0) { COPY_TO_INSTANCE_STRUCT(instance.sock_server) }
    if (strcmp(argv[a], "-k") == 0) { if (a+1 < argc) instance.sock_port = atoi(argv[a+1]); }
    if (strcmp(argv[a], "-t") == 0) { if (a+1 < argc) instance.threads = atoi(argv[a+1]); }
  }
  
  if (instance.input != NULL && instance.host != NULL) {
    if (instance.output != NULL)
      free(instance.output);
    say("\n Especifique (apenas)um alvo(-h) ou uma lista(-l) de dominios para "
        "serem analisados.\n");
    show_banner(argv[0], 1);
  }
  
  if (instance.output == NULL) {
    char default_output [] = DEFAULT_OUTPUT;
    if ((instance.output = (char *) xmalloc(strlen(default_output)+1)) != NULL) {
      memset(instance.output, '\0', strlen(default_output)+1);
      memcpy(instance.output, default_output, strlen(default_output));
    }
  }
  
  if (instance.port == 0)
    instance.port = 80;
  
  if (instance.input == NULL && instance.host == NULL) 
    show_banner(argv[0], 1);

  if ((instance.sock_server != NULL && instance.sock_port == 0) ||
      (instance.sock_server == NULL && instance.sock_port != 0) )
    show_banner(argv[0], 1);
  
  if (instance.sock_server != NULL && instance.sock_port != 0)
    instance.use_socks = TRUE;
  
  core();
  finish();
  
  return 0;
}

/*
** Exibe help e logo do programa.
**  @argv - Nome do programa salvo no disco rígido, valor armazenado em argv[0].
**  @id   - Tipo do banner a ser exibido. 1 = Logo e help, 2 = Apenas logo.
*/
void show_banner (char *argv, int id) {
  switch (id) {
  case 1:
    show_banner(NULL, 2);
    say("  -l = List of hosts that will be scanned.\n"
        "  -h = Target host.\n"
        "  -p = Connection port, default: 80.\n"
        "  -o = Results of the scan. By default save in 'results.txt'.\n"
        "  -s = SOCKS5 proxy server address.\n"
        "  -k = SOCKS5 proxy server port.\n"
        "  -t = Threads limit, default: 1.\n"
        "  \n"
        "  Exemplos de uso...\n"
        "   %s -l list-of-domains.txt -o output.txt -t 20\n"
        "   %s -h host.com\n"
        "   %s -h host.com -p 8080\n"
        "   %s -h host.com -p 8080 -s 127.0.0.1 -k 9050\n"
        "   \n", argv, argv, argv, argv);
    exit(0);
  case 2:
    say("  \n"
        "   __  ___ __  _ __  _ _   __   ___ __  __  _  \n"
        "  | _\\| __|  \\| |  \\| | |/' _/ / _//  \\|  \\| |   V1.0 - 2015 \n"
        "  | v | _|| | ' | | ' | |`._`.| \\_| /\\ | | ' | Coded by Constantine  \n"
        "  |__/|___|_|\\__|_|\\__|_||___/ \\__/_||_|_|\\__|    P0cL4bs Team\n"
        "          github.com/jessesilva - github.com/P0cL4bs   \n\n");
    break;
  }
}

/*
** Controle do modo de execução do programa (Host mode, List mode), carregamento da lista
** de domínios, controle de threads dentre outros itens.
*/
void core (void) {
  if (instance.threads > 1)
    thread_counter = instance.threads;
  
  // Host mode.
  if (instance.host != NULL && instance.input == NULL) {
    thread_param_t *param = (thread_param_t *) xmalloc(sizeof(thread_param_t));
    alloc_and_copy(param->host, instance.host, strlen(instance.host));
    param->counter = 0;
    show_banner(NULL, 2);
    say("  Starting...\n\n");
    scanner((void *) param);
  }
  
  // List mode.
  else {
    FILE *fp = NULL;
    char line [MAX];
    int line_counter = 0;
    
    show_banner(NULL, 2);
    say("  Starting...\n\n");
    
    if ((fp = fopen(instance.input, "r")) != NULL) {
      while (fgets(line, MAX, fp)) {
        for (int a=0; line[a]!='\0'; a++)
          if (line[a] == '\n' || line[a] == '\r')
            line[a] = '\0';
        
        if (check_is_domain(line)) {
          while (TRUE)
            if (thread_counter) {
              thread_param_t *param = (thread_param_t *) xmalloc(sizeof(thread_param_t));
              alloc_and_copy(param->host, line, strlen(line));
              param->counter = line_counter;
              thread_counter--;
              line_counter++;
              pthread_t td;
              pthread_create(&td, NULL, scanner, (void *) param);
              say("  [%d] -> Checking: %s\n", param->counter, param->host);
              break;
            }
        }
      }
      fclose(fp);
      
      while(1) {
        if (thread_total_counter == line_counter)
          break;
      }
    } else {
      say("Nao foi possivel abrir arquivo: %s.\n", instance.input);
      exit(0);
    }
  }
}

/*
** Controle das vulnerabilidades que serão checadas. 
**  @param_data = Estrutura de dados (thread_param_t), contem domínio que será 
**  analisado e número de ordem na lista.
*/
void *scanner (void *param_data) {
  thread_param_t *param = (thread_param_t *) param_data;
  
  // Wordpress.
  int wp_result = wp_multiples_bug(param->host);
  switch (wp_result) {
    case 1:
      show_information(param->host, param->counter, "Gravity Forms v1.8.19");
      break;
  }
  
  if (wp_result >= 1)
    statistics.total_vulns_found++;
  
  statistics.total_hosts_scanned++;
  thread_counter++;
  thread_total_counter++;
  return param_data;
}

/* 
** Verifica se host está vulnerável a determinados bugs no Wordpress.
** No caso bugs simples onde com apenas uma requisição GET é possível analisar.
** 
**  @host - Domínio que será analisado.
**  Retorno: Para erro retorna 'FALSE', para sucesso retorna o número de
**  identificação do bug.
** 
**    1 - Gravity Forms 1.8.19.
*/
static unsigned int wp_multiples_bug (const char *host) {
  if (!host) return FALSE;
  int result = FALSE;
  char *url = NULL;
  if (!(url = (char *) xmalloc(MAX*4)))
    return FALSE;
  memset(url, '\0', MAX*4);
  
  char *path [] = { 
    "/?gf_page=upload", 
    
    NULL 
  };
  
  for (int a=0; path[a]!=NULL; a++) {
    sprintf(url, "http://%s%s", host, path[a]);
    http_response_t *response = send_http_get(url);
    
    if (response != NULL) {
      if (response->size > 0)
        switch (a) {
        case 0:
          if (strstr(response->buffer, "{\"status\""))
           result = 1;
          break;
        }
      response->size = 0;
      free(response->buffer);
      
      if (result != FALSE)
        break;
    }
  }
  
  return result;
}

/* 
** Exibe e salvar informações globais.
**  @host     - Domínio vulnerável a ser exibido.
**  @index    - Ordem do mesmo na lista.
**  @message  - Descrição a ser exibida.
*/
void show_information (const char *host, const int index, const char *message) {
  if (host != NULL && message != NULL)
    say("  [+] host: %s -> %s - VULNERABLE!\n", host, message);
  
  FILE *fp = NULL;
  if ((fp = fopen(instance.output, "a+")) != NULL) {
    if (extra_control == TRUE)
      fprintf(fp, "%s -> %s\n", host, message);
    else if (extra_control == 3) {
      char content [] = 
        "\n---------------------------------------------------------------\n"
        "                      EOS - End of Scan.                       \n"
        "---------------------------------------------------------------\n\n";
      fprintf(fp, "%s", content);
    } else {
      char content [] = 
        "\n---------------------------------------------------------------\n"
        "                Vulnerability scanning results.\n"
        "Denniscan v1.0 - 2015 - Coded by Constantine - P0cL4bs Team.\n"
        "My GitHub: https://github.com/jessesilva\n"
        "Team GitHub: https://github.com/P0cL4bs\n"
        "---------------------------------------------------------------\n\n"
        "Vulnerabilities found...\n\n";
      fprintf(fp, "%s", content);
      fprintf(fp, "%s -> %s\n", host, message);
      extra_control = TRUE;
    }
    fclose(fp);
  } else {
    say("Erro ao abrir/criar arquivo: %s\n", instance.output);
    exit(0);
  }
}

/*
** Verifica se é um domínio válido.
**  @domain - Domínio a ser verificado.
**  Retorno: Se for válido retorna 'TRUE', caso contrário retorna 'FALSE'.
*/
static unsigned int check_is_domain (const char *domain) {
  if (!domain) return FALSE;
  int flag = 0;
  
  for (int a=65,b=97; a<=90; a++,b++)
    if ((int) (domain[strlen(domain) - 1]) == a || 
        (int) (domain[strlen(domain) - 1] == b)) 
    {
      flag++;
      break;
    }

  for (int a=0; domain[a]!='\0'; a++)
    if (domain[a] == '.') {
      flag++;
      break;
    }
    
  if (flag == 2) return TRUE;
  return FALSE;
}

/*
** Responsável por enviar requisições do tipo GET.
**  @host - Endereço do servidor que será acessado.
**  Retorno: Dados armazenados em estrutura http_response_t para sucesso ou NULL em caso de erro.
** 
** Exemplo de uso...
**  http_response_t response = send_http_get("http://host.com/page.php?id=2");
**  printf("Size: %d\nBuffer...\n%s\n", response.size, response.buffer);
*/
static http_response_t *send_http_get(const char *host) {
  if (!host)
    return (http_response_t *) NULL;
  
  struct {
    char *domain;
    char *path;
    int port;
  } info;
  
  info.domain = NULL;
  info.path = NULL;
  info.port = 80;
  
  char *ptr = NULL;
  char temporary [MAX];
  
  // Verifica se url é um site http.
  if (strstr(host, "http://") == NULL)
    return (http_response_t *) NULL;
    
  // Extrai porta se existir.
  if ((ptr = strstr(host, "://")) != NULL)
    if ((ptr = strstr(++ptr, ":")) != NULL) {
      for (int a=0; ptr[a]!='\0'; a++) {
        if (a == (MAX-1) || ptr[a] == '/') {
          temporary[a-1] = '\0';
          break;
        }
        temporary[a] = ptr[a+1];
        info.port = (int) strtol(temporary, (char **)0, 10);
      }
    }
   
  // Extrai path se existir.
  if ((ptr = strstr(host, "://")) != NULL && ptr++ && ptr++)
    if ((ptr = strstr(++ptr, "/")) != NULL) {
      info.path = (char *) xmalloc(strlen(ptr)+1);
      memset(info.path, '\0', strlen(ptr)+1);
      memcpy(info.path, ptr, strlen(ptr));
    }
  
  // Extrai domínio.
  if ((ptr = strstr(host, "://")) != NULL && ptr++ && ptr++ && ptr++)
    for (int a=0; ptr[a]!='\0'; a++) {
      if (ptr[a] == ':' || ptr[a] == '/') {
        info.domain = (char *) xmalloc(a+1);
        memset(info.domain, '\0', a+1);
        memcpy(info.domain, ptr, a);
        break;
      }
    }
  
  // Monta header HTTP.
  char *header = (char *) xmalloc(MAX*4);
  memset(header, '\0', MAX*4);
  
  if (info.domain != NULL) {
    sprintf(header, 
      "GET %s HTTP/1.1\r\n"
      "Host: %s\r\n"
      "User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:38.0) Gecko/20100101 Firefox/38.0\r\n"
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
      "Connection: close\r\n"
      "\r\n", info.path, info.domain);
  }
  
  // Cria conexão.
  int sock;
  struct sockaddr_in server_address;
  struct hostent *server;
  
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    say("Nao foi possivel criar socket.\n");
    return (http_response_t *) NULL;
  }
  
  struct timeval timeout_time;
  timeout_time.tv_sec = 5;
  timeout_time.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout_time, sizeof(struct timeval));
  
  if ((server = gethostbyname(info.domain)) == NULL)
    return (http_response_t *) NULL;
  
  memset(&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;
  
  http_response_t *response = (http_response_t *) xmalloc(sizeof(http_response_t));
  response->buffer = NULL;
  response->size = 0;
  
  char buffer [MAX*4];
  int alloc_size = 0;
  int old_alloc_size = 0;
  
  // Conexão via proxy SOCKS 5.
  if (instance.use_socks == TRUE) {
    server_address.sin_port = htons(instance.sock_port);
    server_address.sin_addr.s_addr = inet_addr(instance.sock_server);
    
    if (connect(sock, (struct sockaddr*) &server_address, sizeof(server_address)) < 0) {
      say("Erro ao se conectar no servidor proxy.\n");
      return (http_response_t *) NULL;
    }
    
    char step_one [] = { 0x05, 0x01, 0x00 };
    send(sock, step_one, sizeof(step_one), 0);
    
    if (recv(sock, buffer, MAX*4, 0) > 0) {
      if (buffer[0] != 0x05) {
        say("Servidor SOCKS nao suporta a versao 5.\n");
        exit(0);
      } else if (buffer[1] == 0x00) {
        char step_two [MAX] = { 0x05, 0x01, 0x00, 0x01 };
        struct sockaddr_in real_address;
        
        real_address.sin_port = htons(info.port);
        real_address.sin_addr.s_addr = inet_addr(info.domain);
        memcpy(step_two + 4, &real_address.sin_addr.s_addr, 4);
        memcpy(step_two + 8, &real_address.sin_port, 2);
        
        send(sock, step_two, 10, 0);
        if (recv(sock, buffer, MAX*4, 0) > 0) {
          send(sock, header, strlen(header), 0);
          while (TRUE) {
            int result = recv(sock, buffer, MAX*4, 0);
            if (result == 0 || result == -1)
              break;
            else {
              if (alloc_size == 0)
                alloc_size = result;
              else 
                alloc_size += result;
              
              if ((response->buffer = (char *) realloc(response->buffer, alloc_size)) != NULL) {
                memcpy(&response->buffer[old_alloc_size], buffer, result);
                old_alloc_size = alloc_size;
              }
            }
          }
          response->size = alloc_size;
        }
      } else {
        say("Erro ao conectar em servidor SOCKS 5.\n");
        exit(0);
      }
    }
  }
  
  // Conexão normal.
  else {
    server_address.sin_port = htons(info.port);
    server_address.sin_addr.s_addr = *(unsigned long *)server->h_addr_list[0];
    
    if (connect(sock, (struct sockaddr*) &server_address, sizeof(server_address)) < 0) 
      return (http_response_t *) NULL;
    
    memset(buffer, '\0', MAX*4);
    send(sock, header, strlen(header), 0);
    
    while (TRUE) {
      int result = recv(sock, buffer, MAX*4, 0);
      if (result == 0 || result == -1)
        break;
      else {
        if (alloc_size == 0)
          alloc_size = result;
        else 
          alloc_size += result;
        
        if ((response->buffer = (char *) realloc(response->buffer, alloc_size)) != NULL) {
          memcpy(&response->buffer[old_alloc_size], buffer, result);
          old_alloc_size = alloc_size;
        }
      }
    }
    response->size = alloc_size;
  }
  
  close(sock);
  if (header != NULL)
    free(header);
  if (info.domain != NULL)
    free(info.domain);
  if (info.path != NULL)
    free(info.path);
  if (response->size > 0 && response->buffer != NULL) 
    return response;
  return (http_response_t *) NULL;
}

/* Exibe informações de estatísticas finais. */
void finish (void) {
  
  // Salva 'EOF' no final do arquivo de log.
  extra_control = 3;
  show_information(NULL, 0, NULL);
  
  say("\n  Scanner finished!\n"
      "  Total host scanned: %d\n"
      "  Total vulnerabilities found: %d\n"
      "  Results saved in '%s' file.\n\n", 
      statistics.total_hosts_scanned, statistics.total_vulns_found, instance.output);
}

/*
** Faz tratamento de ponteiro e aloca dados com malloc().
**  @size - Tamanho a ser alocado.
**  Retorno: Ponteiro para região alocada.
*/
void * xmalloc(unsigned int size) {
  if (size) {
    void *ptr = NULL;
    if ((ptr = malloc(size)) != NULL)
      return ptr;
  }
  return NULL;
}

/* EOF. ******************************************************************************* */
