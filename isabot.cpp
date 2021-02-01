#include <arpa/inet.h>
#include <iostream>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>  
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <regex>
#include <vector>
#include <ctime>
#include <netinet/in.h>

/* IMPORTANT 
   Parts of program marked with "MARK" were inspired and modified from StackOverflow post: 
   https://stackoverflow.com/questions/41229601/openssl-in-c-socket-connection-https-client 
   They were posted by user "O.logN".
   These parts of program mainly concern setuping SSL Library.
*/


int RecvPacket(int sw);
int SendPacket(const char *req);

using namespace std;


/* Class containing information about one message in discord channel */
class Message {       
  public:             
    string username;
    string content;
    string timestamp;
    string msgID;

    Message(string u,string c,string t, string id){
        username = u;
        content = c;
        timestamp = t;
        msgID = id;
    }

    /* Function that compares if two messages are identical */
    bool are_Identical(Message b){
        if((username == b.username) && (content == b.content) && (timestamp == b.timestamp) && (msgID == b.msgID)){
            return true;
        }
        return false;
    }

};

/* Global variables */
SSL *ssl;
int sock;
vector<Message> msg_vect;
vector<string> str_vect;
bool loaded = false;
string tok;
string channel = "";
string channel_name = "";
bool verbose = false;
bool too_many_requests = false;



/* Segments answer recieved from GET request to array of messages */
vector<string> retrieveMessages(string s){

    vector<string> s_array;
    s = s.substr(s.find("{\"id"));

    string delimiter = "}, {";
    size_t last = 0; 
    size_t next = 0; 
    while ((next = s.find(delimiter, last)) != string::npos) {
        s_array.push_back(s.substr(last, next-last));
        last = next + 1;
    } 
    s_array.push_back(s.substr(last, next-last));
    reverse(s_array.begin(),s_array.end());
    return s_array;
}

/* Parses messages and sends those, which were written in the channel after the bot was started */
void parseMessages(vector<string> vs){
    for (int i=0; i<vs.size();i++){ 

        

        /* Gets a message out of the array */
        string message = vs[i];
        smatch match;
        
        /* Getting username with regex */
        string start = "username\": \"";
        string end = "\", \"avatar\"";
        regex usrR ( start + "(.*)" + end);
        regex_search(message,match,usrR);
        string username = match[1].str();

        /* Getting content with regex */
        start = "\"content\": \"";
        end = "\", \"channel";
        regex cntntR ( start + "(.*)" + end);
        regex_search(message,match,cntntR);
        string content = match[1].str();

         /* Getting timestamp with regex */
        start = "timestamp\": \"";
        end = "\", \"edited_timestamp";
        regex tmstmpR ( start + "(.*)" + end);
        regex_search(message,match,tmstmpR);
        string timestamp = match[1].str();

        /* Getting msgID with regex */
        start = "\"id\": \"";
        end = "\", \"type\"";
        regex msgidR ( start + "(.*)" + end);
        regex_search(message,match,msgidR);
        string messageID = match[1].str();

        /* If substring "bot" is contained in username - skip */
        if(!strstr(username.c_str(), "bot")){
            /* "loaded" - After first GET request is sent, this function only loads messages
             *  from chat history straight to the vector "msg_vect" for comparasion purposes ("loaded" - false) 
             *  then "flips" "loaded" to true, so from then, it can compare new messages to chat history
             */
            if (loaded == true){
                    /* Creating message object */
                    Message msg(username,content,timestamp, messageID);
                    bool is_Contained = false;
                    /* Comparing new message with those in the "msg_vect" */
                    for (int i=0; i<msg_vect.size(); i++){
                        if(msg.are_Identical(msg_vect[i])){
                            is_Contained = true;
                        }
                    }
                    /* If the message is not contained in vector, create POST request and send it to discord server */
                    if (!is_Contained){
                        /* Push message to the vector, so program knows it has been processed */
                        msg_vect.push_back(msg);
                        string request = "POST /api/v6/channels/"+channel+"/messages HTTP/1.1\r\nHost: discord.com\r\nAuthorization: Bot "+tok+"\r\nContent-Type: application/json\r\nContent-Length:";
                        request += to_string(msg.username.length() + msg.content.length()+25);
                        request += "\r\n\r\n{\"content\": \"";
                        request += "echo: " + msg.username + " - " + msg.content + "\"}\r\n\r\n";
                        if(msg.content.length() != 0){
                            /* Sending POST request with message to the discord server */
                            sleep(1);
                            SendPacket(request.c_str());
                            
                            /* If verbose flag has been set, print message to STDOUT */
                            if (verbose){
                                cout << channel_name + " - " + msg.username + ": " + msg.content + "\n";
                            }
                        }
                    } 
            /* "loaded - false", loading chat history into vector */
            } else {
                Message msg(username,content,timestamp, messageID);
                msg_vect.push_back(msg);
            }
        }   
    }
    /* Flipping loaded "switch" variable to true so program knows chat history has been loaded */
    loaded = true;
}

/* Processes a packet, "sw" - variable that distinguishes between GET - chat, GET - guilds, GET - channels*/
int RecvPacket(int sw)
{
    int change = 0;
    int len=100;
    char buf[1000000];
    int HTMLH = 1369;
    string s;

    /* Loading SSL_read into string */
    /* MARK */
    do {
        len=SSL_read(ssl, buf, HTMLH);
        buf[len]=0;
        s += buf;
        if(len < 10){
            break;
        }
    } while (len > 0);

    /* Splitting the answer into messages GET - chat */
    if(sw == 0){
        str_vect = retrieveMessages(s);
    /* Getting guild_id and further processing it to get channel_ID */
    } else if(sw == 1) {
        smatch match;
        string start = "\"id\": \"";
        string end = "\", \"name\"";
        regex guild_idR ( start + "(.*)" + end);
        regex_search(s,match,guild_idR);
        string guild_id = match[1].str();
        string request = "GET /api/v6/guilds/"+guild_id+"/channels HTTP/1.1\r\nHost: discord.com\r\nAuthorization: Bot "+tok+"\r\n\r\n";
        SendPacket(request.c_str());
        RecvPacket(2);
    /* Getting channel_ID of channel with name "isa-bot", assigning channel name and channel_ID to global variables */
    } else if(sw == 2) {
        /* Segmenting individual channels to find the one with name "isa-bot" */
        vector<string> v = retrieveMessages(s);
        smatch match;
        /* Searching for desired channel "isa-bot" */
        for (int i = 0; i < v.size(); i++){
            /* Getting whole part that needs to be processed from message about channel */
            string start = "\"id\": \"";
            string end = "\"name\": \"isa-bot\"";
            regex stgR ( start + "(.*)" + end);
            regex_search(v[i],match,stgR);
            string tmp = match.str();
            
            /* Getting channel name */
            start = "\"name\": \"";
            end = "\", \"position";
            regex channel_nameR ( start + "(.*)" + end);
            regex_search(v[i],match,channel_nameR);
            channel_name = match[1].str();

            /* Getting channel_ID */
            start = "\"id\": \"";
            end = "\", \"last_message";
            regex channel_idR ( start + "(.*)" + end);
            regex_search(tmp,match,channel_idR);
            channel = match[1].str();

            /* Regex hit! Break out of the loop */
            if (channel != ""){
                break;
            }
        }
    }

    /* Checking for reading errors */
    /* MARK */
    if (len < 0) {
        int err = SSL_get_error(ssl, len);
    if (err == SSL_ERROR_WANT_READ)
            return 0;
        if (err == SSL_ERROR_WANT_WRITE)
            return 0;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return -1;
    }

    return 0;
}

/* Sending a request */    
/* MARK */
int SendPacket(const char *req)
{
    int len = SSL_write(ssl, req, strlen(req));
    if (len < 0) {
        int err = SSL_get_error(ssl, len);
        switch (err) {
        case SSL_ERROR_WANT_WRITE:
            return 0;
        case SSL_ERROR_WANT_READ:
            return 0;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        default:
            return -1;
        }
    }
	return 0;
}

/* Printing help */
void printhelp(){
    printf("This program loads recieved message from isa-bot discord channel and echoes them back.\n");
    printf("Usage: ./isabot [-v|--verbose] for printing messages sent also to STDOUT, -t <bot_access_token> token of your bot\n");
    exit(0);
}

int main(int argc, char *argv[])
{

    /**************************/
    /*  Resolving arguments   */
    /**************************/

    if(argc < 2){
        printhelp();
    }

    /* Struct for longargs */
    static struct option long_options[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"verbose", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 't'}
    };


    char ch;
    char* token = NULL;
    /* Loading and setting arguments */
    while ((ch = getopt_long(argc, argv, "vht:", long_options, NULL)) != -1){
        switch (ch){
            case 't':
                token = optarg;
                tok = token;
                break;
            case 'h':
                printhelp();
            case 'v':
                verbose = true;
                break;
            case '?':
                cout << "UKNOWN ARGUMENT!";
                exit(1);
            default: 
                cout << "UKNOWN ARGUMENT!";
                exit(1);
        }
    }

    /*************************/
    /* Setting up connection */
    /*         MARK          */
    /*************************/

    /* Setting up socket with Discord IP */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("Error creating socket.\n");
        return -1;
    }
    struct sockaddr_in sa;
    memset (&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr("162.159.128.233");
    sa.sin_port        = htons (443); 
    socklen_t socklen = sizeof(sa);
    if (connect(s, (struct sockaddr *)&sa, socklen)) {
        printf("Error connecting to server.\n");
        return -1;
    }

    /* Initializing SSL_library */
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    /* Defining function for different systems */
    #if defined(LWS_HAVE_TLS_CLIENT_METHOD)
	const SSL_METHOD *meth = (SSL_METHOD *)TLS_client_method();
    #elif defined(LWS_HAVE_TLSV1_2_CLIENT_METHOD)
	const SSL_METHOD *meth = (SSL_METHOD *)TLSv1_2_client_method();
    #else
	const SSL_METHOD *meth = (SSL_METHOD *)SSLv23_client_method();
    #endif

    /* Creating SSL */
    SSL_CTX *ctx = SSL_CTX_new (meth);
    ssl = SSL_new (ctx);
    if (!ssl) {
        printf("Error creating SSL.\n");
        return -1;
    }

    /* Creating SSL connection */
    SSL_set_fd(ssl, s);
    int err = SSL_connect(ssl);
    if (err <= 0) {
        printf("Error creating SSL connection.  err=%x\n", err);
        fflush(stdout);
        return -1;
    }
    
    /*****************************************/
    /*  Communicating with Discord REST API */
    /****************************************/

    /* Assigns channel_ID to global variable "channel" and channel name to global variable "channel_name". */
    string request = "GET /api/v6/users/@me/guilds HTTP/1.1\r\nHost: discord.com\r\nAuthorization: Bot "+tok+"\r\n\r\n";
    SendPacket(request.c_str());
    RecvPacket(1);

    /* Core while that infinitely loops, gets new messages from chat and echoes them back. */
    while(true){
        string request = "GET /api/v6/channels/"+channel+"/messages HTTP/1.1\r\nHost: discord.com\r\nAuthorization: Bot "+tok+"\r\n\r\n"; 
        SendPacket(request.c_str());
        RecvPacket(0);
        parseMessages(str_vect);
        sleep(1);
    }

    return 0;
}

