#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <thread>
#include "coap.h"
#include <stdexcept>
#include "CoapServer.h"

#ifdef __GNUC__
    #define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
    #define UNUSED_PARAM
#endif /* GCC */

class CoapServer::CoapServerImpl
{
public:
    CoapServerImpl(const std::string &url,
                    unsigned int port)
                        : server_uri(url), 
                          port(port), 
                          time_resource(nullptr),
                          protocol_version(PROTOCOL_VERSION::IPV4),
                          quit_(false),
                          thread()
    {
        init();
        if (!ctx) throw std::runtime_error("Error initilizating server stuff!");
        create_resources();
    }
                    
        
    ~CoapServerImpl()
    {
        quit();
        coap_free_context(ctx);
    }

    void set_protocol_version(PROTOCOL_VERSION version)
    {
        protocol_version = version;
    }

    // start_server
    void start()
    {
        thread = std::thread(&CoapServerImpl::thread_main, this);
        // Separates the thread of execution from the thread object, 
        // allowing execution to continue independently. 
        // Any allocated resources will be freed once the thread exits. 
        thread.detach();
    }

private:
    void quit()
    { 
        quit_ = true; 
        if (thread.joinable()) thread.join();
    }

    void thread_main()
    {
        coap_tick_t now;
        coap_queue_t *nextpdu;
        struct timeval tv, *timeout;

        printf("Starting coap server...\n");
        while (!quit_)
        {
            FD_ZERO(&readfds);
            FD_SET(ctx->sockfd, &readfds);

            nextpdu = coap_peek_next(ctx);
            
            coap_ticks(&now);
            while (nextpdu && nextpdu->t <= now - ctx->sendqueue_basetime) 
            {
                coap_retransmit(ctx, coap_pop_next(ctx));
                nextpdu = coap_peek_next(ctx);
            }

            if (nextpdu && nextpdu->t <= COAP_RESOURCE_CHECK_TIME) 
            {
                /* set timeout if there is a pdu to send before our automatic timeout occurs */
                tv.tv_usec = ((nextpdu->t) % COAP_TICKS_PER_SECOND) * 1000000 / COAP_TICKS_PER_SECOND;
                tv.tv_sec = (nextpdu->t) / COAP_TICKS_PER_SECOND;
                timeout = &tv;
            } 
            else 
            {
                tv.tv_usec = 0;
                tv.tv_sec = COAP_RESOURCE_CHECK_TIME;
                timeout = &tv;
            }

            int result = select(FD_SETSIZE, &readfds, 0, 0, timeout);
            if ( result < 0 ) /* socket error */
                throw std::runtime_error("Socket error!");
            else if (result > 0 && FD_ISSET(ctx->sockfd, &readfds)) /* socket read*/
            {
                //printf("Recibo del socket...\n");
                coap_read(ctx);       
            }
            else // timeout
            {
                if (time_resource) time_resource->dirty = 1;
            }
        }
    }

    void init_context(const char *node)
    {
        struct addrinfo hints = {0};
        struct addrinfo *result, *rp;

        hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
        hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
        hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

        int s = getaddrinfo(node, std::to_string(port).c_str(), &hints, &result);
        if (s != 0) throw std::runtime_error(gai_strerror(s));

        for (rp = result; rp != NULL; rp = rp->ai_next) 
        {
            // Be sure that get correct address for selected protocol
            if (rp->ai_family != CoapCommon::get_family_for_protocol_version(protocol_version))
                continue;

            if (rp->ai_addrlen <= sizeof(serv_addr.addr)) 
            {
                coap_address_init(&serv_addr);
                serv_addr.size = rp->ai_addrlen;
                memcpy(&serv_addr.addr, rp->ai_addr, rp->ai_addrlen);
                ctx = coap_new_context(&serv_addr);
                break;
            }
        }

        freeaddrinfo(result);
    }

    void init()
    {
        init_context((protocol_version == PROTOCOL_VERSION::IPV4) ? "0.0.0.0" : "::");
    }

    static std::unique_ptr<unsigned char[]> make_large(const char *filename, int &len)
    {
        FILE *fp = NULL;
        struct stat statbuf;

        if (!filename)
            return nullptr;

        if (stat(filename, &statbuf) < 0) 
            return nullptr;

        fp = fopen(filename, "r");
        if (!fp)
            return nullptr;

        std::unique_ptr<unsigned char[]> payload = std::make_unique<unsigned char[]>(statbuf.st_size);
        len = fread(payload.get(), 1, statbuf.st_size, fp);

        fclose(fp);

        return std::move(payload);
    }

    void create_resources()
    {
        coap_resource_t *r;
        /* init index */
        r = coap_resource_init(NULL, 0, 0);
        coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);
        coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1, 0);
        coap_add_attr(r, (unsigned char *)"title", 5, (unsigned char *)"\"General Info\"", 14, 0);
        coap_add_resource(ctx, r);

        /* Initialize the hello resource */
        r = coap_resource_init((unsigned char *) "hello", 5, 0);
        coap_register_handler(r, COAP_REQUEST_GET, hnd_get_hello);
        coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_hello);
        coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_hello);
        coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 1, 0);
        coap_add_attr(r, (unsigned char *)"title", 5, (unsigned char *)"\"Hello World\"", 13, 0);
        coap_add_resource(ctx, r);

        /* discovering */
        r = coap_resource_init((unsigned char *) "discover", 8, 0);
        coap_register_handler(r, COAP_REQUEST_GET, hnd_get_all_resources);
        coap_add_resource(ctx, r);

        /* large */
        r = coap_resource_init((unsigned char *) "large", 5, 0);
        coap_register_handler(r, COAP_REQUEST_GET, hnd_get_large);
        coap_add_attr(r, (unsigned char *)"ct", 2, (unsigned char *)"0", 2, 0);
        coap_add_attr(r, (unsigned char *)"rt", 2, (unsigned char *)"large", 5, 0);
        coap_add_attr(r, (unsigned char *)"title", 5, (unsigned char *)"\"Large\"", 7, 0);
        coap_add_resource(ctx, r);

        time_resource = r;
    }

    static void hnd_get_all_resources(coap_context_t  *ctx UNUSED_PARAM,
                                            struct coap_resource_t *resource,
                                            const coap_endpoint_t *local_interface UNUSED_PARAM,
                                            coap_address_t *peer UNUSED_PARAM,
                                            coap_pdu_t *request UNUSED_PARAM,
                                            str *token UNUSED_PARAM,
                                            coap_pdu_t *response) 
    {
        unsigned char buf[3];

        response->hdr->code = COAP_RESPONSE_CODE(205);
        coap_add_option(response, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_APPLICATION_LINK_FORMAT), buf);
        coap_pdu_t * tmp = coap_wellknown_response(ctx, response);
        coap_add_data(response, tmp->length, tmp->data);
        //coap_show_pdu(tmp);
        coap_delete_pdu(tmp);
    }


    static void hnd_get_index(coap_context_t *ctx UNUSED_PARAM,
                                    struct coap_resource_t *resource UNUSED_PARAM,
                                    const coap_endpoint_t *local_interface UNUSED_PARAM,
                                    coap_address_t *peer UNUSED_PARAM,
                                    coap_pdu_t *request UNUSED_PARAM,
                                    str *token UNUSED_PARAM,
                                    coap_pdu_t *response) 
    {
        unsigned char buf[3];
        
        response->hdr->code = COAP_RESPONSE_CODE(205);
        coap_add_option(response, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
        coap_add_option(response, COAP_OPTION_MAXAGE, coap_encode_var_bytes(buf, 0x2ffff), buf);
        coap_add_data(response, strlen(INDEX.c_str()), (unsigned char *)INDEX.c_str());
    }

    static void hnd_put_hello(coap_context_t *ctx UNUSED_PARAM,
                                    struct coap_resource_t *resource UNUSED_PARAM,
                                    const coap_endpoint_t *local_interface UNUSED_PARAM,
                                    coap_address_t *peer UNUSED_PARAM,
                                    coap_pdu_t *request,
                                    str *token UNUSED_PARAM,
                                    coap_pdu_t *response) 
    {
        size_t size;
        unsigned char *data;

        /* if hello resource was deleted, we pretend to have no such resource */
        response->hdr->code = hello_exists ? COAP_RESPONSE_CODE(204) : COAP_RESPONSE_CODE(201);

        resource->dirty = 1;

        coap_get_data(request, &size, &data);

        if (size == 0)        /* re-init */
            hello_exists = true;
    }

    static void hnd_delete_hello(coap_context_t *ctx UNUSED_PARAM,
                                    struct coap_resource_t *resource UNUSED_PARAM,
                                    const coap_endpoint_t *local_interface UNUSED_PARAM,
                                    coap_address_t *peer UNUSED_PARAM,
                                    coap_pdu_t *request UNUSED_PARAM,
                                    str *token UNUSED_PARAM,
                                    coap_pdu_t *response UNUSED_PARAM) 
    {
          hello_exists = false;    /* mark hello as "deleted" */
    }

    static void hnd_get_hello(coap_context_t *ctx UNUSED_PARAM,
                                struct coap_resource_t *resource UNUSED_PARAM,
                                const coap_endpoint_t *local_interface UNUSED_PARAM,
                                coap_address_t *peer UNUSED_PARAM,
                                coap_pdu_t *request UNUSED_PARAM,
                                str *token UNUSED_PARAM,
                                coap_pdu_t *response)
    {
        unsigned char buf[3];
        const char* response_data     = "Hello World!";
        response->hdr->code           = hello_exists ? COAP_RESPONSE_CODE(205) : COAP_RESPONSE_CODE(404);
        if (hello_exists)
        {
            coap_add_option(response, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
            coap_add_data(response, strlen(response_data), (unsigned char *)response_data);
        }
    }

    static void hnd_get_large(coap_context_t *ctx UNUSED_PARAM,
                                    struct coap_resource_t *resource UNUSED_PARAM,
                                    const coap_endpoint_t *local_interface UNUSED_PARAM,
                                    coap_address_t *peer UNUSED_PARAM,
                                    coap_pdu_t *request,
                                    str *token UNUSED_PARAM,
                                    coap_pdu_t *response) 
    {
        unsigned char buf[2];

        response->hdr->code = COAP_RESPONSE_CODE(205);

        int len;
        auto large = make_large("../res/large.txt", len);
        if (!large)
            throw std::runtime_error("Error allocating memory for large resource!");

        coap_key_t etag = {0};
        coap_add_option(response, COAP_OPTION_ETAG, sizeof(etag), etag);
        coap_add_option(response, COAP_OPTION_CONTENT_TYPE, coap_encode_var_bytes(buf, COAP_MEDIATYPE_TEXT_PLAIN), buf);
        
        int res;
        coap_block_t block;
        if (coap_get_block(request, COAP_OPTION_BLOCK2, &block)) 
        {
            bool error = false;
            res = coap_write_block_opt(&block, COAP_OPTION_BLOCK2, response, len);

            //printf("Server: coap_write_block_opt get ret: %d\n", res); 
            
            switch (res)
            {
                case -2: /* illegal block */
                    response->hdr->code = COAP_RESPONSE_CODE(400);
                    error = true;
                    break;
                case -1: /* should really not happen */
                    throw std::runtime_error("write_block_opt get a -1 code!");
                case -3: /* cannot handle request */
                    response->hdr->code = COAP_RESPONSE_CODE(500);
                    error = true;
                    break;
                default: /* all ok */
                    break;
            }

            if (error)
            {
                //printf("Server: error detected\n");
                coap_add_data(response,
                                strlen(coap_response_phrase(response->hdr->code)),
                                (unsigned char *)coap_response_phrase(response->hdr->code));
            }
            else
            {
                //printf("Server: block.num: %d , block.szx: %d\n", block.num, block.szx);

                coap_add_block(response, len, large.get(), block.num, block.szx);
            }
        }
        else
        {
            //printf("Server: !coap_get_block() (else)\n");
            if (!coap_add_data(response, len, large.get())) 
            {
                /* 
                 * set initial block size, will be lowered by
                 * coap_write_block_opt) automatically 
                 */
                block.szx = 6;
                coap_write_block_opt(&block, COAP_OPTION_BLOCK2, response, len);
                coap_add_block(response, len, large.get(), block.num, block.szx);
            }
        }
    }

private:
    coap_context_t *ctx;
    coap_address_t serv_addr;
    coap_resource_t *time_resource;
    fd_set readfds; 
    std::string server_uri;
    unsigned int port;
    PROTOCOL_VERSION protocol_version;
    bool quit_;
    std::thread thread;
    static bool hello_exists; // use this to mark delete of hello resource
    static const std::string INDEX;
};

// static inits
const std::string CoapServer::CoapServerImpl::INDEX("This is a coap c++ server using libcoap (see https://libcoap.net)\nCopyright (C) 2016 Sergio Paracuellos <sergio.paracuellos@gmail.com>\n\n");
bool CoapServer::CoapServerImpl::hello_exists = true;

/* CoapServer implementation */

CoapServer::CoapServer(const std::string &host,
                        unsigned int port)
{
    impl_ = std::make_unique<CoapServerImpl>(host, port);
}

CoapServer::~CoapServer() = default;

void CoapServer::set_protocol_version(PROTOCOL_VERSION version)
{
    impl_->set_protocol_version(version);
}

void CoapServer::start()
{
    impl_->start();
}
