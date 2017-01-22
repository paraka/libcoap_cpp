#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdexcept>
#include <thread>
#include "coap.h"
#include "CoapClient.h"

/* CoapClient implementation details class: pimpl idiom */

class CoapClient::CoapClientImpl
{
public:
    CoapClientImpl(const std::string &host,
                   unsigned int port) 
                                : client(client),
                                  server_uri(host),
                                  port(port),
                                  ctx(nullptr), 
                                  src_addr({0}),
                                  dst_addr({0}),
                                  resource(""),
                                  protocol_version(PROTOCOL_VERSION::IPV4),
                                  add_block2_option(false)
    {
        memset(&addr, 0, sizeof(addr));
        init();
    }

    ~CoapClientImpl()
    {
        coap_free_context(ctx);
    }

    void set_protocol_version(PROTOCOL_VERSION version)
    {
        protocol_version = version;
    }

    void set_request_method(REQUEST method)
    {
        request_method = method;
    }

    void set_resource(const std::string &res)
    {
        resource = res;
    }

    void set_block2_option(bool block_option)
    {
        add_block2_option = block_option;
    }

    void send_request()
    {
        coap_tid_t tid = COAP_INVALID_TID;
        struct timeval tv;
        coap_tick_t now;
        coap_queue_t *nextpdu;

        coap_show_pdu(request);

        if (request->hdr->type == COAP_MESSAGE_CON)
            tid = coap_send_confirmed(ctx, ctx->endpoint, &dst_addr, request);
        else 
            tid = coap_send(ctx, ctx->endpoint, &dst_addr, request);

        if (request->hdr->type != COAP_MESSAGE_CON || tid == COAP_INVALID_TID)
            coap_delete_pdu(request);

        set_timeout(&max_wait, DEFAULT_SECONDS_TIMEOUT);

        while (!coap_can_exit(ctx))
        {
            FD_ZERO(&readfds);
            FD_SET(ctx->sockfd, &readfds);

            nextpdu = coap_peek_next(ctx);
            coap_ticks(&now);
            while (nextpdu && nextpdu->t <= now - ctx->sendqueue_basetime) 
            {
                coap_retransmit( ctx, coap_pop_next(ctx));
                nextpdu = coap_peek_next(ctx);
            }

            if (nextpdu && nextpdu->t < max_wait - now)
            {
                /* set timeout if there is a pdu to send */
                tv.tv_usec = ((nextpdu->t) % COAP_TICKS_PER_SECOND) * 1000000 / COAP_TICKS_PER_SECOND;
                tv.tv_sec = (nextpdu->t) / COAP_TICKS_PER_SECOND;
            }
            else
            {
                tv.tv_usec = ((max_wait - now) % COAP_TICKS_PER_SECOND) * 1000000 / COAP_TICKS_PER_SECOND;
                tv.tv_sec = (max_wait - now) / COAP_TICKS_PER_SECOND;
            }

            int result = select(FD_SETSIZE, &readfds, 0, 0, &tv);

            if (result < 0) /* socket error */
                throw std::runtime_error("Socket error!");
            else if (result > 0 && FD_ISSET(ctx->sockfd, &readfds)) /* socket read */
                coap_read(ctx);       
            else /* timeout */
            {
                coap_ticks(&now);
                if (max_wait <= now) 
                {
                    printf("timeout\n");
                    break;
                }
            }
        }
    }

    void prepare_request()
    {
        /* Prepare the request */
        request = prepare_request(addr);
    }

private:

    static inline void set_timeout(coap_tick_t *timer, const unsigned int seconds)
    {
        coap_ticks(timer);
        *timer += seconds * COAP_TICKS_PER_SECOND;
    }

    std::string get_request_url(const char *addr) const
    {
        std::string ret = "coap://" + std::string(addr) + "/" + resource;
        return ret;
    }

    void init_context(const char *node)
    {
        struct addrinfo hints = {0};
        struct addrinfo *result, *rp;

        hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
        hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
        hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV | AI_ALL;

        int s = getaddrinfo(node, std::to_string(0).c_str(), &hints, &result);
        if (s != 0) throw std::runtime_error(gai_strerror(s));

        for (rp = result; rp != NULL; rp = rp->ai_next) 
        {
            // Be sure that get correct address for selected protocol
            if (rp->ai_family != CoapCommon::get_family_for_protocol_version(protocol_version))
                continue;

            if (rp->ai_addrlen <= sizeof(src_addr.addr)) 
            {
                coap_address_init(&src_addr);
                src_addr.size = rp->ai_addrlen;
                memcpy(&src_addr.addr, rp->ai_addr, rp->ai_addrlen);
                ctx = coap_new_context(&src_addr);
                break;
            }
        }

        freeaddrinfo(result);
    }

    int resolve_address(struct sockaddr *dst)
    {
        struct addrinfo *res, *ainfo;
        struct addrinfo hints = {0};
        char addrstr[256] = {0};
        int len = -1;
            
        memcpy(addrstr, server_uri.c_str(), strlen(server_uri.c_str()));
        printf("Address to resolve: %s\n", addrstr);
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_family = AF_UNSPEC;

        int error = getaddrinfo(addrstr, NULL, &hints, &res);
        if (error != 0) throw std::runtime_error(gai_strerror(error));

        for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) 
        {
            // Be sure that get correct address for selected protocol
            if (ainfo->ai_family != CoapCommon::get_family_for_protocol_version(protocol_version))
                continue;

            switch (ainfo->ai_family) 
            {
                case AF_INET6:
                case AF_INET:
                {
                    len = ainfo->ai_addrlen;
                    memcpy(dst, ainfo->ai_addr, len);
                    printf("Protocol family detected interface: %s\n", 
                             (dst->sa_family == AF_INET) ? "IPV4" : "IPV6");
                    break;
                }
                default:
                    break;
            }
        }

        freeaddrinfo(res);

        return len;
    }

    coap_pdu_t *prepare_request(const char *addr)
    {
        coap_pdu_t *ret = nullptr;

        std::string complete_uri = get_request_url(addr);

        coap_split_uri((const unsigned char *)complete_uri.c_str(), complete_uri.size(), &uri);

        if (memcmp(addr, uri.host.s, uri.host.length) != 0 ||
            strlen(addr) != uri.host.length)
            throw std::runtime_error("Bad Uri!!!");

        ret            = coap_new_pdu();    
        ret->hdr->type = COAP_MESSAGE_CON;
        ret->hdr->id   = coap_new_message_id(ctx);
        ret->hdr->code = static_cast<int>(request_method); 
        coap_add_option(ret, COAP_OPTION_URI_HOST, uri.host.length, uri.host.s);
        coap_add_option(ret, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);

        if (add_block2_option)
        {
            coap_block_t block = { .num = 0, .m = 0, .szx = 6 };
            unsigned char buf[4];
            unsigned int len = coap_encode_var_bytes(buf, (block.num << 4 | block.m << 3 | block.szx));
            coap_add_option(ret, COAP_OPTION_BLOCK2, len, buf);
        }

        if (uri.port != COAP_DEFAULT_PORT)
        {
            unsigned char portbuf[2];
            coap_add_option(ret, COAP_OPTION_URI_PORT,
                            coap_encode_var_bytes(portbuf, uri.port), portbuf);
        }

        return ret;
    }

    void init()
    {
        init_context((protocol_version == PROTOCOL_VERSION::IPV4) ? "0.0.0.0" : "::");

        /* The destination endpoint */
        int size = resolve_address(&dst_addr.addr.sa);
        if (size == -1)
            throw std::runtime_error("Error resolving address!");

        dst_addr.size = size;
        dst_addr.addr.sin.sin_port = htons(port);

        /* set handler to be called when data arrives */
        coap_register_response_handler(ctx, message_handler);
        
        coap_register_option(ctx, COAP_OPTION_BLOCK2);

        void *addrptr = NULL;
        if (protocol_version == PROTOCOL_VERSION::IPV4)
            addrptr = &dst_addr.addr.sin.sin_addr;
        else
            addrptr = &dst_addr.addr.sin6.sin6_addr;

        if (!inet_ntop(dst_addr.addr.sa.sa_family, addrptr, addr, sizeof(addr)) != 0)
            throw std::runtime_error("inet_ntop failed!!!");

        printf("Inet_ntop: resolved ip address: %s\n", addr);
    }

    static void message_handler(struct coap_context_t *ctx, const coap_endpoint_t *local_interface,
                                const coap_address_t *remote, coap_pdu_t *sent, coap_pdu_t *received, 
                                const coap_tid_t id)
    {
        unsigned char * data;
        size_t data_len;

        //printf("Received response code: %d\n", COAP_RESPONSE_CLASS(received->hdr->code)); 

        if (COAP_RESPONSE_CLASS(received->hdr->code) == 2) 
        {
            // Check if it is a multiframe message

            coap_opt_iterator_t opt_iter;
            coap_opt_t *block_opt;
            block_opt = coap_check_option(received, COAP_OPTION_BLOCK2, &opt_iter);
            if (block_opt)
            {
                unsigned short blktype = opt_iter.type;

                if (coap_get_data(received, &data_len, &data))
                    CoapClient::on_data_arrived.emit(data, data_len);

                if (COAP_OPT_BLOCK_MORE(block_opt)) 
                {
                    /* more bit is set */
                    //printf("\nfound the M bit, block size is %u, block nr. %u\n",
                    //        COAP_OPT_BLOCK_SZX(block_opt),
                    //        coap_opt_block_num(block_opt));


                    /* create pdu with request for next block */
                    coap_pdu_t *pdu            = coap_new_pdu();    
                    pdu->hdr->type = COAP_MESSAGE_CON;
                    pdu->hdr->id   = coap_new_message_id(ctx);
                    pdu->hdr->code = static_cast<int>(request_method); 
                    coap_add_option(pdu, COAP_OPTION_URI_HOST, uri.host.length, uri.host.s);
                    coap_add_option(pdu, COAP_OPTION_URI_PATH, uri.path.length, uri.path.s);
                    
                    /* finally add updated block option from response, clear M bit */
                    /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
                    unsigned char buf[4];
                    //printf("\nquery block %d\n", (coap_opt_block_num(block_opt) + 1));
                    coap_add_option(pdu, blktype, coap_encode_var_bytes(buf,
                                                        ((coap_opt_block_num(block_opt) + 1) << 4) |
                                                        COAP_OPT_BLOCK_SZX(block_opt)), buf);
                    coap_show_pdu(pdu);
                    coap_tid_t tid;
                    if (pdu->hdr->type == COAP_MESSAGE_CON)
                        tid = coap_send_confirmed(ctx, local_interface, remote, pdu);
                    else    
                        tid = coap_send(ctx, local_interface, remote, pdu);

                    if (tid == COAP_INVALID_TID)
                    {
                        //printf("message_handler: error sending new request\n");
                        coap_delete_pdu(pdu);
                    }
                    else
                    {
                        set_timeout(&max_wait, DEFAULT_SECONDS_TIMEOUT);
                        if (pdu->hdr->type != COAP_MESSAGE_CON)
                            coap_delete_pdu(pdu);
                    }
                }
            }
            else // no multiframe message
            {
                if (coap_get_data(received, &data_len, &data))
                {
                    CoapClient::on_data_arrived.emit(data, data_len);
                }
                else // put o delete
                {
                    char tmpbuf[5];
                    snprintf(tmpbuf, 5, "%d.%02d", (received->hdr->code >> 5), received->hdr->code & 0x1F);
                    CoapClient::on_response_error.emit(CoapResponseString::instance().get_code_for_string(std::string(tmpbuf)));
                }
            }
        }
        else // no 2.05
        {
            if (COAP_RESPONSE_CLASS(received->hdr->code) >= 4) 
            {
                char tmpbuf[5];
                snprintf(tmpbuf, 5, "%d.%02d", (received->hdr->code >> 5), received->hdr->code & 0x1F);
                CoapClient::on_response_error.emit(CoapResponseString::instance().get_code_for_string(std::string(tmpbuf)));
            }
        }
    }

private:
    CoapClient &client;
    coap_context_t *ctx;
    coap_address_t src_addr;
    coap_address_t dst_addr;
    char addr[INET6_ADDRSTRLEN];
    fd_set readfds; 
    coap_pdu_t *request;
    std::string server_uri;
    unsigned int port;
    std::string resource;
    PROTOCOL_VERSION protocol_version;
    bool add_block2_option;
    static coap_uri_t uri;
    static coap_tick_t max_wait;
    static REQUEST request_method;
    static const unsigned int DEFAULT_SECONDS_TIMEOUT = 90; 
};

/* CoapClient implementation */

// static inits
coap_uri_t CoapClient::CoapClientImpl::uri({0});
REQUEST CoapClient::CoapClientImpl::request_method(REQUEST::GET);
coap_tick_t CoapClient::CoapClientImpl::max_wait;
Signal<unsigned char *, size_t> CoapClient::on_data_arrived;
Signal<RESPONSE_CODE> CoapClient::on_response_error;

CoapClient::CoapClient(const std::string &host,
                    unsigned int port)
{
    impl_ = std::make_unique<CoapClientImpl>(host, port);
}

CoapClient::~CoapClient() = default;

void CoapClient::set_protocol_version(PROTOCOL_VERSION version)
{
    impl_->set_protocol_version(version);
}

void CoapClient::set_request_method(REQUEST method)
{
    impl_->set_request_method(method);
}

void CoapClient::set_resource(const std::string &res)
{
    impl_->set_resource(res);
}

void CoapClient::send_request()
{
    impl_->send_request();
}

void CoapClient::prepare_request()
{
    impl_->prepare_request();
}

void CoapClient::set_multiframe(bool multiframe)
{
    impl_->set_block2_option(multiframe);
}
