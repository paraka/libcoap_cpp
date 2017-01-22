#ifndef _COAP_SERVER_H_
#define _COAP_SERVER_H_

#include <string>
#include <memory>
#include "CoapCommon.h"

class CoapServer
{
public:
    explicit CoapServer(const std::string &url,
                        unsigned int port = DEFAULT_PORT);
    
    ~CoapServer();

    // avoid copys and assignaments of this class
    CoapServer(const CoapServer & other) = delete;
    CoapServer(const CoapServer && other) = delete;
    CoapServer &operator=(const CoapServer &other) = delete;

    void set_protocol_version(PROTOCOL_VERSION version);

    // start_server
    void start();

private:
    class CoapServerImpl;
    using CoapServerImplPtr = std::unique_ptr<CoapServerImpl>;
    CoapServerImplPtr impl_;
    static const unsigned int DEFAULT_PORT = 5683;
};

#endif // _COAP_SERVER_H_
