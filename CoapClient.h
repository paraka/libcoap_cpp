#ifndef _COAP_CLIENT_H_
#define _COAP_CLIENT_H_

#include <string>
#include <memory>
#include "Signals.h"
#include "CoapCommon.h"

class CoapClient
{
public:
    explicit CoapClient(const std::string &host,
                        unsigned int port = DEFAULT_PORT);
    
    ~CoapClient();

    // avoid copys and assignaments of this class
    CoapClient(const CoapClient & other) = delete;
    CoapClient(const CoapClient && other) = delete;
    CoapClient &operator=(const CoapClient &other) = delete;

    void set_request_method(REQUEST method);

    void set_protocol_version(PROTOCOL_VERSION version);

    void set_resource(const std::string &resource);

    // This must be set to true in order to access big data resources
    void set_multiframe(bool multi_frame);

    // prepare request. MUST be called before send_request()
    void prepare_request();

    // send a request to a resource
    void send_request();

private:
    class CoapClientImpl;
    using CoapClientImplPtr = std::unique_ptr<CoapClientImpl>;
    CoapClientImplPtr impl_;
    static const unsigned int DEFAULT_PORT = 5683;

public:
    static Signal<unsigned char *, size_t> on_data_arrived;
    static Signal<RESPONSE_CODE> on_response_error;
};

#endif // _COAP_CLIENT_H_
