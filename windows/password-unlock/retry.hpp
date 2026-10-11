#pragma once
#include "core.hpp"
namespace pu::vault {
inline bool transientRelayStatus(unsigned status){return status==500||status==502||status==503||status==504;}
// The caller supplies a bounded, cancellable wait and validates the live sign-in
// context on every attempt. Certificate, protocol and authorization failures stop.
template<class Operation,class Wait> Json retryRelay(Operation operation,Wait wait){
  for(;;){
    try{return operation();}
    catch(const RelayNetworkError& error){if(!error.transient())throw;}
    catch(const RelayHttpError& error){if(!transientRelayStatus(error.status))throw;}
    wait();
  }
}
// A POST may have reached the relay even when its response was lost. Probe the
// same request ID before sending again; never create another challenge or nonce.
template<class Send,class Probe,class Wait> Json publishRequest(Send send,Probe probe,Wait wait){
  for(;;){
    try{return send();}
    catch(const RelayNetworkError& error){if(!error.transient())throw;}
    catch(const RelayHttpError& error){if(!transientRelayStatus(error.status))throw;}
    wait();
    try{retryRelay(probe,wait);return Json{{"pushDelivery","unknown"}};}
    catch(const RelayHttpError& error){if(error.status!=404)throw;}
  }
}
}
